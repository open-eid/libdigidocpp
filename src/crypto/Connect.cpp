/*
 * libdigidocpp
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "Connect.h"

#include "Conf.h"
#include "Container.h"
#include "crypto/OpenSSLHelpers.h"

#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include <zlib.h>

#include <algorithm>
#include <thread>

#ifdef _WIN32
#include <Winsock2.h>
#endif

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
#define TARGET_ARCH "arm64"
#elif defined(__arm__) || defined(_M_ARM)
#define TARGET_ARCH "arm"
#elif defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(_M_X64)
#define TARGET_ARCH "x86_64"
#else
#define TARGET_ARCH "x86"
#endif

using namespace digidoc;
using namespace std;

#define THROW_NETWORKEXCEPTION(...) { \
    OpenSSLException ex(EXCEPTION_PARAMS(__VA_ARGS__)); \
    if(ex.code() == Exception::General) \
        ex.setCode(Exception::NetworkError); \
    throw ex; \
}



Connect::Connect(const string &_url, string _method, int _timeout, const vector<X509Cert> &certs, const string &userAgentData)
    : method(std::move(_method))
    , timeout(_timeout)
{
    DEBUG("Connecting to URL: %s", _url.c_str());
    char *_host = nullptr, *_port = nullptr, *_path = nullptr;
    int usessl = 0;
    if(!OCSP_parse_url(_url.c_str(), &_host, &_port, &_path, &usessl))
    {
        OpenSSLException e(EXCEPTION_PARAMS("Incorrect URL provided: '%s'.", _url.c_str()));
        e.setCode(Exception::InvalidUrl);
        throw e;
    }

    string host = _host ? _host : "";
    string port = _port ? _port : "80";
    string path = _path ? _path : "/";
    string url = (_path && char_traits<char>::length(_path) == 1 && _path[0] == '/' && _url[_url.size() - 1] != '/') ? _url + '/' : _url;
    OPENSSL_free(_host);
    OPENSSL_free(_port);
    OPENSSL_free(_path);
    if(size_t pos = url.find("://"); pos != string::npos) {
        if(pos = url.find('/', pos + 3); pos != string::npos)
            baseurl = url.substr(0, pos);
    }

    string hostname = host + ':' + port;
    Conf *c = Conf::instance();
    if(!c->proxyHost().empty() && !c->proxyPort().empty())
    {
        hostname = c->proxyHost() + ":" + c->proxyPort();
        if(usessl == 0 || (CONF(proxyForceSSL)))
            path = std::move(url);
    }

    DEBUG("Connecting to Host: %s timeout: %i", hostname.c_str(), _timeout);
    d = BIO_new_connect(hostname.c_str());
    if(!d)
        THROW_NETWORKEXCEPTION("Failed to create connection with host: '%s'", hostname.c_str())

    BIO_set_nbio(d, _timeout > 0);
    auto start = chrono::high_resolution_clock::now();
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    while(BIO_do_connect(d) != 1)
    {
        if(_timeout == 0)
            THROW_NETWORKEXCEPTION("Failed to connect to host: '%s'", hostname.c_str())
        if(!BIO_should_retry(d))
            THROW_NETWORKEXCEPTION("Failed to connect to host: '%s'", hostname.c_str())
        auto end = chrono::high_resolution_clock::now();
        if(chrono::duration_cast<chrono::seconds>(end - start).count() >= _timeout)
            THROW_NETWORKEXCEPTION("Failed to create connection with host timeout: '%s'", hostname.c_str())
        this_thread::sleep_for(chrono::milliseconds(50));
    }
#else
    if(timeout > 0 && BIO_do_connect_retry(d, timeout, -1) < 1)
        THROW_NETWORKEXCEPTION("Failed to create connection with host timeout: '%s'", hostname.c_str())
    if(timeout == 0 && BIO_do_connect(d) < 1)
        THROW_NETWORKEXCEPTION("Failed to create connection with host: '%s'", hostname.c_str())
#endif

    if(usessl > 0)
    {
        if(!c->proxyHost().empty() && (CONF(proxyTunnelSSL)))
        {
            BIO_printf(d, "CONNECT %s:%s HTTP/1.0\r\n", host.c_str(), port.c_str());
            addHeader("Host", host + ':' + port);
            sendProxyAuth();
            doProxyConnect = true;
            Result r = exec();
            if(!r.isOK() || r.result.find("established") == string::npos)
                THROW_NETWORKEXCEPTION("Failed to create proxy connection with host: '%s'", hostname.c_str())
            doProxyConnect = false;
        }

        ssl.reset(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
        if(!ssl)
            THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
        SSL_CTX_set_mode(ssl.get(), SSL_MODE_AUTO_RETRY);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
        /* Make OpenSSL 3.0.0 behave like 1.1.1 */
        auto options = SSL_CTX_get_options(ssl.get());
        options |= SSL_OP_IGNORE_UNEXPECTED_EOF;
        SSL_CTX_set_options(ssl.get(), options);
#endif
        SSL_CTX_set_quiet_shutdown(ssl.get(), 1);
        if(!certs.empty())
        {
            SSL_CTX_set_verify(ssl.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            SSL_CTX_set_cert_verify_callback(ssl.get(), [](X509_STORE_CTX *store, void *data) -> int {
                X509 *x509 = X509_STORE_CTX_get0_cert(store);
                auto *certs = (vector<X509Cert>*)data;
                return any_of(certs->cbegin(), certs->cend(), [x509](const X509Cert &cert) {
                    return cert && cert == x509;
                }) ? 1 : 0;
            }, const_cast<vector<X509Cert>*>(&certs));
        }
        BIO *sbio = BIO_new_ssl(ssl.get(), 1);
        if(!sbio)
            THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
        if(SSL *ssl {}; BIO_get_ssl(sbio, &ssl) == 1 && ssl)
        {
            SSL_set1_host(ssl, host.c_str());
            SSL_set_tlsext_host_name(ssl, host.c_str());
        }
        d = BIO_push(sbio, d);
        while(BIO_do_handshake(d) != 1)
        {
            if(_timeout == 0)
                THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
            auto end = chrono::high_resolution_clock::now();
            if(chrono::duration_cast<chrono::seconds>(end - start).count() >= _timeout)
                THROW_NETWORKEXCEPTION("Failed to create ssl connection with host timeout: '%s'", hostname.c_str())
            this_thread::sleep_for(chrono::milliseconds(50));
        }
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if(_timeout > 0)
    {
        int fd = BIO_get_fd(d, nullptr);
        fd_set confds;
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        timeval tv { timeout, 0 };
        int read = BIO_should_read(d);
        if(select(fd + 1, read ? &confds : nullptr, read ? nullptr : &confds, nullptr, &tv) == -1)
            DEBUG("select failed");
    }
#endif

    BIO_printf(d, "%s %s HTTP/1.1\r\n", method.c_str(), path.c_str());
    addHeader("Connection", "close");
    if(port == "80" || port == "443")
        addHeader("Host", host);
    else
        addHeader("Host", host + ':' + port);
    if(const auto &agent = userAgentData.empty() ? userAgent() : userAgentData; !agent.empty())
        addHeader("User-Agent", "LIB libdigidocpp/" FILE_VER_STR " (" TARGET_ARCH ") APP " + agent);
    if(usessl == 0)
        sendProxyAuth();
}

Connect::~Connect()
{
    if(d)
        BIO_free_all(d);
}

void Connect::addHeader(string_view key, string_view value)
{
    BIO_printf(d, "%.*s: %.*s\r\n", int(key.size()), key.data(), int(value.size()), value.data());
}

string Connect::decompress(const string &encoding, const string &data)
{
    if(data.empty())
        return data;

    z_stream s {};
    s.next_in = (Bytef*)data.c_str();
    s.avail_in = uInt(data.size());
    int result = Z_OK;
    if(encoding == "gzip")
        result = inflateInit2(&s, 16 + MAX_WBITS);
    else if(encoding == "deflate")
        result = inflateInit2(&s, -MAX_WBITS);
    else
    {
        WARN("Unsuported Content-Encoding: %s", encoding.c_str());
        return data;
    }
    if(result != Z_OK) {
        WARN("Failed to uncompress content Content-Encoding: %s", encoding.c_str());
        return data;
    }

    string out(2048, 0);
    do {
        if(s.total_out >= out.size())
            out.resize(out.size() * 2);
        s.next_out = (Bytef*)&out[s.total_out];
        s.avail_out = uInt(uLong(out.size()) - s.total_out);
        switch(inflate(&s, Z_NO_FLUSH))
        {
        case Z_OK:
        case Z_STREAM_END: break;
        default: THROW_NETWORKEXCEPTION("Failed to decompress HTTP content")
        }
    } while(s.avail_out == 0);
    out.resize(s.total_out);
    inflateEnd(&s);
    return out;
}

Connect::Result Connect::exec(initializer_list<pair<string_view,string_view>> headers,
    const unsigned char *data, size_t size)
{
    for(const auto &[key, value]: headers)
        addHeader(key, value);

    if(size != 0)
    {
        addHeader("Content-Length", to_string(size));
        BIO_printf(d, "\r\n");
        BIO_write(d, data, int(size));
    }
    else
        BIO_printf(d, "\r\n");

    int rc = 0;
    size_t pos = 0;
    Result r;
    r.content.resize(1024);
    chrono::high_resolution_clock::time_point start = chrono::high_resolution_clock::now();
    do {
        if(rc > 0 && (pos += size_t(rc)) >= r.content.size())
            r.content.resize(r.content.size()*2);
        rc = BIO_read(d, &r.content[pos], int(r.content.size() - pos));
        if(rc == -1 && BIO_should_read(d) != 1)
            break;
        if(doProxyConnect && rc > 0) {
            pos = size_t(rc);
            break;
        }
        auto end = chrono::high_resolution_clock::now();
        if(timeout > 0 && timeout < chrono::duration_cast<chrono::seconds>(end - start).count())
            break;
    } while(rc != 0);
    r.content.resize(pos);

    stringstream stream(r.content);
    string line;
    auto to_lower = [](string str) {
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        return str;
    };
    while(getline(stream, line))
    {
        line.resize(max<size_t>(line.size() - 1, 0));
        if(line.empty())
            break;
        if(r.result.empty())
        {
            r.result = line;
            continue;
        }
        size_t split = line.find(": ");
        if(split != string::npos)
            r.headers[to_lower(line.substr(0, split))] = line.substr(split + 2);
        else
            r.headers[to_lower(line)] = string();
    }

    pos = r.content.find("\r\n\r\n");
    if(pos != string::npos)
        r.content.erase(0, pos + 4);

    if(const auto it = r.headers.find("transfer-encoding");
        it != r.headers.cend() &&
        it->second.find("chunked") != string::npos) {
        pos = 0;
        for(size_t chunkpos = r.content.find("\r\n", pos);
            chunkpos != string::npos;
            chunkpos = r.content.find("\r\n", pos))
        {
            string chunk = r.content.substr(pos, chunkpos - pos);
            r.content.erase(pos, chunk.size() + 2);
            pos += stoul(chunk, nullptr, 16);
            r.content.erase(pos, 2);
        }
    }

    if(const auto it = r.headers.find("content-encoding");
        it != r.headers.cend())
        r.content = decompress(it->second, r.content);

    if(!r.isRedirect() || recursive > 3)
        return r;
    string &location = r.headers["location"];
    string url = location.find("://") != string::npos ? std::move(location) : baseurl + location;
    Connect c(url, method, timeout);
    c.recursive = recursive + 1;
    return c.exec(headers);
}

void Connect::sendProxyAuth()
{
    Conf *c = Conf::instance();
    if(c->proxyUser().empty() || c->proxyPass().empty())
        return;

    BIO_printf(d, "Proxy-Authorization: Basic ");
    SCOPE(BIO, b64, BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64.get(), d);
    BIO_printf(b64.get(), "%s:%s", c->proxyUser().c_str(), c->proxyPass().c_str());
    (void)BIO_flush(b64.get());
    BIO_pop(b64.get());
    BIO_printf(d, "\r\n");
}
