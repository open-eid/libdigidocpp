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

#include <cstring>
#include <thread>

using namespace digidoc;
using namespace std;

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx)
{
    return ctx->cert;
}
#endif

Connect::Connect(const string &_url, const string &method, int timeout, const string &useragent, const X509Cert &cert)
    : _timeout(timeout)
{
    DEBUG("Connecting to URL: %s", _url.c_str());
    char *_host = nullptr, *_port = nullptr, *_path = nullptr;
    int usessl = 0;
    if(!OCSP_parse_url(const_cast<char*>(_url.c_str()), &_host, &_port, &_path, &usessl))
        THROW_OPENSSLEXCEPTION("Incorrect URL provided: '%s'.", _url.c_str());

    string host = _host ? _host : "";
    string port = _port ? _port : "80";
    string path = _path ? _path : "/";
    string url = (_path && strlen(_path) == 1 && _path[0] == '/' && _url[_url.size() - 1] != '/') ? _url + "/" : _url;
    OPENSSL_free(_host);
    OPENSSL_free(_port);
    OPENSSL_free(_path);

    string hostname = host + ":" + port;
    Conf *c = Conf::instance();
    if(!c->proxyHost().empty() && (usessl == 0 || (CONF(proxyForceSSL)) || (CONF(proxyTunnelSSL))))
    {
        hostname = c->proxyHost() + ":" + c->proxyPort();
        path = url;
    }

    DEBUG("Connecting to Host: %s timeout: %i", hostname.c_str(), _timeout);
    d = BIO_new_connect(const_cast<char*>(hostname.c_str()));
    if(!d)
        THROW_OPENSSLEXCEPTION("Failed to create connection with host: '%s'", hostname.c_str());

    BIO_set_nbio(d, _timeout > 0);
    auto start = chrono::high_resolution_clock::now();
    while(BIO_do_connect(d) != 1)
    {
        if(_timeout == 0)
            THROW_OPENSSLEXCEPTION("Failed to connect to host: '%s'", hostname.c_str());
        if(!BIO_should_retry(d))
            THROW_OPENSSLEXCEPTION("Failed to connect to host: '%s'", hostname.c_str());
        auto end = chrono::high_resolution_clock::now();
        if(chrono::duration_cast<chrono::seconds>(end - start).count() >= _timeout)
            THROW("Failed to create connection with host timeout: '%s'", hostname.c_str());
        this_thread::sleep_for(chrono::milliseconds(50));
    }

    if(usessl > 0)
    {
        if(!c->proxyHost().empty() && (CONF(proxyTunnelSSL)))
        {
            BIO_printf(d, "CONNECT %s:%s HTTP/1.0\r\n", host.c_str(), port.c_str());
            addHeader("Host", host + ":" + port);
            sendProxyAuth();
            _timeout = 1; // Don't wait additional data on read, case proxy tunnel
            Result r = exec();
            if(!r.isOK() || r.result.find("established") == string::npos)
                THROW_OPENSSLEXCEPTION("Failed to create proxy connection with host: '%s'", hostname.c_str());
            _timeout = timeout; // Restore
        }

        ssl.reset(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
        if(!ssl)
            THROW_OPENSSLEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str());
        SSL_CTX_set_mode(ssl.get(), SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_quiet_shutdown(ssl.get(), 1);
        if(cert.handle())
        {
            SSL_CTX_set_verify(ssl.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            SSL_CTX_set_cert_verify_callback(ssl.get(), [](X509_STORE_CTX *store, void *cert) -> int {
                X509 *x509 = X509_STORE_CTX_get0_cert(store);
                return x509 && X509_cmp(x509, (X509*)cert) == 0 ? 1 : 0;
            }, cert.handle());
        }
        BIO *sbio = BIO_new_ssl(ssl.get(), 1);
        if(!sbio)
            THROW_OPENSSLEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str());
        d = BIO_push(sbio, d);
        while(BIO_do_handshake(d) != 1)
        {
            if(_timeout == 0)
                THROW("Failed to create ssl connection with host: '%s'", hostname.c_str());
            auto end = chrono::high_resolution_clock::now();
            if(chrono::duration_cast<chrono::seconds>(end - start).count() >= _timeout)
                THROW("Failed to create ssl connection with host timeout: '%s'", hostname.c_str());
            this_thread::sleep_for(chrono::milliseconds(50));
        }
    }

    BIO_printf(d, "%s %s HTTP/1.0\r\n", method.c_str(), path.c_str());
    if(port == "80")
        addHeader("Host", host);
    else
        addHeader("Host", host + ":" + port);
    if(!userAgent().empty())
        addHeader("User-Agent", "LIB libdigidocpp/" + string(FILE_VER_STR) + " APP " + userAgent() + useragent);
    if(usessl == 0)
        sendProxyAuth();
}

Connect::~Connect()
{
    if(d)
        BIO_free_all(d);
}

void Connect::addHeader(const string &key, const string &value)
{
    BIO_printf(d, "%s: %s\r\n", key.c_str(), value.c_str());
}

void Connect::addHeaders(initializer_list<pair<string,string>> headers)
{
    for(const pair<string,string> &it: headers)
        addHeader(it.first, it.second);
}

Connect::Result Connect::exec(initializer_list<pair<string,string>> headers,
    const vector<unsigned char> &data)
{
    return exec(headers, data.data(), data.size());
}

Connect::Result Connect::exec(initializer_list<pair<string,string>> headers,
    const unsigned char *data, size_t size)
{
    addHeaders(headers);
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
        auto end = chrono::high_resolution_clock::now();
        if(_timeout > 0 && _timeout < chrono::duration_cast<chrono::seconds>(end - start).count())
            break;
    } while(rc != 0);
    r.content.resize(pos);

    stringstream stream(r.content);
    string line;
    while(getline(stream, line))
    {
        line.resize(line.size() - 1);
        if(line.empty())
            break;
        if(r.result.empty())
        {
            r.result = line;
            continue;
        }
        size_t split = line.find(": ");
        if(split != string::npos)
            r.headers[line.substr(0, split)] = line.substr(split + 2);
        else
            r.headers[line] = string();
    }

    pos = r.content.find("\r\n\r\n");
    if(pos != string::npos)
        r.content.erase(0, pos + 4);

    if(r.content.empty())
        return r;

    const auto it = r.headers.find("Content-Encoding");
    if(it != r.headers.cend())
    {
        z_stream s;
        s.zalloc = nullptr;
        s.zfree = nullptr;
        s.next_in = (Bytef*)r.content.c_str();
        s.avail_in = uInt(r.content.size());
        s.total_out = 0;
        if(it->second == "gzip")
            inflateInit2(&s, 16 + MAX_WBITS);
        else if(it->second == "deflate")
            inflateInit2(&s, -MAX_WBITS);
        else
        {
            WARN("Unsuported Content-Encoding: %s", it->second.c_str());
            return r;
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
            default: THROW("Failed to decompress HTTP content");
            }
        } while(s.avail_out == 0);
        out.resize(s.total_out);
        inflateEnd(&s);
        r.content = move(out);
    }

    return r;
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
