// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "Connect_p.h"

#include "Conf.h"
#include "Container.h"
#include "crypto/OpenSSLHelpers.h"
#include "util/algorithm.h"

#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include <chrono>
#include <ctime>
#include <thread>

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

Connect::Connect(const string &_url, string_view _method, int _timeout, vector<X509Cert> _certs, string _userAgentData, string_view _version)
    : method(_method)
    , userAgentData(std::move(_userAgentData))
    , version(_version)
    , certs(std::move(_certs))
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
    if(timeout > 0 && BIO_do_connect_retry(d, timeout, -1) < 1)
        THROW_NETWORKEXCEPTION("Failed to create connection with host timeout: '%s'", hostname.c_str())
    if(timeout == 0 && BIO_do_connect(d) < 1)
        THROW_NETWORKEXCEPTION("Failed to create connection with host: '%s'", hostname.c_str())

    if(usessl > 0)
    {
        if(!c->proxyHost().empty() && (CONF(proxyTunnelSSL)))
        {
            BIO_printf(d, "CONNECT %s:%s HTTP/1.0\r\n", host.c_str(), port.c_str());
            addHeader("Host", host + ':' + port);
            sendProxyAuth();
            doProxyConnect = true;
            Result r = exec();
            if(!r.isOK() || (r.result.find("established") == string::npos && r.result.find("ok") == string::npos))
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
        // TLS peer verification is performed only when pinned certificates are provided.
        // Without pinning, content-level crypto covers integrity: OCSP responses are signed
        // by the responder cert, TSA responses are CMS-signed, and TSL uses known public keys.
        if(!certs.empty())
        {
            SSL_CTX_set_verify(ssl.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            X509_STORE *store = SSL_CTX_get_cert_store(ssl.get());
            X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
            for(const X509Cert &cert: certs)
            {
                if(cert.handle())
                    X509_STORE_add_cert(store, cert.handle());
            }
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

    BIO_printf(d, "%.*s %s HTTP/%.*s\r\n", STR_VIEW_FMT(method), path.c_str(), STR_VIEW_FMT(version));
    addHeader("Connection", "close");
    if(port == "80" || port == "443")
        addHeader("Host", host);
    else
        addHeader("Host", host + ':' + port);
    if(const auto &agent = userAgentData.empty() ? userAgent() : userAgentData; !agent.empty())
        addHeader("User-Agent", "LIB libdigidocpp/" VERSION_STR " (" TARGET_ARCH ") APP " + agent);
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
    BIO_printf(d, "%.*s: %.*s\r\n", STR_VIEW_FMT(key), STR_VIEW_FMT(value));
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
    const time_t deadline = time(nullptr) + timeout;
    do {
        if(rc > 0) {
            pos += size_t(rc);
            if(pos > MAX_RESPONSE_SIZE)
                THROW_NETWORKEXCEPTION("HTTP response exceeds maximum allowed size of %zu bytes", MAX_RESPONSE_SIZE)
            if(pos >= r.content.size())
                r.content.resize(r.content.size() * 2);
        }
        rc = BIO_read(d, &r.content[pos], int(r.content.size() - pos));
        if(rc == -1 && BIO_should_read(d) != 1)
            break;
        // The tunnel carries TLS next, so read the CONNECT response headers and nothing more.
        if(doProxyConnect && rc > 0 && headerEnd({r.content.data(), pos + size_t(rc)}) != string_view::npos) {
            pos += size_t(rc);
            break;
        }
        if(rc == -1 && timeout > 0 && BIO_wait(d, deadline, 100) != 1)
            break;
    } while(rc != 0);
    r.content.resize(pos);

    // Parse HTTP headers
    const size_t bodyStart = headerEnd(r.content);
    if(bodyStart == string_view::npos)
        THROW_NETWORKEXCEPTION("Invalid HTTP response: missing end of headers")
    for(string_view head = string_view(r.content).substr(0, bodyStart), line; nextLine(head, line);)
    {
        if(line.empty())
            break;
        if(r.result.empty())
        {
            r.result = to_lower(string(line));
            continue;
        }
        size_t colon = line.find(':');
        string_view value = colon == string_view::npos ? string_view{} : line.substr(colon + 1);
        r.headers[to_lower(string(line.substr(0, colon)))] = trim(value, " \t");
    }
    r.content.erase(0, bodyStart);

    // HEAD, 204 and 304 responses have no body, whatever their framing headers say.
    if(method == "HEAD" || r.isStatusCode("204") || r.isStatusCode("304"))
        r.content.clear();
    // Handle chunked transfer encoding
    else if(const auto it = r.headers.find("transfer-encoding");
        it != r.headers.cend() &&
        it->second.find("chunked") != string::npos) {
        size_t out = 0;
        for(pos = 0;;)
        {
            size_t end = r.content.find("\r\n", pos);
            if(end == string::npos)
                THROW_NETWORKEXCEPTION("Invalid HTTP chunked response: missing chunk size")
            string_view field = string_view(r.content).substr(pos, end - pos);
            if(size_t ext = field.find(';'); ext != string_view::npos)
                field = trim_suffix(field.substr(0, ext), " \t");
            size_t chunk = 0;
            if(!parseInteger(field, chunk, 16))
                THROW_NETWORKEXCEPTION("Invalid HTTP chunked response: chunk size '%.*s'", STR_VIEW_FMT(field))
            pos = end + 2;
            if(chunk == 0)
            {
                // The last chunk is followed by optional trailer fields and an empty line.
                if(r.content.compare(pos, 2, "\r\n") != 0 && !string_view(r.content).substr(pos).contains("\r\n\r\n"))
                    THROW_NETWORKEXCEPTION("Invalid HTTP chunked response: missing final CRLF")
                break;
            }
            if(chunk > r.content.size() - pos || r.content.compare(pos + chunk, 2, "\r\n") != 0)
                THROW_NETWORKEXCEPTION("Invalid HTTP chunked response: truncated chunk")
            copy_n(r.content.data() + pos, chunk, r.content.data() + out);
            out += chunk;
            pos += chunk + 2;
        }
        r.content.resize(out);
    }

    // Handle content encoding
    if(const auto it = r.headers.find("content-encoding");
        it != r.headers.cend())
        r.content = decompress(it->second, r.content);

    if(!r.isRedirect() || recursive > 3)
        return r;
    string &location = r.headers["location"];
    string url = location.find("://") != string::npos ? std::move(location) : baseurl + location;
    Connect c(url, method, timeout, std::move(certs), std::move(userAgentData), version);
    c.recursive = recursive + 1;
    return c.exec(headers);
}

void Connect::sendProxyAuth()
{
    Conf *c = Conf::instance();
    if(c->proxyUser().empty() || c->proxyPass().empty())
        return;

    BIO_printf(d, "Proxy-Authorization: Basic ");
    auto b64 = make_unique_ptr<BIO_free>(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64.get(), d);
    BIO_printf(b64.get(), "%s:%s", c->proxyUser().c_str(), c->proxyPass().c_str());
    (void)BIO_flush(b64.get());
    BIO_pop(b64.get());
    BIO_printf(d, "\r\n");
}
