// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "Connect.h"

#include "Conf.h"
#include "Container.h"
#include "crypto/OpenSSLHelpers.h"
#include "util/algorithm.h"

#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <zlib.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if TARGET_OS_OSX || TARGET_OS_IOS
#include <Security/Security.h>
#endif

#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <sstream>

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

static constexpr size_t MAX_RESPONSE_SIZE = 10 * 1024 * 1024;

#if TARGET_OS_OSX || TARGET_OS_IOS
static constexpr auto CFScope(auto *value) noexcept
{
    return make_unique_ptr<CFRelease>(value);
}

// The system evaluates the chain, so keychain trust settings apply and iOS, which does not expose its roots, works
static int verifyWithSystemRoots(X509_STORE_CTX *ctx, void * /*arg*/)
{
    auto *ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    auto hostname = CFScope(host && *host ? CFStringCreateWithCString(nullptr, host, kCFStringEncodingUTF8) : nullptr);
    auto policy = CFScope(hostname ? SecPolicyCreateSSL(true, hostname.get()) : nullptr);
    auto chain = CFScope(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
    STACK_OF(X509) *certs = X509_STORE_CTX_get0_untrusted(ctx);
    for(int i = 0; i < sk_X509_num(certs); ++i)
    {
        vector<unsigned char> der = X509Cert(sk_X509_value(certs, i));
        auto data = CFScope(CFDataCreate(nullptr, der.data(), CFIndex(der.size())));
        if(auto cert = CFScope(SecCertificateCreateWithData(nullptr, data.get())))
            CFArrayAppendValue(chain.get(), cert.get());
    }
    SecTrustRef trust = nullptr;
    if(policy)
        SecTrustCreateWithCertificates(chain.get(), policy.get(), &trust);
    auto trustScope = CFScope(trust);
    // Fetching missing intermediates would run outside the connection timeout
    bool trusted = trust && SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess &&
        SecTrustEvaluateWithError(trust, nullptr);
    X509_STORE_CTX_set_error(ctx, trusted ? X509_V_OK : X509_V_ERR_APPLICATION_VERIFICATION);
    return trusted;
}
#elifdef __ANDROID__
// Apps run with AT_SECURE, so OpenSSL ignores SSL_CERT_FILE; load only the system roots named by the old
// subject hash of the chain's issuers
static int verifyWithSystemRoots(X509_STORE_CTX *ctx, void * /*arg*/)
{
    error_code ec;
    const char *dir = filesystem::is_directory("/apex/com.android.conscrypt/cacerts", ec) ?
        "/apex/com.android.conscrypt/cacerts" : "/system/etc/security/cacerts";
    X509_STORE *store = X509_STORE_CTX_get0_store(ctx);
    STACK_OF(X509) *certs = X509_STORE_CTX_get0_untrusted(ctx);
    for(int i = 0; i < sk_X509_num(certs); ++i)
    {
        unsigned long hash = X509_NAME_hash_old(X509_get_issuer_name(sk_X509_value(certs, i)));
        array<char, 64> path {};
        for(int n = 0; snprintf(path.data(), path.size(), "%s/%08lx.%d", dir, hash, n) > 0; ++n)
        {
            auto file = make_unique_ptr<fclose>(fopen(path.data(), "r"));
            if(!file)
                break;
            if(auto x509 = make_unique_ptr<X509_free>(PEM_read_X509(file.get(), nullptr, nullptr, nullptr)))
                X509_STORE_add_cert(store, x509.get());
        }
    }
    return X509_verify_cert(ctx);
}
#endif

static void loadSystemRoots(SSL_CTX *ctx)
{
#if TARGET_OS_OSX || TARGET_OS_IOS || defined(__ANDROID__)
    SSL_CTX_set_cert_verify_callback(ctx, verifyWithSystemRoots, nullptr);
#else
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if(X509_STORE_set_default_paths(store) != 1)
        THROW_NETWORKEXCEPTION("Failed to load default TLS trust store")
#ifdef _WIN32
    if(X509_STORE_load_store(store, "org.openssl.winstore:") != 1)
        THROW_NETWORKEXCEPTION("Failed to load Windows TLS trust store")
#endif
#endif
}

Connect::Connect(const string &_url, string_view _method, int _timeout, vector<X509Cert> _certs, string _userAgentData, string_view _version)
    : Connect(_url, _method, _timeout, std::move(_certs), std::move(_userAgentData), _version, {nullptr, SSL_CTX_free})
{}

Connect::Connect(const string &_url, string_view _method, int _timeout, vector<X509Cert> _certs, string _userAgentData,
        string_view _version, unique_free_t<SSL_CTX> _ssl)
    : userAgentData(std::move(_userAgentData))
    , method(_method)
    , version(_version)
    , certs(std::move(_certs))
    , d(nullptr, BIO_free_all)
    , ssl(std::move(_ssl))
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
    d.reset(BIO_new_connect(hostname.c_str()));
    if(!d)
        THROW_NETWORKEXCEPTION("Failed to create connection with host: '%s'", hostname.c_str())

    BIO_set_nbio(d.get(), _timeout > 0);
    const auto deadline = chrono::steady_clock::now() + chrono::seconds(timeout);
    if(int rc = timeout > 0 ? BIO_do_connect_retry(d.get(), timeout, -1) : BIO_do_connect(d.get()); rc < 1)
    {
        if(rc == 0 && timeout > 0)
            THROW_NETWORKEXCEPTION("Failed to create connection with host timeout: '%s'", hostname.c_str())
        THROW_NETWORKEXCEPTION("Failed to create connection with host: '%s'", hostname.c_str())
    }

    if(usessl > 0)
    {
        if(!c->proxyHost().empty() && (CONF(proxyTunnelSSL)))
        {
            BIO_printf(d.get(), "CONNECT %s:%s HTTP/1.0\r\n", host.c_str(), port.c_str());
            addHeader("Host", host + ':' + port);
            sendProxyAuth();
            doProxyConnect = true;
            Result r = exec();
            if(!r.isOK() || (r.result.find("established") == string::npos && r.result.find("ok") == string::npos))
                THROW_NETWORKEXCEPTION("Failed to create proxy connection with host: '%s'", hostname.c_str())
            doProxyConnect = false;
        }

        if(!ssl)
        {
            ssl.reset(SSL_CTX_new(TLS_client_method()));
            if(!ssl)
                THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
            SSL_CTX_set_mode(ssl.get(), SSL_MODE_AUTO_RETRY);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
            SSL_CTX_set_options(ssl.get(), SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
            SSL_CTX_set_quiet_shutdown(ssl.get(), 1);
            SSL_CTX_set_verify(ssl.get(), SSL_VERIFY_PEER, nullptr);
            if(!certs.empty())
            {
                X509_STORE *store = SSL_CTX_get_cert_store(ssl.get());
                X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
                for(const X509Cert &cert: certs)
                {
                    if(cert.handle())
                        X509_STORE_add_cert(store, cert.handle());
                }
            }
            else
                loadSystemRoots(ssl.get());
        }
        auto sbio = make_unique_ptr(BIO_new_ssl(ssl.get(), 1), BIO_free_all);
        if(!sbio)
            THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
        SSL *session {};
        if(BIO_get_ssl(sbio.get(), &session) != 1 || !session)
            THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
#if OPENSSL_VERSION_MAJOR >= 4
        if(SSL_set1_ipaddr(session, host.c_str()) != 1 && SSL_set1_dnsname(session, host.c_str()) != 1)
#else
        if(SSL_set1_host(session, host.c_str()) != 1)
#endif
            THROW_NETWORKEXCEPTION("Failed to set TLS host name: '%s'", host.c_str())
        SSL_set_tlsext_host_name(session, host.c_str());
        d.reset(BIO_push(sbio.release(), d.release()));
        int rc = 0;
        if(timeout == 0)
            rc = BIO_do_handshake(d.get());
        else if(auto remaining = chrono::ceil<chrono::seconds>(deadline - chrono::steady_clock::now()).count(); remaining > 0)
            rc = BIO_do_connect_retry(d.get(), int(remaining), -1);
        if(rc < 1)
        {
            if(long result = SSL_get_verify_result(session); result != X509_V_OK)
                THROW_NETWORKEXCEPTION("TLS certificate verification failed for host '%s': %s",
                    host.c_str(), X509_verify_cert_error_string(result))
            if(rc == 0 && timeout > 0)
                THROW_NETWORKEXCEPTION("Failed to create ssl connection with host timeout: '%s'", hostname.c_str())
            THROW_NETWORKEXCEPTION("Failed to create ssl connection with host: '%s'", hostname.c_str())
        }
    }

    BIO_printf(d.get(), "%.*s %s HTTP/%.*s\r\n", STR_VIEW_FMT(method), path.c_str(), STR_VIEW_FMT(version));
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

void Connect::addHeader(string_view key, string_view value)
{
    BIO_printf(d.get(), "%.*s: %.*s\r\n", STR_VIEW_FMT(key), STR_VIEW_FMT(value));
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
        if(s.total_out >= out.size()) {
            if(out.size() >= MAX_RESPONSE_SIZE)
                THROW_NETWORKEXCEPTION("HTTP decompressed response exceeds maximum allowed size of %zu bytes", MAX_RESPONSE_SIZE)
            out.resize(out.size() * 2);
        }
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
        BIO_printf(d.get(), "\r\n");
        BIO_write(d.get(), data, int(size));
    }
    else
        BIO_printf(d.get(), "\r\n");

    int rc = 0;
    size_t pos = 0;
    Result r;
    r.content.resize(1024);
    chrono::high_resolution_clock::time_point start = chrono::high_resolution_clock::now();
    do {
        if(rc > 0) {
            pos += size_t(rc);
            if(pos > MAX_RESPONSE_SIZE)
                THROW_NETWORKEXCEPTION("HTTP response exceeds maximum allowed size of %zu bytes", MAX_RESPONSE_SIZE)
            if(pos >= r.content.size())
                r.content.resize(r.content.size() * 2);
        }
        rc = BIO_read(d.get(), &r.content[pos], int(r.content.size() - pos));
        if(rc == -1 && BIO_should_read(d.get()) != 1)
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
    while(getline(stream, line))
    {
        line.resize(max<size_t>(line.size() - 1, 0));
        if(line.empty())
            break;
        if(r.result.empty())
        {
            r.result = to_lower(line);
            continue;
        }
        size_t split = line.find(": ");
        if(split != string::npos)
            r.headers[to_lower(line.erase(split))] = line.substr(split + 2);
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

    if(doProxyConnect || !r.isRedirect() || recursive > 3)
        return r;
    string &location = r.headers["location"];
    string url = location.find("://") != string::npos ? std::move(location) : baseurl + location;
    if(ssl && !to_lower(url.substr(0, 8)).starts_with("https://"))
        THROW_NETWORKEXCEPTION("Refusing redirect from HTTPS to a non-HTTPS URL: '%s'", url.c_str())
    Connect c(url, method, timeout, std::move(certs), std::move(userAgentData), version, std::move(ssl));
    c.recursive = recursive + 1;
    return c.exec(headers);
}

void Connect::sendProxyAuth()
{
    Conf *c = Conf::instance();
    if(c->proxyUser().empty() || c->proxyPass().empty())
        return;

    BIO_printf(d.get(), "Proxy-Authorization: Basic ");
    auto b64 = make_unique_ptr<BIO_free>(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64.get(), d.get());
    BIO_printf(b64.get(), "%s:%s", c->proxyUser().c_str(), c->proxyPass().c_str());
    (void)BIO_flush(b64.get());
    BIO_pop(b64.get());
    BIO_printf(d.get(), "\r\n");
}
