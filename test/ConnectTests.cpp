// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <boost/test/unit_test.hpp>

#include <crypto/Connect.h>
#include <crypto/OpenSSLHelpers.h>
#include <util/File.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <optional>
#include <thread>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

using namespace digidoc;
using namespace std;
using namespace chrono_literals;

namespace
{
struct Environment
{
    const char *name;
    optional<string> previous;

    Environment(const char *name, const string &value): name(name)
    {
        if(const char *old = getenv(name))
            previous = old;
        set(value.c_str());
    }

    ~Environment() { set(previous ? previous->c_str() : nullptr); }

    void set(const char *value) const
    {
#ifdef _WIN32
        _putenv_s(name, value ? value : "");
#else
        if(value)
            setenv(name, value, 1);
        else
            unsetenv(name);
#endif
    }
};

struct TLSFixture
{
    unique_free_d<EVP_PKEY_free> key {nullptr};
    unique_free_d<X509_free> cert {X509_new()};
    filesystem::path path = util::File::tempFileName();
    Environment caFile {"SSL_CERT_FILE", util::File::decodeName(path)};
    Environment caDirectory {"SSL_CERT_DIR", util::File::decodeName(path) + ".missing"};
    string error;
    int timeout = 5;

    explicit TLSFixture(const string &name = "localhost")
    {
        auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        BOOST_REQUIRE(ctx);
        BOOST_REQUIRE_EQUAL(EVP_PKEY_keygen_init(ctx.get()), 1);
        BOOST_REQUIRE_EQUAL(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1), 1);
        EVP_PKEY *generated = nullptr;
        BOOST_REQUIRE_EQUAL(EVP_PKEY_keygen(ctx.get(), &generated), 1);
        key.reset(generated);
        BOOST_REQUIRE(cert);
        BOOST_REQUIRE_EQUAL(X509_set_version(cert.get(), 2), 1);
        BOOST_REQUIRE_EQUAL(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1), 1);
        BOOST_REQUIRE(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60));
        BOOST_REQUIRE(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600));
        BOOST_REQUIRE_EQUAL(X509_set_pubkey(cert.get(), key.get()), 1);
        auto subject = make_unique_ptr<X509_NAME_free>(X509_NAME_new());
        BOOST_REQUIRE(subject);
        BOOST_REQUIRE_EQUAL(X509_NAME_add_entry_by_txt(subject.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(name.c_str()), -1, -1, 0), 1);
        BOOST_REQUIRE_EQUAL(X509_set_subject_name(cert.get(), subject.get()), 1);
        BOOST_REQUIRE_EQUAL(X509_set_issuer_name(cert.get(), subject.get()), 1);
        string san = "DNS:" + name;
        auto names = make_unique_ptr<X509_EXTENSION_free>(X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_subject_alt_name, san.data()));
        BOOST_REQUIRE(names);
        BOOST_REQUIRE_EQUAL(X509_add_ext(cert.get(), names.get(), -1), 1);
        auto usage = make_unique_ptr<X509_EXTENSION_free>(X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_ext_key_usage, const_cast<char*>("serverAuth")));
        BOOST_REQUIRE(usage);
        BOOST_REQUIRE_EQUAL(X509_add_ext(cert.get(), usage.get(), -1), 1);
        BOOST_REQUIRE_GT(X509_sign(cert.get(), key.get(), EVP_sha256()), 0);
    }

    ~TLSFixture()
    {
        error_code ec;
        filesystem::remove(path, ec);
    }

    void trustDefault() const
    {
        auto file = make_unique_ptr<BIO_free>(BIO_new_file(util::File::decodeName(path).c_str(), "w"));
        BOOST_REQUIRE(file);
        BOOST_REQUIRE_EQUAL(PEM_write_bio_X509(file.get(), cert.get()), 1);
    }

    bool connect(string_view hostname = "localhost", vector<X509Cert> anchors = {},
        initializer_list<string_view> responses = {"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"})
    {
        auto ctx = make_unique_ptr<SSL_CTX_free>(SSL_CTX_new(TLS_server_method()));
        BOOST_REQUIRE(ctx);
        BOOST_REQUIRE_EQUAL(SSL_CTX_use_certificate(ctx.get(), cert.get()), 1);
        BOOST_REQUIRE_EQUAL(SSL_CTX_use_PrivateKey(ctx.get(), key.get()), 1);
        auto listener = make_unique_ptr<BIO_free_all>(BIO_new_accept("localhost:0"));
        BOOST_REQUIRE(listener);
        BIO_set_nbio_accept(listener.get(), 1);
        BIO_set_nbio(listener.get(), 1);
        BOOST_REQUIRE_EQUAL(BIO_do_accept(listener.get()), 1);
        auto address = make_unique_ptr<BIO_ADDR_free>(BIO_ADDR_new());
        BOOST_REQUIRE(address);
        union BIO_sock_info_u info {};
        info.addr = address.get();
        BOOST_REQUIRE_EQUAL(BIO_sock_info(BIO_get_fd(listener.get(), nullptr), BIO_SOCK_INFO_ADDRESS, &info), 1);
        char *port = BIO_ADDR_service_string(address.get(), 1);
        BOOST_REQUIRE(port);
        string url = "https://" + string(hostname) + ':' + port + '/';
        OPENSSL_free(port);

        auto server = async(launch::async, [&]
        {
#ifdef _WIN32
            struct ThreadCleanup { ~ThreadCleanup() { OPENSSL_thread_stop(); } } cleanup;
#endif
            const auto deadline = chrono::steady_clock::now() + 10s;
            for(string_view response: responses)
            {
                while(BIO_do_accept(listener.get()) != 1)
                {
                    if(!BIO_should_retry(listener.get()) || chrono::steady_clock::now() >= deadline)
                        return false;
                    this_thread::sleep_for(5ms);
                }
                BIO *peer = BIO_pop(listener.get());
                auto ssl = make_unique_ptr<SSL_free>(SSL_new(ctx.get()));
                if(!ssl)
                {
                    BIO_free_all(peer);
                    return false;
                }
                SSL_set_bio(ssl.get(), peer, peer);
                for(int result; (result = SSL_accept(ssl.get())) != 1;)
                {
                    int error = SSL_get_error(ssl.get(), result);
                    if((error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) ||
                        chrono::steady_clock::now() >= deadline)
                        return false;
                    this_thread::sleep_for(5ms);
                }
                string request;
                while(request.find("\r\n\r\n") == string::npos)
                {
                    if(chrono::steady_clock::now() >= deadline)
                        return false;
                    char buffer[1024];
                    int result = SSL_read(ssl.get(), buffer, sizeof(buffer));
                    if(result > 0)
                        request.append(buffer, size_t(result));
                    else
                    {
                        int error = SSL_get_error(ssl.get(), result);
                        if(error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                            return false;
                        this_thread::sleep_for(5ms);
                    }
                }
                bool written = SSL_write(ssl.get(), response.data(), int(response.size())) == int(response.size());
                SSL_shutdown(ssl.get());
                if(!written)
                    return false;
            }
            return true;
        });
        bool accepted = false;
        try
        {
            Connect connection(url, "GET", timeout, std::move(anchors));
            accepted = connection.exec().content == "OK";
        }
        catch(const Exception &e)
        {
            BOOST_CHECK_EQUAL(e.code(), Exception::NetworkError);
            error = e.msg();
        }
        const bool served = server.get();
        if(accepted)
            BOOST_CHECK(served);
        ERR_clear_error();
        return accepted;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(ConnectSuite, TLSFixture)

#if !TARGET_OS_OSX && !TARGET_OS_IOS && !defined(__ANDROID__)
BOOST_AUTO_TEST_CASE(acceptsDefaultTrustedServer)
{
    trustDefault();
    BOOST_CHECK(connect());
}
#endif

BOOST_AUTO_TEST_CASE(rejectsUntrustedServer)
{
    BOOST_CHECK(!connect());
    BOOST_CHECK_NE(error.find("TLS certificate verification failed"), string::npos);
}

BOOST_AUTO_TEST_CASE(blockingHandshake)
{
    timeout = 0;
    BOOST_CHECK(!connect());
    BOOST_CHECK_NE(error.find("TLS certificate verification failed"), string::npos);
    BOOST_CHECK(connect("localhost", {X509Cert(cert.get())}));
}

#if !TARGET_OS_OSX && !TARGET_OS_IOS && !defined(__ANDROID__)
BOOST_AUTO_TEST_CASE(rejectsWrongHostname)
{
    TLSFixture other("example.invalid");
    other.trustDefault();
    BOOST_CHECK(!other.connect());
    BOOST_CHECK_NE(other.error.find("hostname mismatch"), string::npos);
}
#endif

BOOST_AUTO_TEST_CASE(acceptsConfiguredTrustAnchor)
{
    BOOST_CHECK(connect("localhost", {X509Cert(cert.get())}));
}

BOOST_AUTO_TEST_CASE(configuredTrustAnchorsReplaceDefaults)
{
    TLSFixture other;
    caFile.set(util::File::decodeName(path).c_str());
    trustDefault();
    BOOST_CHECK(!connect("localhost", {X509Cert(other.cert.get())}));
}

BOOST_AUTO_TEST_CASE(followsRedirectToHTTPS)
{
    BOOST_CHECK(connect("localhost", {X509Cert(cert.get())}, {
        "HTTP/1.0 302 Found\r\nLocation: /next\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"}));
}

BOOST_AUTO_TEST_CASE(rejectsRedirectToHTTP)
{
    BOOST_CHECK(!connect("localhost", {X509Cert(cert.get())},
        {"HTTP/1.0 302 Found\r\nLocation: http://127.0.0.1:1/\r\n\r\n"}));
    BOOST_CHECK_NE(error.find("Refusing redirect from HTTPS"), string::npos);
}

#if TARGET_OS_OSX
BOOST_AUTO_TEST_CASE(macOSDefaultTrustRejectsUnknownServer)
{
    caFile.set(nullptr);
    caDirectory.set(nullptr);
    BOOST_CHECK(!connect());
}
#endif

BOOST_AUTO_TEST_SUITE_END()
