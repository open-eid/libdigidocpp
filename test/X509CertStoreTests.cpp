/*
 * SPDX-FileCopyrightText: Estonian Information System Authority
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define BOOST_TEST_MODULE "X509 certificate store tests"
#include "test.h"

#include <Signature.h>
#include <crypto/PKCS12Signer.h>
#include <crypto/X509CertStore.h>

#include <openssl/x509v3.h>

struct StoreFixture: DigiDocPPFixture
{
    StoreFixture()
    {
        initialize("X509CertStoreTests");
        // This target compiles the private store implementation without exporting it.
        X509CertStore::instance()->update();
    }

};

BOOST_GLOBAL_FIXTURE(StoreFixture);

namespace {

struct RestoreStore
{
    ~RestoreStore() { X509CertStore::instance()->update(); }
};

auto verify(const X509Cert &cert, const vector<X509Cert> &untrusted = {},
    const X509CertStore::Type &type = X509CertStore::CA)
{
    tm time{};
    ASN1_TIME_to_tm(X509_get0_notBefore(cert.handle()), &time);
    auto store = X509CertStore::createStore(type, time);
    auto stack = make_unique_ptr(sk_X509_new_null(), [](auto *sk) { sk_X509_free(sk); });
    for(const auto &candidate: untrusted)
        sk_X509_push(stack.get(), candidate.handle());
    auto ctx = make_unique_ptr<X509_STORE_CTX_free>(X509_STORE_CTX_new());
    BOOST_REQUIRE_EQUAL(X509_STORE_CTX_init(ctx.get(), store.get(), cert.handle(), stack.get()), 1);
    int result = X509_verify_cert(ctx.get());
    vector<X509Cert> chain;
    auto *built = X509_STORE_CTX_get0_chain(ctx.get());
    for(int i = 0; i < sk_X509_num(built); ++i)
        chain.emplace_back(sk_X509_value(built, i));
    return pair{result, std::move(chain)};
}

}

BOOST_AUTO_TEST_CASE(tsl_issuer_precedes_supplied_candidates)
{
    PKCS12Signer signer("signer1.p12", "signer1");
    X509Cert issuer("inter.crt");
    X509Cert root("ca.crt");
    for(bool sameKey: {false, true})
    {
        BOOST_TEST_CONTEXT("same public key: " << sameKey)
        {
            auto decoy = make_unique_ptr<X509_free>(X509_dup(issuer.handle()));
            BOOST_REQUIRE(decoy);
            if(!sameKey)
                BOOST_REQUIRE_EQUAL(X509_set_pubkey(decoy.get(), X509_get0_pubkey(root.handle())), 1);
            int index = X509_get_ext_by_NID(decoy.get(), NID_subject_key_identifier, -1);
            BOOST_REQUIRE_GE(index, 0);
            X509_EXTENSION_free(X509_delete_ext(decoy.get(), index));
            BOOST_REQUIRE_EQUAL(ASN1_TIME_set_string(X509_getm_notBefore(decoy.get()), "20990101000000Z"), 1);
            BOOST_REQUIRE_GT(i2d_re_X509_tbs(decoy.get(), nullptr), 0);
            X509Cert candidate(decoy.get());
            BOOST_REQUIRE_EQUAL(X509_check_issued(candidate.handle(), signer.cert().handle()), X509_V_OK);
            auto [result, chain] = verify(signer.cert(), {candidate});
            BOOST_REQUIRE_EQUAL(result, 1);
            BOOST_REQUIRE_EQUAL(chain.size(), 2U);
            BOOST_CHECK_EQUAL(chain[1], issuer);
        }
    }
}

BOOST_AUTO_TEST_CASE(sha1_certificate_uses_tsl_issuer)
{
    auto container = Container::openPtr("sha1-cert-ocsp.bdoc");
    BOOST_REQUIRE_EQUAL(container->signatures().size(), 1U);
    auto cert = container->signatures().front()->signingCertificate();
    BOOST_REQUIRE_EQUAL(X509_get_signature_nid(cert.handle()), NID_sha1WithRSAEncryption);
    auto issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    BOOST_REQUIRE(issuer);
    auto [result, chain] = verify(cert);
    BOOST_REQUIRE_EQUAL(result, 1);
    BOOST_REQUIRE_EQUAL(chain.size(), 2U);
    BOOST_CHECK_EQUAL(chain.back(), issuer);
}

BOOST_AUTO_TEST_CASE(legacy_signature_retry_preserves_other_failures)
{
    auto container = Container::openPtr("sha1-cert-ocsp.bdoc");
    BOOST_REQUIRE_EQUAL(container->signatures().size(), 1U);
    auto cert = container->signatures().front()->signingCertificate();
    auto issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    BOOST_REQUIRE(issuer);
    auto callbackResult = [](const X509Cert &cert, const X509Cert &issuer, int error) {
        tm time{};
        ASN1_TIME_to_tm(X509_get0_notBefore(cert.handle()), &time);
        auto store = X509CertStore::createStore(X509CertStore::CA, time);
        auto ctx = make_unique_ptr<X509_STORE_CTX_free>(X509_STORE_CTX_new());
        BOOST_REQUIRE_EQUAL(X509_STORE_CTX_init(ctx.get(), store.get(), cert.handle(), nullptr), 1);
        auto chain = make_unique_ptr(sk_X509_new_null(), [](auto *sk) { sk_X509_pop_free(sk, X509_free); });
        BOOST_REQUIRE(chain);
        for(const auto *candidate: {&cert, &issuer})
        {
            auto copy = make_unique_ptr<X509_free>(X509_dup(candidate->handle()));
            BOOST_REQUIRE(copy);
            BOOST_REQUIRE_GT(sk_X509_push(chain.get(), copy.get()), 0);
            copy.release();
        }
        X509_STORE_CTX_set_current_cert(ctx.get(), sk_X509_value(chain.get(), 0));
        X509_STORE_CTX_set0_verified_chain(ctx.get(), chain.release());
        X509_STORE_CTX_set_error_depth(ctx.get(), 0);
        X509_STORE_CTX_set_error(ctx.get(), error);
        return X509_STORE_CTX_get_verify_cb(ctx.get())(0, ctx.get());
    };

    // Only Fedora/RHEL supplies the private-context SHA-1 compatibility hook.
    bool legacyAvailable = bool(X509CertStore::legacyCertificate(cert.handle()));
    BOOST_CHECK_EQUAL(callbackResult(cert, issuer, X509_V_ERR_CERT_SIGNATURE_FAILURE), legacyAvailable ? 1 : 0);
    BOOST_CHECK_EQUAL(callbackResult(cert, issuer, X509_V_ERR_CERT_HAS_EXPIRED), 0);
    BOOST_CHECK_EQUAL(callbackResult(cert, issuer, X509_V_ERR_CERT_NOT_YET_VALID), 0);
    BOOST_CHECK_EQUAL(callbackResult(cert, X509Cert("ca.crt"), X509_V_ERR_CERT_SIGNATURE_FAILURE), 0);
    vector<unsigned char> damaged = cert;
    damaged.back() ^= 1;
    BOOST_CHECK_EQUAL(callbackResult(X509Cert(damaged), issuer, X509_V_ERR_CERT_SIGNATURE_FAILURE), 0);
    PKCS12Signer signer("signer1.p12", "signer1");
    BOOST_REQUIRE_NE(X509_get_signature_nid(signer.cert().handle()), NID_sha1WithRSAEncryption);
    BOOST_CHECK_EQUAL(callbackResult(signer.cert(), X509Cert("inter.crt"), X509_V_ERR_CERT_SIGNATURE_FAILURE), 0);
}

BOOST_AUTO_TEST_CASE(tsl_intermediate_does_not_require_root)
{
    PKCS12Signer signer("signer1.p12", "signer1");
    auto [result, chain] = verify(signer.cert());
    BOOST_REQUIRE_EQUAL(result, 1);
    BOOST_CHECK_EQUAL(chain.size(), 2U);
}

BOOST_AUTO_TEST_CASE(untrusted_chain_requires_tsl_anchor)
{
    X509Cert root("ca.crt");
    auto [result, chain] = verify(root, {root});
    BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE(supplied_intermediate_completes_chain_to_tsl)
{
    X509Cert leaf("issuer-chain-leaf.crt", X509Cert::Der);
    auto [missing, incomplete] = verify(leaf);
    BOOST_CHECK_EQUAL(missing, 0);
    auto [result, chain] = verify(leaf, {X509Cert("issuer-chain-intermediate.crt", X509Cert::Der)});
    BOOST_REQUIRE_EQUAL(result, 1);
    BOOST_REQUIRE_EQUAL(chain.size(), 3U);
    BOOST_CHECK_EQUAL(chain.back(), X509Cert("inter.crt"));
}

BOOST_AUTO_TEST_CASE(service_type_is_enforced)
{
    PKCS12Signer signer("signer1.p12", "signer1");
    auto [result, chain] = verify(signer.cert(), {X509Cert("inter.crt")}, X509CertStore::TSA);
    BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE(tsl_qualifiers_remain_available)
{
    PKCS12Signer signer("signer1.p12", "signer1");
    BOOST_CHECK(signer.cert().verify(false));
}

BOOST_AUTO_TEST_CASE(renewed_tsl_issuer_does_not_shadow_historical_certificate)
{
    RestoreStore restore;
    X509Cert cert("issuer-chain-intermediate.crt", X509Cert::Der);
    X509Cert original("inter.crt");
    auto historical = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    BOOST_REQUIRE(historical);
    auto certs = X509CertStore::instance()->certs(X509CertStore::CA);
    BOOST_REQUIRE(!certs.empty());
    // Replace an earlier, granted CA identity in this process's private test store.
    // Its certificate signature is irrelevant: the TSL authenticates its name/key.
    auto &renewed = certs.front();
    BOOST_REQUIRE(renewed != original);
    BOOST_REQUIRE_EQUAL(X509_set_subject_name(renewed.handle(), X509_get_subject_name(original.handle())), 1);
    BOOST_REQUIRE_EQUAL(X509_set_pubkey(renewed.handle(), X509_get0_pubkey(original.handle())), 1);
    int index = X509_get_ext_by_NID(renewed.handle(), NID_subject_key_identifier, -1);
    BOOST_REQUIRE_GE(index, 0);
    X509_EXTENSION_free(X509_delete_ext(renewed.handle(), index));
    BOOST_REQUIRE_EQUAL(ASN1_TIME_set_string(X509_getm_notBefore(renewed.handle()), "20400101000000Z"), 1);
    BOOST_REQUIRE_EQUAL(ASN1_TIME_set_string(X509_getm_notAfter(renewed.handle()), "20500101000000Z"), 1);
    BOOST_REQUIRE_GT(i2d_re_X509_tbs(renewed.handle(), nullptr), 0);
    // Reparse after changing extensions to invalidate OpenSSL's cached key identifier.
    vector<unsigned char> der(size_t(i2d_X509(renewed.handle(), nullptr)));
    auto *out = der.data();
    BOOST_REQUIRE_GT(i2d_X509(renewed.handle(), &out), 0);
    const auto *in = der.data();
    X509 *reused = renewed.handle();
    BOOST_REQUIRE(d2i_X509(&reused, &in, long(der.size())));
    BOOST_REQUIRE_EQUAL(reused, renewed.handle());
    BOOST_REQUIRE_EQUAL(X509_check_issued(renewed.handle(), cert.handle()), X509_V_OK);
    for(bool futureFirst: {true, false})
    {
        BOOST_TEST_CONTEXT("future identity first: " << futureFirst)
        {
            for(auto [candidate, future]: {pair{renewed.handle(), futureFirst},
                    pair{historical.handle(), !futureFirst}})
            {
                BOOST_REQUIRE_EQUAL(ASN1_TIME_set_string(X509_getm_notBefore(candidate),
                    future ? "20400101000000Z" : "20240101000000Z"), 1);
                BOOST_REQUIRE_EQUAL(ASN1_TIME_set_string(X509_getm_notAfter(candidate),
                    future ? "20500101000000Z" : "20340101000000Z"), 1);
                BOOST_REQUIRE_GT(i2d_re_X509_tbs(candidate, nullptr), 0);
            }
            auto [result, chain] = verify(cert);
            BOOST_REQUIRE_EQUAL(result, 1);
            BOOST_REQUIRE_EQUAL(chain.size(), 2U);
            const auto &expected = futureFirst ? historical : renewed;
            BOOST_CHECK_EQUAL(ASN1_TIME_compare(X509_get0_notBefore(chain.back().handle()),
                X509_get0_notBefore(expected.handle())), 0);
        }
    }
}
