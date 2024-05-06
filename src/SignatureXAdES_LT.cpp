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

#include "SignatureXAdES_LT.h"

#include "ASiC_E.h"
#include "Conf.h"
#include "crypto/Digest.h"
#include "crypto/OCSP.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "crypto/X509CertStore.h"
#include "util/DateTime.h"
#include "util/log.h"

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_MSVC(4005)
#include <xsec/dsig/DSIGConstants.hpp>
DIGIDOCPP_WARNING_POP

#include <ctime>

using namespace digidoc;
using namespace digidoc::dsig;
using namespace digidoc::xades;
using namespace std;
using namespace xml_schema;

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return {const_cast<unsigned char*>(v.data()), v.size(), v.size(), false};
}

SignatureXAdES_LT::SignatureXAdES_LT(unsigned int id, ASiContainer *bdoc, Signer *signer)
: SignatureXAdES_T(id, bdoc, signer)
{}

SignatureXAdES_LT::SignatureXAdES_LT(const std::shared_ptr<Signatures> &signatures, size_t i, ASiContainer *container)
    : SignatureXAdES_T(signatures, i, container)
{
    try {
        // ADOC files are default T level, take OCSP response to create temporary LT level
        if(bdoc->mediaType() == ASiContainer::MIMETYPE_ADOC &&
            unsignedSignatureProperties().revocationValues().empty())
        {
            X509Cert cert = signingCertificate();
            X509Cert issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::OCSP);
            if(!issuer)
                THROW("Could not find certificate issuer '%s' in certificate store.",
                      cert.issuerName().c_str());

            addOCSPValue(id().replace(0, 1, "N"), OCSP(cert, issuer));
        }
    } catch(const Exception &) {
    }
}

vector<unsigned char> SignatureXAdES_LT::messageImprint() const
{
    if(profile().find(ASiC_E::ASIC_TM_PROFILE) != string::npos)
        return getOCSPResponseValue().nonce();
    return SignatureXAdES_T::messageImprint();
}

/**
 * @return returns OCSP certificate
 */
X509Cert SignatureXAdES_LT::OCSPCertificate() const
{
    return getOCSPResponseValue().responderCert();
}

/**
 * @return returns OCSP timestamp
 */
string SignatureXAdES_LT::OCSPProducedAt() const
{
    return util::date::to_string(getOCSPResponseValue().producedAt());
}

string SignatureXAdES_LT::trustedSigningTime() const
{
    string time = OCSPProducedAt();
    return time.empty() || profile().find(ASiC_E::ASIC_TM_PROFILE) == string::npos ? SignatureXAdES_T::trustedSigningTime() : std::move(time);
}

/**
 * Do TM offline validations.
 *
 * - Validate BES offline
 * - Check OCSP response (RevocationValues) was signed by trusted OCSP server
 * - Check that nonce field in OCSP response is same as CompleteRevocationRefs-&gt;DigestValue
 * - Recalculate hash of signature and compare with nonce
 *
 * @throws SignatureException if signature is not valid
 */
void SignatureXAdES_LT::validate(const string &policy) const
{
    Exception exception(EXCEPTION_PARAMS("Signature validation"));
    try {
        SignatureXAdES_T::validate(policy);
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }

    try {
        const UnsignedSignaturePropertiesType::RevocationValuesSequence &revSeq =
            unsignedSignatureProperties().revocationValues();
        if(revSeq.empty())
            THROW_MAIN(exception, "RevocationValues object is missing")
        if(revSeq.size() > 1)
            THROW_MAIN(exception, "More than one RevocationValues object is not supported")
        if(!revSeq.front().oCSPValues().present())
            THROW_MAIN(exception, "OCSPValues is missing")

        /*
         * Find OCSP response that matches with signingCertificate.
         * If none is found throw all OCSP validation exceptions.
         */
        bool foundSignerOCSP = false;
        vector<Exception> ocspExceptions;
        for(const OCSPValuesType::EncapsulatedOCSPValueType &resp: revSeq.front().oCSPValues()->encapsulatedOCSPValue())
        {
            OCSP ocsp(resp);
            try {
                ocsp.verifyResponse(signingCertificate());
                foundSignerOCSP = true;
            } catch(const Exception &e) {
                ocspExceptions.push_back(e);
                continue;
            }

            if(profile().find(ASiC_E::ASIC_TM_PROFILE) != string::npos)
            {
                vector<string> policies = ocsp.responderCert().certificatePolicies();
                const set<string> trusted = CONF(OCSPTMProfiles);
                if(!any_of(policies.cbegin(), policies.cend(), [&](const string &policy) { return trusted.find(policy) != trusted.cend(); }))
                {
                    EXCEPTION_ADD(exception, "OCSP Responder does not meet TM requirements");
                    break;
                }
                DEBUG("OCSP Responder contains valid TM OID");

                string method = Digest::digestInfoUri(ocsp.nonce());
                if(method.empty())
                    THROW("Nonce digest method is missing");
                vector<unsigned char> digest = Digest(method).result(getSignatureValue());
                vector<unsigned char> respDigest = Digest::digestInfoDigest(ocsp.nonce());
                if(digest != respDigest)
                {
                    DEBUGMEM("Calculated signature HASH", digest.data(), digest.size());
                    DEBUGMEM("Response nonce", respDigest.data(), respDigest.size());
                    EXCEPTION_ADD(exception, "Calculated signature hash doesn't match to OCSP responder nonce field");
                }
            }
            else
            {
                tm producedAt = ocsp.producedAt();
                string producedAt_s = util::date::to_string(producedAt);
                time_t producedAt_t = util::date::mkgmtime(producedAt);
                tm timeStampTime = TimeStamp().time();
                time_t timeStampTime_t = util::date::mkgmtime(timeStampTime);
                if(timeStampTime_t > producedAt_t)
                {
                    /*
                     * ETSI TS 103 171 V2.1.1 (2012-03)
                     * 8 Requirements for LT-Level Conformance
                     * This clause defines those requirements that XAdES signatures conformant to T-Level, have to fulfil to also be
                     * conformant to LT-Level.
                     */
                    Exception e(EXCEPTION_PARAMS("TimeStamp time is greater than OCSP producedAt TS: %s OCSP: %s", TimeStampTime().c_str(), producedAt_s.c_str()));
                    e.setCode(Exception::OCSPBeforeTimeStamp);
                    exception.addCause(e);
                }
                if((producedAt_t - timeStampTime_t > 15 * 60) && !Exception::hasWarningIgnore(Exception::ProducedATLateWarning))
                {
                    Exception e(EXCEPTION_PARAMS("TimeStamp time and OCSP producedAt are over 15m off TS: %s OCSP: %s", TimeStampTime().c_str(), producedAt_s.c_str()));
                    e.setCode(Exception::ProducedATLateWarning);
                    exception.addCause(e);
                }
            }
            break;
        }
        if(!foundSignerOCSP)
        {
            for(const Exception &e: ocspExceptions)
                exception.addCause(e);
        }
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}

/**
 *
 * @throws SignatureException
 */
void SignatureXAdES_LT::extendSignatureProfile(const string &profile)
{
    SignatureXAdES_T::extendSignatureProfile(profile);
    if(profile.find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
        return;

    // Get issuer certificate from certificate store.
    X509Cert cert = signingCertificate();
    X509Cert issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    if(!issuer)
        issuer = X509CertStore::issuerFromAIA(cert);
    if(!issuer)
        THROW("Could not find certificate issuer '%s' in certificate store or from AIA.",
            cert.issuerName().c_str());

    OCSP ocsp(cert, issuer);
    ocsp.verifyResponse(cert);

    addCertificateValue(id() + "-CA-CERT", issuer);
    addOCSPValue(id().replace(0, 1, "N"), ocsp);
    signatures->reloadDOM();
}

/**
 * Add certificate under CertificateValues element
 * @param certId id attribute of EncapsulatedX509Certificate
 * @param x509 value of EncapsulatedX509Certificate
 */
void SignatureXAdES_LT::addCertificateValue(const string& certId, const X509Cert& x509)
{
    DEBUG("SignatureXAdES_LT::addCertificateValue(%s, X509Cert{%s,%s})",
        certId.c_str(), x509.serial().c_str(), x509.subjectName().c_str());

    createUnsignedSignatureProperties();

    UnsignedSignaturePropertiesType::CertificateValuesSequence &values =
            unsignedSignatureProperties().certificateValues();
    if(values.empty())
    {
        values.push_back(make_unique<CertificateValuesType>());
        unsignedSignatureProperties().contentOrder().push_back(
            UnsignedSignaturePropertiesType::ContentOrderType(
                UnsignedSignaturePropertiesType::certificateValuesId, values.size() - 1));
    }

    auto certData = make_unique<CertificateValuesType::EncapsulatedX509CertificateType>(toBase64(x509));
    certData->id(certId);
    values[0].encapsulatedX509Certificate().push_back(std::move(certData));
}

void SignatureXAdES_LT::addOCSPValue(const string &id, const OCSP &ocsp)
{
    DEBUG("SignatureXAdES_LT::addOCSPValue(%s, %s)", id.c_str(), util::date::to_string(ocsp.producedAt()).c_str());

    createUnsignedSignatureProperties();

    auto ocspValueData = make_unique<OCSPValuesType::EncapsulatedOCSPValueType>(toBase64(ocsp));
    ocspValueData->id(id);

    auto ocspValue = make_unique<OCSPValuesType>();
    ocspValue->encapsulatedOCSPValue().push_back(std::move(ocspValueData));

    auto revocationValues = make_unique<RevocationValuesType>();
    revocationValues->oCSPValues(std::move(ocspValue));

    unsignedSignatureProperties().revocationValues().push_back(std::move(revocationValues));
    unsignedSignatureProperties().contentOrder().push_back(
        UnsignedSignaturePropertiesType::ContentOrderType(
            UnsignedSignaturePropertiesType::revocationValuesId,
            unsignedSignatureProperties().revocationValues().size() - 1));
}

/**
 * Get value of UnsignedProperties\UnsignedSignatureProperties\RevocationValues\OCSPValues\EncapsulatedOCSPValue
 * which contains whole OCSP response
 * @param data will contain DER encoded OCSP response bytes
 */
OCSP SignatureXAdES_LT::getOCSPResponseValue() const
{
    try
    {
        if(unsignedSignatureProperties().revocationValues().empty())
            return {};
        const RevocationValuesType &t = unsignedSignatureProperties().revocationValues().front();
        if(!t.oCSPValues().present() || t.oCSPValues()->encapsulatedOCSPValue().empty())
            return {};
        // Return OCSP response that matches with signingCertificate
        for(const OCSPValuesType::EncapsulatedOCSPValueType &resp: t.oCSPValues()->encapsulatedOCSPValue())
        {
            try {
                OCSP ocsp(resp);
                ocsp.verifyResponse(signingCertificate());
                return ocsp;
            } catch(const Exception &) {
            }
        }
        // Return first OCSP response when chains are not complete and validation fails
        return {t.oCSPValues()->encapsulatedOCSPValue().front()};
    }
    catch(const Exception &)
    {}
    return {};
}
