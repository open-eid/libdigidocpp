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

SignatureXAdES_LT::SignatureXAdES_LT(unsigned int id, ASiContainer *bdoc, Signer *signer)
: SignatureXAdES_T(id, bdoc, signer)
{
}

SignatureXAdES_LT::SignatureXAdES_LT(istream &sigdata, ASiContainer *bdoc, bool relaxSchemaValidation)
: SignatureXAdES_T(sigdata, bdoc, relaxSchemaValidation)
{
    try {
        // ADOC files are default T level, take OCSP response to create temporary LT level
        if(bdoc->mediaType() == ASiContainer::MIMETYPE_ADOC && unsignedSignatureProperties().revocationValues().empty())
        {
            X509Cert cert = signingCertificate();
            X509Cert issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::OCSP);
            if(!issuer)
                THROW("Could not find certificate issuer '%s' in certificate store.",
                    cert.issuerName().c_str());

            OCSP ocsp(cert, issuer, {}, " format: " + bdoc->mediaType());
            addOCSPValue(id().replace(0, 1, "N"), ocsp);
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
    return time.empty() || profile().find(ASiC_E::ASIC_TM_PROFILE) == string::npos ? SignatureXAdES_T::trustedSigningTime() : time;
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
void SignatureXAdES_LT::validate(const std::string &policy) const
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
            OCSP ocsp((const unsigned char*)resp.data(), resp.size());
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
                if(!std::any_of(policies.cbegin(), policies.cend(), [&](const string &policy) { return trusted.find(policy) != trusted.cend(); }))
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
void SignatureXAdES_LT::extendSignatureProfile(const std::string &profile)
{
    SignatureXAdES_T::extendSignatureProfile(profile);
    if(profile == ASiC_E::BES_PROFILE || profile == ASiC_E::EPES_PROFILE)
        return;

    // Calculate NONCE value.
    Digest calc;
    vector<unsigned char> nonce = Digest::addDigestInfo(calc.result(getSignatureValue()), calc.uri());
    DEBUGMEM("OID + Calculated signature HASH (nonce):", nonce.data(), nonce.size());

    // Get issuer certificate from certificate store.
    X509Cert cert = signingCertificate();
    X509Cert issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    if(!issuer)
        issuer = X509CertStore::instance()->issuerFromAIA(cert);
    if(!issuer)
        THROW("Could not find certificate issuer '%s' in certificate store or from AIA.",
            cert.issuerName().c_str());

    string userAgent = " format: " + bdoc->mediaType() + " profile: " +
        (profile.find(ASiC_E::ASIC_TM_PROFILE) != string::npos ? "ASiC_E_BASELINE_LT_TM" : "ASiC_E_BASELINE_LT");
    OCSP ocsp(cert, issuer, nonce, userAgent);
    ocsp.verifyResponse(cert);

    addCertificateValue(id() + "-CA-CERT", issuer);
    addOCSPValue(id().replace(0, 1, "N"), ocsp);
    sigdata_.clear();
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
        values.push_back(CertificateValuesType());
        unsignedSignatureProperties().contentOrder().push_back(
            UnsignedSignaturePropertiesType::ContentOrderType(
                UnsignedSignaturePropertiesType::certificateValuesId, values.size() - 1));
    }

    vector<unsigned char> der = x509;
    CertificateValuesType::EncapsulatedX509CertificateType certData(Base64Binary(der.data(), der.size(), der.size(), false));
    certData.id(certId);
    values[0].encapsulatedX509Certificate().push_back(certData);
}

void SignatureXAdES_LT::addOCSPValue(const string &id, const OCSP &ocsp)
{
    DEBUG("SignatureXAdES_LT::addOCSPValue(%s, %s)", id.c_str(), util::date::to_string(ocsp.producedAt()).c_str());

    createUnsignedSignatureProperties();

    vector<unsigned char> der = ocsp;
    OCSPValuesType::EncapsulatedOCSPValueType ocspValueData(Base64Binary(der.data(), der.size(), der.size(), false));
    ocspValueData.id(id);

    OCSPValuesType ocspValue;
    ocspValue.encapsulatedOCSPValue().push_back(ocspValueData);

    RevocationValuesType revocationValues;
    revocationValues.oCSPValues(ocspValue);

    unsignedSignatureProperties().revocationValues().push_back(revocationValues);
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
                OCSP ocsp((const unsigned char*)resp.data(), resp.size());
                ocsp.verifyResponse(signingCertificate());
                return ocsp;
            } catch(const Exception &) {
            }
        }
        // Return first OCSP response when chains are not complete and validation fails
        const OCSPValuesType::EncapsulatedOCSPValueType &resp = t.oCSPValues()->encapsulatedOCSPValue().at(0);
        return {(const unsigned char*)resp.data(), resp.size()};
    }
    catch(const Exception &)
    {}
    return {};
}
