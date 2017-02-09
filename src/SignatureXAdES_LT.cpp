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
#include "crypto/X509CertStore.h"
#include "crypto/OCSP.h"
#include "util/DateTime.h"
#include "log.h"

#include <xsec/dsig/DSIGConstants.hpp>

#include <ctime>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace digidoc::dsig;
using namespace digidoc::xades;
using namespace std;
using namespace xml_schema;

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return v.empty() ? Base64Binary() : Base64Binary(v.data(), v.size());
}

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

            OCSP ocsp(cert, issuer, vector<unsigned char>(), "format: " + bdoc->mediaType() + " version: " + policy());
            addOCSPValue(id().replace(0, 1, "N"), ocsp);
        }
    } catch(const Exception &) {
    }
}

/**
 * @return nonce value
 */
vector<unsigned char> SignatureXAdES_LT::OCSPNonce() const
{
    vector<unsigned char> respBuf = getOCSPResponseValue();
    return respBuf.empty() ? vector<unsigned char>() : OCSP(respBuf).nonce();
}

/**
 * @return returns OCSP certificate
 */
X509Cert SignatureXAdES_LT::OCSPCertificate() const
{
    vector<unsigned char> respBuf = getOCSPResponseValue();
    return respBuf.empty() ? X509Cert() : OCSP(respBuf).responderCert();
}

/**
 * @return returns OCSP timestamp
 */
string SignatureXAdES_LT::OCSPProducedAt() const
{
    vector<unsigned char> respBuf = getOCSPResponseValue();
    if(respBuf.empty())
        return "";
    return ASN1TimeToXSD(OCSP(respBuf).producedAt());
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
    Exception exception(__FILE__, __LINE__, "Signature validation");
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
            THROW_MAIN(exception, "RevocationValues object is missing");
        if(revSeq.size() > 1)
            THROW_MAIN(exception, "More than one RevocationValues object is not supported");
        if(!revSeq.front().oCSPValues().present())
            THROW_MAIN(exception, "OCSPValues is missing");

        /*
         * Find OCSP response that matches with signingCertificate.
         * If none is found throw all OCSP validation exceptions.
         */
        bool foundSignerOCSP = false;
        vector<Exception> ocspExceptions;
        for(const OCSPValuesType::EncapsulatedOCSPValueType &resp: revSeq.front().oCSPValues()->encapsulatedOCSPValue())
        {
            OCSP ocsp(vector<unsigned char>(resp.data(), resp.data()+resp.size()));
            try {
                ocsp.verifyResponse(signingCertificate());
                foundSignerOCSP = true;
            } catch(const Exception &e) {
                ocspExceptions.push_back(e);
                continue;
            }

            if(profile().find(ASiC_E::ASIC_TM_PROFILE) != string::npos)
            {
                string method = Digest::digestInfoUri(ocsp.nonce());
                if(method.empty())
                    THROW("Nonce digest method is missing");
                Digest calc(method);
                calc.update(getSignatureValue());
                vector<unsigned char> digest = calc.result();
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
                struct tm producedAt = ASN1TimeToTM(ocsp.producedAt());
                time_t producedAt_t = util::date::mkgmtime(producedAt);
                time_t timeT = string2time_t(TimeStampTime());
                if((producedAt_t - timeT > 15 * 60 || timeT - producedAt_t > 15 * 60) &&
                    !Exception::hasWarningIgnore(Exception::ProducedATLateWarning))
                {
                    Exception e(EXCEPTION_PARAMS("TimeStamp time and OCSP producedAt are over 15m TS: %s OCSP: %s", ocsp.producedAt().c_str(), TimeStampTime().c_str()));
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
    calc.update(getSignatureValue());
    vector<unsigned char> nonce = Digest::addDigestInfo(calc.result(), calc.uri());
    DEBUGMEM("OID + Calculated signature HASH (nonce):", nonce.data(), nonce.size());

    // Get issuer certificate from certificate store.
    X509Cert cert = signingCertificate();
    X509Cert issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    if(!issuer)
        THROW("Could not find certificate issuer '%s' in certificate store.",
            cert.issuerName().c_str());

    OCSP ocsp(cert, issuer, nonce, "format: " + bdoc->mediaType() + " profile: " +
        (profile.find(ASiC_E::ASIC_TM_PROFILE) == string::npos ? "ASiC_E_BASELINE_LT" : "ASiC_E_BASELINE_LT_TM"));
    ocsp.verifyResponse(cert);

    addOCSPValue(id().replace(0, 1, "N"), ocsp);
    addCertificateValue(id() + "-RESPONDER_CERT", ocsp.responderCert());
    addCertificateValue(id() + "-CA-CERT", issuer);
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

    UnsignedSignaturePropertiesType::CertificateValuesSequence &values =
            unsignedSignatureProperties().certificateValues();
    if(values.empty())
    {
        values.push_back(CertificateValuesType());
        unsignedSignatureProperties().contentOrder().push_back(
            UnsignedSignaturePropertiesType::ContentOrderType(
                UnsignedSignaturePropertiesType::certificateValuesId, values.size() - 1));
    }

    CertificateValuesType::EncapsulatedX509CertificateType certData(toBase64(x509));
    certData.id(certId);
    values[0].encapsulatedX509Certificate().push_back(certData);
}

void SignatureXAdES_LT::addOCSPValue(const string &id, const OCSP &ocsp)
{
    DEBUG("SignatureXAdES_LT::addOCSPValue(%s, %s)", id.c_str(), ocsp.producedAt().c_str());

    OCSPValuesType::EncapsulatedOCSPValueType ocspValueData(toBase64(ocsp.toDer()));
    ocspValueData.id(id);

    OCSPValuesType ocspValue;
    ocspValue.encapsulatedOCSPValue().push_back(ocspValueData);

    RevocationValuesType revocationValues;
    revocationValues.oCSPValues(ocspValue);

    if(!qualifyingProperties().unsignedProperties().present())
    {
        UnsignedPropertiesType usProp;
        usProp.unsignedSignatureProperties(UnsignedSignaturePropertiesType());
        qualifyingProperties().unsignedProperties(usProp);
    }

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
vector<unsigned char> SignatureXAdES_LT::getOCSPResponseValue() const
{
    try
    {
        if(unsignedSignatureProperties().revocationValues().empty())
            return vector<unsigned char>();
        const RevocationValuesType &t = unsignedSignatureProperties().revocationValues().front();
        if(!t.oCSPValues().present())
            return vector<unsigned char>();
        // Return OCSP response that matches with signingCertificate
        for(const OCSPValuesType::EncapsulatedOCSPValueType &resp: t.oCSPValues()->encapsulatedOCSPValue())
        {
            try {
                vector<unsigned char> data(resp.data(), resp.data()+resp.size());
                OCSP(data).verifyResponse(signingCertificate());
                return data;
            } catch(const Exception &) {
            }
        }
    }
    catch(const Exception &)
    {}
    return vector<unsigned char>();
}

