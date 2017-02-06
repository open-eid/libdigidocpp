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

#include "SignatureTM.h"

#include "BDoc.h"
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

SignatureTM::SignatureTM(unsigned int id, BDoc *bdoc, Signer *signer)
: SignatureBES(id, bdoc, signer)
{
}

SignatureTM::SignatureTM(istream &sigdata, BDoc *bdoc)
: SignatureBES(sigdata, bdoc)
{
}

SignatureTM::~SignatureTM()
{
}

/**
 * @return nonce value
 */
vector<unsigned char> SignatureTM::OCSPNonce() const
{
    vector<unsigned char> respBuf = getOCSPResponseValue();
    return respBuf.empty() ? vector<unsigned char>() : OCSP(respBuf).nonce();
}

/**
 * @return returns OCSP certificate
 */
X509Cert SignatureTM::OCSPCertificate() const
{
    vector<unsigned char> respBuf = getOCSPResponseValue();
    return respBuf.empty() ? X509Cert() : OCSP(respBuf).responderCert();
}

/**
 * @return returns OCSP timestamp
 */
string SignatureTM::OCSPProducedAt() const
{
    vector<unsigned char> respBuf = getOCSPResponseValue();
    if(respBuf.empty())
        return "";
    tm datetime = ASN1TimeToTM(OCSP(respBuf).producedAt());
    return xsd2string(makeDateTime(datetime));
}

string SignatureTM::trustedSigningTime() const
{
    string time = OCSPProducedAt();
    return time.empty() ? claimedSigningTime() : time;
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
void SignatureTM::validate() const
{
    Exception exception(__FILE__, __LINE__, "Signature validation");
    try {
        SignatureBES::validate();
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }

    try {
        const QualifyingPropertiesType::UnsignedPropertiesOptional &uProps = qualifyingProperties().unsignedProperties();
        if(!uProps.present())
            THROW_MAIN(exception, "QualifyingProperties must contain UnsignedProperties");

        if(uProps->unsignedDataObjectProperties().present())
            EXCEPTION_ADD(exception, "unexpected UnsignedDataObjectProperties in Signature");
        if(!uProps->unsignedSignatureProperties().present())
            THROW_MAIN(exception, "UnsignedProperties must contain UnsignedSignatureProperties");
        if(uProps->unsignedSignatureProperties()->revocationValues().empty())
            THROW_MAIN(exception, "RevocationValues object is missing");
        if(uProps->unsignedSignatureProperties()->revocationValues().size() > 1)
            THROW_MAIN(exception, "More than one RevocationValues object is not supported");
        const RevocationValuesType &t = uProps->unsignedSignatureProperties()->revocationValues().front();
        if(!t.oCSPValues().present())
            THROW_MAIN(exception, "OCSPValues is missing");
        if(t.oCSPValues()->encapsulatedOCSPValue().size() != 1)
            THROW_MAIN(exception, "More than one EncapsulatedOCSPValue object is not supported");

        const OCSPValuesType::EncapsulatedOCSPValueType &resp = t.oCSPValues()->encapsulatedOCSPValue().front();
        OCSP ocsp(vector<unsigned char>(resp.data(), resp.data()+resp.size()));
        try {
            ocsp.verifyResponse(signingCertificate());
        } catch(const Exception &e) {
            exception.addCause(e);
        }

        struct tm producedAt = ASN1TimeToTM(ocsp.producedAt());
        time_t producedAt_t = mktime(&producedAt);
        if(!X509CertStore::instance()->verify(ocsp.responderCert(), false, &producedAt_t))
            EXCEPTION_ADD(exception, "Unable to verify responder certificate");

        if(profile().find(BDoc::ASIC_TM_PROFILE) != string::npos)
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
void SignatureTM::extendSignatureProfile(const std::string &profile)
{
    if(profile == BDoc::BES_PROFILE || profile == BDoc::EPES_PROFILE)
        return;

    // Calculate NONCE value.
    Digest calc;
    calc.update(getSignatureValue());
    vector<unsigned char> nonce = Digest::addDigestInfo(calc.result(), calc.uri());
    DEBUGMEM("OID + Calculated signature HASH (nonce):", nonce.data(), nonce.size());

    // Get issuer certificate from certificate store.
    X509Cert cert = signingCertificate();
    X509Cert issuer = X509CertStore::instance()->findIssuer(cert);
    if(!issuer)
        THROW("Could not find certificate issuer '%s' in certificate store.",
            cert.issuerName().c_str());

    DEBUG("Signing with X.509 cert {serial=%s, subject=%s, issuer=%s})",
        cert.serial().c_str(), cert.subjectName().c_str(), cert.issuerName().c_str());

    DEBUG("Making OCSP request.");
    OCSP ocsp(cert, issuer, nonce, "format: " + bdoc->mediaType() + " version: " + policy());
    ocsp.verifyResponse(cert);

    // Set TM profile signature parameters.
    if(!qualifyingProperties().unsignedProperties().present())
    {
        UnsignedPropertiesType usProp;
        usProp.unsignedSignatureProperties(UnsignedSignaturePropertiesType());
        qualifyingProperties().unsignedProperties(usProp);
    }

    addCertificateValue(id() + "-RESPONDER_CERT", ocsp.responderCert());
    addCertificateValue(id() + "-CA-CERT", issuer);

    vector<unsigned char> ocspResponse = ocsp.toDer();
    DEBUG("OCSP response size %d", ocspResponse.size());
    OCSPValuesType::EncapsulatedOCSPValueType ocspValueData(toBase64(ocspResponse));
    ocspValueData.id(id().replace(0, 1, "N"));

    OCSPValuesType ocspValue;
    ocspValue.encapsulatedOCSPValue().push_back(ocspValueData);

    RevocationValuesType revocationValues;
    revocationValues.oCSPValues(ocspValue);

    unsignedSignatureProperties().revocationValues().push_back(revocationValues);
    unsignedSignatureProperties().contentOrder().push_back(
        UnsignedSignaturePropertiesType::ContentOrderType(
            UnsignedSignaturePropertiesType::revocationValuesId,
            unsignedSignatureProperties().revocationValues().size() - 1));
    sigdata_.clear();
}

/**
 * Add certificate under CertificateValues element
 * @param certId id attribute of EncapsulatedX509Certificate
 * @param x509 value of EncapsulatedX509Certificate
 */
void SignatureTM::addCertificateValue(const string& certId, const X509Cert& x509)
{
    DEBUG("SignatureTM::setCertificateValue(%s, X509Cert{%s,%s})",
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

/**
 * Get value of UnsignedProperties\UnsignedSignatureProperties\RevocationValues\OCSPValues\EncapsulatedOCSPValue
 * which contains whole OCSP response
 * @param data will contain DER encoded OCSP response bytes
 */
vector<unsigned char> SignatureTM::getOCSPResponseValue() const
{
    try
    {
        if(unsignedSignatureProperties().revocationValues().empty())
            return vector<unsigned char>();
        const RevocationValuesType &t = unsignedSignatureProperties().revocationValues().front();
        if(!t.oCSPValues().present())
            return vector<unsigned char>();
        const OCSPValuesType &tt = t.oCSPValues().get();
        if(tt.encapsulatedOCSPValue().empty())
            return vector<unsigned char>();
        const OCSPValuesType::EncapsulatedOCSPValueType &resp = tt.encapsulatedOCSPValue().front();
        return vector<unsigned char>(resp.data(), resp.data()+resp.size());
    }
    catch(const Exception &)
    {}
    return vector<unsigned char>();
}

UnsignedSignaturePropertiesType &SignatureTM::unsignedSignatureProperties() const
{
    QualifyingPropertiesType::UnsignedPropertiesOptional &unsignedPropsOptional =
            qualifyingProperties().unsignedProperties();
    if(!unsignedPropsOptional.present())
        THROW("QualifyingProperties block 'UnsignedProperties' is missing.");

    UnsignedPropertiesType::UnsignedSignaturePropertiesOptional &unsignedSigProps =
    unsignedPropsOptional->unsignedSignatureProperties();
    if(!unsignedSigProps.present())
        THROW("QualifyingProperties block 'UnsignedSignatureProperties' is missing.");

    return unsignedSigProps.get();
}
