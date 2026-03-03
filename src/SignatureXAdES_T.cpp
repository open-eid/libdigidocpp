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

#include "SignatureXAdES_T.h"

#include "ASiC_E.h"
#include "crypto/Digest.h"
#include "crypto/OCSP.h"
#include "crypto/Signer.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "crypto/X509CertStore.h"
#include "util/DateTime.h"
#include "util/log.h"

using namespace digidoc;
using namespace std;

vector<unsigned char> SignatureXAdES_T::messageImprint() const
{
    return TimeStamp().messageImprint();
}

X509Cert SignatureXAdES_T::TimeStampCertificate() const
{
    return TimeStamp().cert();
}

string SignatureXAdES_T::TimeStampTime() const
{
    return util::date::to_string(TimeStamp().time());
}

string SignatureXAdES_T::trustedSigningTime() const
{
    string time = TimeStampTime();
    return time.empty() ? SignatureXAdES_B::trustedSigningTime() : std::move(time);
}

void SignatureXAdES_T::extendSignatureProfile(Signer *signer)
{
    if(signer->profile().find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
        return;

    auto up = qualifyingProperties()/"UnsignedProperties";
    if(!up)
        up = qualifyingProperties() + "UnsignedProperties";

    auto usp = up/"UnsignedSignatureProperties";
    if(!usp)
        usp = up + "UnsignedSignatureProperties";

    size_t i = 0;
    for(auto ts = usp/"SignatureTimeStamp"; ts; ts++, ++i);

    Digest calc;
    auto method = canonicalizationMethod();
    signatures->c14n(calc, method, signatureValue());

    TS tsa(calc, signer->userAgent());
    auto ts = usp + "SignatureTimeStamp";
    ts.setProperty("Id", id() + Log::format("-T%zu", i));
    (ts + CanonicalizationMethod).setProperty("Algorithm", method);
    ts + "EncapsulatedTimeStamp" = tsa;
}

TS SignatureXAdES_T::TimeStamp() const
{
    try {
        return {unsignedSignatureProperties()/"SignatureTimeStamp"/"EncapsulatedTimeStamp"};
    } catch(const Exception &) {}
    return {};
}

void SignatureXAdES_T::validate(const std::string &policy) const
{
    Exception exception(EXCEPTION_PARAMS("Signature validation"));
    try {
        SignatureXAdES_B::validate(policy);
        if(profile().find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
            return;
    } catch(const Exception &e) {
        if(profile().find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
            throw;
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }

    try {
        auto usp = unsignedSignatureProperties();
        auto ts = usp/"SignatureTimeStamp";
        if(!ts)
            THROW("Missing SignatureTimeStamp");
        if(ts + 1)
            THROW("More than one SignatureTimeStamp is not supported");

        TS tsa = verifyTS(ts, exception, [this](const Digest &digest, string_view canonicalizationMethod) {
            signatures->c14n(digest, canonicalizationMethod, signatureValue());
        });

        if(!checkSigningCertificate(policy == POLv1, tsa.time()))
            THROW("Signing certificate was not valid on signing time");

        auto completeCertRefs = usp/"CompleteCertificateRefs";
        if(completeCertRefs + 1)
            THROW("UnsignedSignatureProperties may contain only one CompleteCertificateRefs element");
        if(completeCertRefs)
        {
            auto certValue = usp/"CertificateValues";
            if(!certValue || certValue + 1)
                THROW("UnsignedSignatureProperties may contain only one CertificateValues element");
            auto cert = completeCertRefs/"CertRefs"/"Cert";
            auto base64 = certValue/"EncapsulatedX509Certificate";
            for(; cert && base64; cert++, base64++)
                checkCertID(cert, X509Cert(base64));
            if(bool(cert) != bool(base64))
                THROW("CertificateValues::EncapsulatedX509Certificate count does not equal with CompleteCertificateRefs::Cert");
        }

        auto completeRevRefs = usp/"CompleteRevocationRefs";
        if(completeRevRefs + 1)
            THROW("UnsignedSignatureProperties may contain only one CompleteRevocationRefs element");
        if(completeRevRefs)
        {
            if(completeRevRefs/"CRLRefs")
                THROW("CompleteRevocationRefs may contain only one OCSPRefs element");
            auto ocspRefs = completeRevRefs/"OCSPRefs";
            if(!ocspRefs)
                THROW("CompleteRevocationRefs is missing OCSPRefs element");
            auto revValues = usp/"RevocationValues";
            if(!revValues || revValues + 1)
                THROW("UnsignedSignatureProperties may contain only one RevocationValues element");
            auto ocspValues = revValues/"OCSPValues";
            if(!ocspValues)
                THROW("RevocationValues is missing OCSPValues element");
            auto ocspRef = ocspRefs/"OCSPRef";
            auto base64 = ocspValues/"EncapsulatedOCSPValue";
            for(; ocspRef && base64; ocspRef++, base64++)
            {
                OCSP ocsp(base64);
                checkDigest(ocspRef/"DigestAlgAndValue", ocsp);
            }
            if(bool(ocspRef) != bool(base64))
                THROW("CertificateValues::EncapsulatedX509Certificate count does not equal with CompleteCertificateRefs::Cert");
        }

        for(auto sigAndRefsTS = usp/"SigAndRefsTimeStamp"; sigAndRefsTS; sigAndRefsTS++)
        {
            verifyTS(sigAndRefsTS, exception, [this, usp](const Digest &digest, string_view canonicalizationMethod) {
                signatures->c14n(digest, canonicalizationMethod, signatureValue());
                for(const auto *name: {
                       "SignatureTimeStamp",
                       "CompleteCertificateRefs",
                       "CompleteRevocationRefs",
                       "AttributeCertificateRefs",
                       "AttributeRevocationRefs" })
                {
                    if(auto elem = usp/name)
                        signatures->c14n(digest, canonicalizationMethod, elem);
                }
            });
        }
    } catch(const Exception &e) {
        exception.addCause(e);
    } catch(...) {
        EXCEPTION_ADD(exception, "Failed to validate signature");
    }
    if(!exception.causes().empty())
        throw exception;
}

XMLNode SignatureXAdES_T::unsignedSignatureProperties() const
{
    auto up = qualifyingProperties()/"UnsignedProperties";
    if(!up)
        THROW("QualifyingProperties block 'UnsignedProperties' is missing.");
    if(auto usp = up/"UnsignedSignatureProperties")
        return usp;
    THROW("UnsignedProperties block 'UnsignedSignatureProperties' is missing.");
}

TS SignatureXAdES_T::verifyTS(XMLNode timestamp, digidoc::Exception &exception,
    std::function<void (const Digest &, std::string_view)> &&calcDigest)
{
    auto ets = timestamp/EncapsulatedTimeStamp;
    if(!ets)
        THROW("Missing EncapsulatedTimeStamp");
    if(ets + 1)
        THROW("More than one EncapsulatedTimeStamp is not supported");

    TS ts(ets);
    Digest calc(ts.digestMethod());
    calcDigest(calc, (timestamp/CanonicalizationMethod)["Algorithm"]);
    ts.verify(calc.result());

    if(!Exception::hasWarningIgnore(Exception::ReferenceDigestWeak) &&
        Digest::isWeakDigest(ts.digestMethod()))
    {
        Exception e(EXCEPTION_PARAMS("TimeStamp '%s' digest weak", ts.digestMethod().c_str()));
        e.setCode(Exception::ReferenceDigestWeak);
        exception.addCause(e);
    }
    return ts;
}
