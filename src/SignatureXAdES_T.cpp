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
#include "Conf.h"
#include "crypto/Digest.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "util/log.h"
#include "xml/XAdES01903v132-201601.hxx"

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_MSVC(4005)
#include <xsec/dsig/DSIGConstants.hpp>
DIGIDOCPP_WARNING_POP

using namespace digidoc;
using namespace digidoc::xades;
using namespace xml_schema;
using namespace std;

void SignatureXAdES_T::createUnsignedSignatureProperties()
{
    if(qualifyingProperties().unsignedProperties())
        return;
    qualifyingProperties().unsignedProperties(make_unique<UnsignedPropertiesType>());
    qualifyingProperties().unsignedProperties()
        ->unsignedSignatureProperties(make_unique<UnsignedSignaturePropertiesType>());
}

vector<unsigned char> SignatureXAdES_T::messageImprint() const
{
    return tsFromBase64().messageImprint();
}

X509Cert SignatureXAdES_T::TimeStampCertificate() const
{
    return tsFromBase64().cert();
}

string SignatureXAdES_T::TimeStampTime() const
{
    return util::date::ASN1TimeToXSD(tsFromBase64().time());
}

string SignatureXAdES_T::trustedSigningTime() const
{
    string time = TimeStampTime();
    return time.empty() ? SignatureXAdES_B::trustedSigningTime() : time;
}

void SignatureXAdES_T::extendSignatureProfile(const std::string &profile)
{
    if(profile.find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
        return;

    createUnsignedSignatureProperties();

    Digest calc;
    calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue");

    TS tsa(CONF(TSUrl), calc, " Profile: " + profile);
    vector<unsigned char> der = tsa;
    auto &usp = unsignedSignatureProperties();
    auto ts = make_unique<UnsignedSignaturePropertiesType::SignatureTimeStampType>();
    ts->id(id() + Log::format("-T%zu", usp.signatureTimeStamp().size()));
    ts->canonicalizationMethod(signature->signedInfo().canonicalizationMethod());
    ts->encapsulatedTimeStamp().push_back(make_unique<EncapsulatedPKIDataType>(
        Base64Binary(der.data(), der.size(), der.size(), false)));
    usp.signatureTimeStamp().push_back(move(ts));
    usp.contentOrder().emplace_back(UnsignedSignaturePropertiesType::ContentOrderType(
        UnsignedSignaturePropertiesType::signatureTimeStampId,
        unsignedSignatureProperties().signatureTimeStamp().size() - 1));
    sigdata_.clear();
}

TS SignatureXAdES_T::tsFromBase64() const
{
    try {
        if(unsignedSignatureProperties().signatureTimeStamp().empty())
            return {};
        const UnsignedSignaturePropertiesType::SignatureTimeStampType &ts =
                unsignedSignatureProperties().signatureTimeStamp().front();
        if(ts.encapsulatedTimeStamp().empty())
            return {};
        const GenericTimeStampType::EncapsulatedTimeStampType &bin =
                ts.encapsulatedTimeStamp().front();
        return {(const unsigned char*)bin.data(), bin.size()};
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
        const UnsignedSignaturePropertiesType::SignatureTimeStampSequence &tseq =
            unsignedSignatureProperties().signatureTimeStamp();
        if(tseq.empty())
            THROW("Missing SignatureTimeStamp");
        if(tseq.size() > 1)
            THROW("More than one SignatureTimeStamp is not supported");
        const UnsignedSignaturePropertiesType::SignatureTimeStampType &ts = tseq.front();

        const GenericTimeStampType::EncapsulatedTimeStampSequence &etseq =
            ts.encapsulatedTimeStamp();
        if(etseq.empty())
            THROW("Missing EncapsulatedTimeStamp");
        if(etseq.size() > 1)
            THROW("More than one EncapsulatedTimeStamp is not supported");

        string canonicalizationMethod;
        if(ts.canonicalizationMethod())
            canonicalizationMethod = ts.canonicalizationMethod()->algorithm();
        const GenericTimeStampType::EncapsulatedTimeStampType &bin = etseq.front();
        TS tsa((const unsigned char*)bin.data(), bin.size());
        Digest calc(tsa.digestMethod());
        calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue", {}, canonicalizationMethod);
        tsa.verify(calc);

        time_t validateTime = util::date::ASN1TimeToTime_t(tsa.time());
        if(!signingCertificate().isValid(&validateTime))
            THROW("Signing certificate was not valid on signing time");

        if(tsa.digestMethod() == URI_SHA1 &&
            !Exception::hasWarningIgnore(Exception::ReferenceDigestWeak))
        {
            Exception e(EXCEPTION_PARAMS("TimeStamp '%s' digest weak", tsa.digestMethod().c_str()));
            e.setCode(Exception::ReferenceDigestWeak);
            exception.addCause(e);
        }

        const auto &completeCertRefs = unsignedSignatureProperties().completeCertificateRefs();
        if(completeCertRefs.size() > 1)
            THROW("UnsignedSignatureProperties may contain only one CompleteCertificateRefs element");
        if(completeCertRefs.size() == 1)
        {
            const auto &certValues = unsignedSignatureProperties().certificateValues();
            if(certValues.size() != 1)
                THROW("UnsignedSignatureProperties may contain only one CertificateValues element");
            const auto &certValue = certValues.front();
            const auto &certRefs = completeCertRefs.front().certRefs();
            if(certRefs.cert().size() != certValue.encapsulatedX509Certificate().size())
                THROW("CertificateValues::EncapsulatedX509Certificate count does not equal with CompleteCertificateRefs::Cert");
            for(size_t i = 0; i < certRefs.cert().size(); ++i)
            {
                const auto &base64 = certValue.encapsulatedX509Certificate().at(i);
                checkCertID(certRefs.cert().at(i), X509Cert((const unsigned char*)base64.data(), base64.size()));
            }
        }
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}

UnsignedSignaturePropertiesType &SignatureXAdES_T::unsignedSignatureProperties() const
{
    if(!qualifyingProperties().unsignedProperties())
        THROW("QualifyingProperties block 'UnsignedProperties' is missing.");
    if(!qualifyingProperties().unsignedProperties()->unsignedSignatureProperties())
        THROW("UnsignedProperties block 'UnsignedSignatureProperties' is missing.");
    return qualifyingProperties().unsignedProperties()->unsignedSignatureProperties().get();
}
