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
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
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
    if(qualifyingProperties().unsignedProperties().present())
        return;
    UnsignedPropertiesType usProp;
    usProp.unsignedSignatureProperties(UnsignedSignaturePropertiesType());
    qualifyingProperties().unsignedProperties(usProp);
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
    UnsignedSignaturePropertiesType::SignatureTimeStampType ts;
    ts.id(id() + Log::format("-T%lu", (unsigned long)unsignedSignatureProperties().signatureTimeStamp().size()));
    ts.canonicalizationMethod(signature->signedInfo().canonicalizationMethod());
    ts.encapsulatedTimeStamp().push_back(EncapsulatedPKIDataType(Base64Binary(der.data(), der.size())));
    unsignedSignatureProperties().signatureTimeStamp().push_back(ts);
    unsignedSignatureProperties().contentOrder().push_back(
        UnsignedSignaturePropertiesType::ContentOrderType(
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
        return TS((const unsigned char*)bin.data(), bin.size());
    } catch(const Exception &) {}
    return {};
}

void SignatureXAdES_T::validate(const std::string &policy) const
{
    Exception exception(EXCEPTION_PARAMS("Signature validation"));
    try {
        SignatureXAdES_B::validate(policy);
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }
    if(profile().find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
    {
        if(!exception.causes().empty())
            throw exception;
        return;
    }

    try {
        const QualifyingPropertiesType::UnsignedPropertiesOptional &uProps = qualifyingProperties().unsignedProperties();
        if(!uProps.present())
            THROW_MAIN(exception, "QualifyingProperties must contain UnsignedProperties");
        if(uProps->unsignedDataObjectProperties().present())
            EXCEPTION_ADD(exception, "unexpected UnsignedDataObjectProperties in Signature");
        if(!uProps->unsignedSignatureProperties().present())
            THROW_MAIN(exception, "UnsignedProperties must contain UnsignedSignatureProperties");

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
        const GenericTimeStampType::EncapsulatedTimeStampType &bin = etseq.front();
        string canonicalizationMethod;
        if(ts.canonicalizationMethod().present())
            canonicalizationMethod = ts.canonicalizationMethod()->algorithm();

        TS tsa((const unsigned char*)bin.data(), bin.size());
        Digest calc(tsa.digestMethod());
        calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue", {}, canonicalizationMethod);
        tsa.verify(calc);

        time_t validateTime = util::date::ASN1TimeToTime_t(tsa.time());
        if(!signingCertificate().isValid(&validateTime))
            THROW("Signing certificate was not valid on signing time");
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}

UnsignedSignaturePropertiesType &SignatureXAdES_T::unsignedSignatureProperties() const
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
