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

#include "SignatureTS.h"

#include "BDoc.h"
#include "Conf.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/OCSP.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "xml/XAdES01903v132-201601.hxx"

#include <xsec/dsig/DSIGConstants.hpp>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace digidoc::xades;
using namespace xml_schema;
using namespace std;

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return v.empty() ? Base64Binary() : Base64Binary(v.data(), v.size());
}


SignatureTS::SignatureTS(unsigned int id, BDoc *bdoc, Signer *signer): SignatureTM(id, bdoc, signer) {}

SignatureTS::SignatureTS(std::istream &sigdata, BDoc *bdoc): SignatureTM(sigdata, bdoc) {}

SignatureTS::~SignatureTS() {}

X509Cert SignatureTS::TimeStampCertificate() const
{
    return TS(tsBase64()).cert();
}

string SignatureTS::TimeStampTime() const
{
    string time = TS(tsBase64()).time();
    if(time.empty())
        return time;
    tm datetime = ASN1TimeToTM(time);
    return xsd2string(makeDateTime(datetime));
}

string SignatureTS::trustedSigningTime() const
{
    string time = TimeStampTime();
    return time.empty() ? SignatureTM::trustedSigningTime() : time;
}

void SignatureTS::extendSignatureProfile(const std::string &profile)
{
    if(profile.find(BDoc::ASIC_TS_PROFILE) != string::npos)
    {
        if(!qualifyingProperties().unsignedProperties().present())
        {
            UnsignedPropertiesType usProp;
            usProp.unsignedSignatureProperties(UnsignedSignaturePropertiesType());
            qualifyingProperties().unsignedProperties(usProp);
        }

        Digest calc;
        calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue");

        TS tsa(CONF(TSUrl), calc, " Profile: " + profile);
        UnsignedSignaturePropertiesType::SignatureTimeStampType ts;
        ts.id(id() + Log::format("-T%u", unsignedSignatureProperties().signatureTimeStamp().size()));
        ts.encapsulatedTimeStamp().push_back(EncapsulatedPKIDataType(toBase64(tsa)));
        unsignedSignatureProperties().signatureTimeStamp().push_back(ts);
        unsignedSignatureProperties().contentOrder().push_back(
            UnsignedSignaturePropertiesType::ContentOrderType(
                UnsignedSignaturePropertiesType::signatureTimeStampId,
                unsignedSignatureProperties().signatureTimeStamp().size() - 1));
        sigdata_.clear();
    }
    SignatureTM::extendSignatureProfile(profile);
}

vector<unsigned char> SignatureTS::tsBase64() const
{
    try {
        if(unsignedSignatureProperties().signatureTimeStamp().empty())
            return vector<unsigned char>();
        const UnsignedSignaturePropertiesType::SignatureTimeStampType &ts =
                unsignedSignatureProperties().signatureTimeStamp().front();
        if(ts.encapsulatedTimeStamp().empty())
            return vector<unsigned char>();
        GenericTimeStampType::EncapsulatedTimeStampType bin =
                ts.encapsulatedTimeStamp().front();
        return vector<unsigned char>(bin.data(), bin.data() + bin.size());
    } catch(const Exception &) {}
    return vector<unsigned char>();
}

void SignatureTS::validate() const
{
    Exception exception(__FILE__, __LINE__, "Signature validation");
    try {
        SignatureTM::validate();
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }
    if(profile().find(BDoc::ASIC_TS_PROFILE) == string::npos)
    {
        if(!exception.causes().empty())
            throw exception;
        return;
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
        GenericTimeStampType::EncapsulatedTimeStampType bin = etseq.front();

        TS tsa(vector<unsigned char>(bin.data(), bin.data() + bin.size()));
        Digest calc(tsa.digestMethod());
        calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue");
        tsa.verify(calc);

        tm producedAt = ASN1TimeToTM(OCSP(getOCSPResponseValue()).producedAt());
        time_t producedAtT = mktime(&producedAt);
        tm time = ASN1TimeToTM(tsa.time());
        time_t timeT = mktime(&time);
        if(producedAtT < timeT)
            EXCEPTION_ADD(exception, "TimeStamp is after OCSP response");
        else if(producedAtT - timeT > 24 * 60 * 60) // 24h
            EXCEPTION_ADD(exception, "TimeStamp time and OCSP producedAt are over 24h");
        else if(producedAtT - timeT > 15 * 60 && !Exception::hasWarningIgnore(Exception::ProducedATLateWarning)) // 15m
        {
            Exception e(EXCEPTION_PARAMS("TimeStamp time and OCSP producedAt are over 15m"));
            e.setCode(Exception::ProducedATLateWarning);
            exception.addCause(e);
        }
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}
