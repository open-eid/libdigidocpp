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
#include "xml/XAdES.hxx"

#include <xsec/dsig/DSIGConstants.hpp>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace digidoc::xades;
using namespace xml_schema;
using namespace std;

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return v.empty() ? Base64Binary() : Base64Binary(&v[0], v.size());
}


SignatureTS::SignatureTS(unsigned int id, BDoc *bdoc): SignatureTM(id, bdoc) {}

SignatureTS::SignatureTS(std::istream &sigdata, BDoc *bdoc): SignatureTM(sigdata, bdoc) {}

SignatureTS::~SignatureTS() {}

X509Cert SignatureTS::TSCertificate() const
{
    return TS(tsBase64()).cert();
}

string SignatureTS::TSTime() const
{
    string time = TS(tsBase64()).time();
    if(time.empty())
        return time;
    tm datetime = ASN1TimeToTM(time);
    return xsd2string(makeDateTime(datetime));
}

void SignatureTS::notarizeTS()
{
    if(!qualifyingProperties().unsignedProperties().present())
    {
        UnsignedPropertiesType usProp;
        usProp.unsignedSignatureProperties(UnsignedSignaturePropertiesType());
        qualifyingProperties().unsignedProperties(usProp);
    }

    Digest calc;
    calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue");

    TS tsa(ConfV2::instance() ? ConfV2::instance()->TSUrl() : ConfV2().TSUrl(), calc);
    UnsignedSignaturePropertiesType::SignatureTimeStampType ts;
    ts.id(id() + Log::format("-T%u", unsignedSignatureProperties().signatureTimeStamp().size()));
    ts.encapsulatedTimeStamp().push_back(EncapsulatedPKIDataType(toBase64(tsa)));
    unsignedSignatureProperties().signatureTimeStamp().push_back(ts);
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

void SignatureTS::validate(Validate params) const
{
    Exception exception(__FILE__, __LINE__, "Signature validation");
    try {
        SignatureTM::validate(params);
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
        if(unsignedSignatureProperties().signatureTimeStamp().empty())
            THROW("Missing SignatureTimeStamp");
        const UnsignedSignaturePropertiesType::SignatureTimeStampType &ts =
                unsignedSignatureProperties().signatureTimeStamp().front();

        if(ts.encapsulatedTimeStamp().empty())
            THROW("Missing EncapsulatedTimeStamp");
        GenericTimeStampType::EncapsulatedTimeStampType bin =
                ts.encapsulatedTimeStamp().front();

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
        else if(timeT - producedAtT > 24 * 60 * 60) // 24h
            EXCEPTION_ADD(exception, "TimeStamp time and OCSP producedAt are over 24h");
        else if(timeT - producedAtT > 15 * 60 && !Exception::hasWarningIgnore(Exception::ProducedATLateWarning)) // 15m
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
