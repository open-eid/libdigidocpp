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

#include "SignatureA.h"

#include "ASiC_E.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "util/File.h"
#include "xml/XAdES01903v141-201601.hxx"

#include <xsec/dsig/DSIGConstants.hpp>

using namespace digidoc;
using namespace digidoc::dsig;
using namespace digidoc::util;
using namespace digidoc::util::date;
using namespace digidoc::xades;
using namespace xml_schema;
using namespace std;

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return v.empty() ? Base64Binary() : Base64Binary(v.data(), v.size());
}

SignatureA::SignatureA(unsigned int id, ASiContainer *bdoc, Signer *signer): SignatureTS(id, bdoc, signer) {}

SignatureA::SignatureA(std::istream &sigdata, ASiContainer *bdoc, bool relaxSchemaValidation): SignatureTS(sigdata, bdoc, relaxSchemaValidation) {}

SignatureA::~SignatureA() {}

void SignatureA::calcArchiveDigest(Digest *digest) const
{
    string signedPropertiesId;
    if(qualifyingProperties().signedProperties()->id().present())
        signedPropertiesId = "#" + qualifyingProperties().signedProperties()->id().get();
    for(const ReferenceType &ref: signature->signedInfo().reference())
    {
        if(ref.uRI().present() && ref.uRI().get() != signedPropertiesId)
        {
            for(const DataFile *file: bdoc->dataFiles())
                if(file->fileName() == File::fromUriPath(ref.uRI().get()))
                    static_cast<const DataFilePrivate*>(file)->calcDigest(digest);
        }
        else
            calcDigestOnNode(digest, XADES_NAMESPACE, "SignedProperties");
    };

    vector<string> list = {"SignedInfo", "SignatureValue", "KeyInfo"};
    for(const string &name: list)
    {
        try {
            calcDigestOnNode(digest, URI_ID_DSIG, name);
        } catch(const Exception &) {
            DEBUG("Element %s not found", name.c_str());
        }
    }

    list = {
        "SignatureTimeStamp",
        "CounterSignature",
        "CompleteCertificateRefs",
        "CompleteRevocationRefs",
        "AttributeCertificateRefs",
        "AttributeRevocationRefs",
        "CertificateValues",
        "RevocationValues",
        "SigAndRefsTimeStamp",
        "RefsOnlyTimeStamp" };
    for(const string &name: list)
    {
        try {
            calcDigestOnNode(digest, XADES_NAMESPACE, name);
        } catch(const Exception &) {
            DEBUG("Element %s not found", name.c_str());
        }
    }

    try {
        calcDigestOnNode(digest, XADESv141_NAMESPACE, "TimeStampValidationData");
    } catch(const Exception &) {
        DEBUG("Element TimeStampValidationData not found");
    }
    //ds:Object
}

void SignatureA::extendSignatureProfile(const std::string &profile)
{
    SignatureTS::extendSignatureProfile(profile);
    if(profile != ASiC_E::ASIC_TSA_PROFILE && profile != ASiC_E::ASIC_TMA_PROFILE)
        return;

    Digest calc;
    calcArchiveDigest(&calc);
    TS tsa(CONF(TSUrl), calc, " Profile: " + profile);
    xadesv141::ArchiveTimeStampType ts;
    ts.id(id() + "-A0");
    ts.encapsulatedTimeStamp().push_back(EncapsulatedPKIDataType(toBase64(tsa)));
    unsignedSignatureProperties().archiveTimeStampV141().push_back(ts);
    unsignedSignatureProperties().contentOrder().push_back(
        UnsignedSignaturePropertiesType::ContentOrderType(
            UnsignedSignaturePropertiesType::archiveTimeStampV141Id,
            unsignedSignatureProperties().archiveTimeStampV141().size() - 1));
    sigdata_.clear();
}

vector<unsigned char> SignatureA::tsaBase64() const
{
    try {
        if(unsignedSignatureProperties().archiveTimeStampV141().empty())
            return vector<unsigned char>();
        const xadesv141::ArchiveTimeStampType &ts = unsignedSignatureProperties().archiveTimeStampV141().front();
        if(ts.encapsulatedTimeStamp().empty())
            return vector<unsigned char>();
        const GenericTimeStampType::EncapsulatedTimeStampType &bin =
                ts.encapsulatedTimeStamp().front();
        return vector<unsigned char>(bin.data(), bin.data() + bin.size());
    } catch(const Exception &) {}
    return vector<unsigned char>();
}

X509Cert SignatureA::ArchiveTimeStampCertificate() const
{
    return TS(tsaBase64()).cert();
}

string SignatureA::ArchiveTimeStampTime() const
{
    return ASN1TimeToXSD(TS(tsaBase64()).time());
}

void SignatureA::validate() const
{
    Exception exception(__FILE__, __LINE__, "Signature validation");
    try {
        SignatureTS::validate();
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }

    if(profile().find(ASiC_E::ASIC_TSA_PROFILE) == string::npos)
    {
        if(!exception.causes().empty())
            throw exception;
        return;
    }

    try {
        if(unsignedSignatureProperties().archiveTimeStampV141().empty())
            THROW("Missing ArchiveTimeStamp element");

        const xadesv141::ArchiveTimeStampType &ts = unsignedSignatureProperties().archiveTimeStampV141().front();
        if(ts.encapsulatedTimeStamp().empty())
            THROW("Missing EncapsulatedTimeStamp");

        const GenericTimeStampType::EncapsulatedTimeStampType &bin = ts.encapsulatedTimeStamp().front();
        TS tsa(vector<unsigned char>(bin.data(), bin.data() + bin.size()));
        Digest calc(tsa.digestMethod());
        calcArchiveDigest(&calc);
        tsa.verify(calc);
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}
