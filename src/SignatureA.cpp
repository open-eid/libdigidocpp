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

#include "BDoc.h"
#include "Conf.h"
#include "DataFile.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/File.h"
#include "xml/XAdESv141.hxx"

#include <xsec/dsig/DSIGConstants.hpp>

using namespace digidoc;
using namespace digidoc::dsig;
using namespace digidoc::util;
using namespace digidoc::xades;
using namespace xml_schema;
using namespace std;

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return v.empty() ? Base64Binary() : Base64Binary(&v[0], v.size());
}



SignatureA::SignatureA(unsigned int id, BDoc *bdoc): SignatureTS(id, bdoc) {}

SignatureA::SignatureA(std::istream &sigdata, BDoc *bdoc): SignatureTS(sigdata, bdoc) {}

SignatureA::~SignatureA() {}

void SignatureA::notarizeTSA()
{
    Digest calc;
    string signedPropertiesId;
    if(qualifyingProperties().signedProperties()->id().present())
        signedPropertiesId = "#" + qualifyingProperties().signedProperties()->id().get();
    for(const ReferenceType &ref: signature->signedInfo().reference())
    {
        if(ref.uRI().present() && ref.uRI().get() != signedPropertiesId)
        {
            for(const DataFile &file: bdoc->dataFiles())
                if(file.fileName() == File::fromUriPath(ref.uRI().get()))
                    file.calcDigest(&calc);
        }
        else
            calcDigestOnNode(&calc, XADES_NAMESPACE, "SignedProperties");
    };
    calcDigestOnNode(&calc, URI_ID_DSIG, "SignedInfo");
    calcDigestOnNode(&calc, URI_ID_DSIG, "SignatureValue");
    calcDigestOnNode(&calc, URI_ID_DSIG, "KeyInfo");

    if(!unsignedSignatureProperties().signatureTimeStamp().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "SignatureTimeStamp");
    if(!unsignedSignatureProperties().counterSignature().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "CounterSignature");
    if(!unsignedSignatureProperties().completeCertificateRefs().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "CompleteCertificateRefs");
    if(!unsignedSignatureProperties().completeRevocationRefs().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "CompleteRevocationRefs");
    if(!unsignedSignatureProperties().attributeCertificateRefs().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "AttributeCertificateRefs");
    if(!unsignedSignatureProperties().attributeRevocationRefs().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "AttributeRevocationRefs");
    if(!unsignedSignatureProperties().certificateValues().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "CertificateValues");
    if(!unsignedSignatureProperties().revocationValues().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "RevocationValues");
    if(!unsignedSignatureProperties().sigAndRefsTimeStamp().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "SigAndRefsTimeStamp");
    if(!unsignedSignatureProperties().refsOnlyTimeStamp().empty())
        calcDigestOnNode(&calc, XADES_NAMESPACE, "RefsOnlyTimeStamp");
    if(!unsignedSignatureProperties().archiveTimeStampV141().empty())
        calcDigestOnNode(&calc, XADESv141_NAMESPACE, "ArchiveTimeStamp");
    if(!unsignedSignatureProperties().timeStampValidationData().empty())
        calcDigestOnNode(&calc, XADESv141_NAMESPACE, "TimeStampValidationData");
    //ds:Object

    TS tsa(ConfV2::instance() ? ConfV2::instance()->TSUrl() : ConfV2().TSUrl(), calc);
    xadesv141::ArchiveTimeStampType ts;
    ts.id(id() + "-A0");
    ts.encapsulatedTimeStamp().push_back(EncapsulatedPKIDataType(toBase64(tsa)));
    unsignedSignatureProperties().archiveTimeStampV141().push_back(ts);
}
