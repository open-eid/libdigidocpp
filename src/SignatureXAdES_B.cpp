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

#include "SignatureXAdES_B.h"

#include "ASiC_E.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/Signer.h"
#include "crypto/X509CertStore.h"
#include "crypto/X509Crypto.h"
#include "util/DateTime.h"
#include "util/log.h"
#include "util/File.h"
#include "xml/en_31916201v010101.hxx"
#include "xml/OpenDocument_dsig.hxx"
#include "xml/SecureDOMParser.h"
#include "xml/URIResolver.h"

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_CLANG("-Wnull-conversion")
DIGIDOCPP_WARNING_DISABLE_GCC("-Wunused-parameter")
DIGIDOCPP_WARNING_DISABLE_MSVC(4005)
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/framework/XSECProvider.hpp>
DIGIDOCPP_WARNING_POP

#include <regex>

using namespace digidoc;
using namespace digidoc::asic;
using namespace digidoc::dsig;
using namespace digidoc::util;
using namespace digidoc::xades;
using namespace std;
using namespace xercesc;
using namespace xml_schema;
namespace xml = xsd::cxx::xml;

const string Signatures::XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";
const string Signatures::XADESv141_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#";
const string Signatures::ASIC_NAMESPACE = "http://uri.etsi.org/02918/v1.2.1#";
const string Signatures::OPENDOCUMENT_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
const map<string,SignatureXAdES_B::Policy> SignatureXAdES_B::policylist = {
    {"urn:oid:1.3.6.1.4.1.10015.1000.3.2.1",{ // https://www.sk.ee/repository/bdoc-spec21.pdf
        // SHA-1
        {   0x80,0x81,0xe2,0x69,0xeb,0x44,0x13,0xde,0x20,0x6e,0x40,0x91,0xca,0x04,0x3d,0x5a,
            0xca,0x71,0x51,0xdc},
        // SHA-224
        {   0xc8,0xeb,0x95,0x3f,0xc8,0xe5,0x93,0x74,0xaa,0x81,0x5a,0x1e,0x24,0x3f,0xcb,0x42,
            0x30,0xd2,0x0a,0xf0,0xc4,0x0d,0xc4,0xb4,0x80,0xa5,0xb0,0xdf},
        // SHA-256
        {   0xdd,0x39,0x75,0xa0,0x82,0xd2,0xbc,0xe0,0x16,0xa2,0x67,0x48,0xf5,0x57,0x96,0x57,
            0xa2,0x00,0xff,0x7d,0x9e,0x49,0x74,0x54,0xae,0x2f,0x64,0x3c,0x4c,0xf5,0x21,0x5b},
        // SHA-384
        {   0x81,0xfa,0xa3,0x7b,0x82,0xf1,0x8d,0xc2,0x8c,0x71,0x2e,0xc1,0xb9,0x7b,0xf9,0x79,
            0xaf,0x08,0x99,0x77,0xb7,0x55,0x42,0x62,0xfc,0x07,0x0d,0x6b,0xb3,0x06,0x0b,0x44,
            0x40,0xa8,0x1c,0x9d,0xbc,0x67,0x4c,0xb5,0x0c,0x97,0x33,0xc6,0x33,0x17,0x1a,0x4e},
        // SHA-512
        {   0x8e,0x1d,0x3f,0xa0,0xe7,0x66,0x0c,0xa7,0x1c,0xcf,0xb0,0x80,0x13,0x39,0x1e,0xbf,
            0x29,0x73,0xcf,0x25,0xff,0x6d,0xd1,0xe1,0xc8,0xc4,0x5b,0x84,0xdd,0xb1,0xca,0x3e,
            0xa6,0x7b,0x18,0x86,0x04,0xd8,0x20,0x9b,0xf8,0x54,0x4e,0xb0,0x5f,0xb3,0x67,0x58,
            0x39,0xb9,0xef,0xfe,0xf7,0x75,0x7d,0x34,0x5e,0x39,0xa8,0xa5,0xbf,0x4a,0xa1,0xd7}
    }},
    {"urn:oid:1.3.6.1.4.1.10015.1000.3.2.3",{ // http://id.ee/public/bdoc-spec212-eng.pdf
        // SHA-1
        {   0x0b,0x2d,0x60,0x6b,0x17,0x9b,0x3b,0x92,0x9c,0x3f,0x79,0xf5,0x92,0x5c,0x84,0xc8,
            0xeb,0xef,0x31,0xc6},
        // SHA-224
        {   0x9a,0x5d,0x04,0xc1,0xd2,0x4b,0x44,0x4f,0x12,0xa7,0x19,0x0e,0xaa,0x3a,0xa3,0x22,
            0xe0,0x41,0xfd,0x78,0x58,0x53,0x85,0x5e,0x9c,0xf0,0x32,0x72},
        // SHA-256
        {   0x7a,0x9f,0x0d,0x83,0x43,0x57,0xa3,0xe8,0x46,0xe7,0xca,0x16,0xa3,0x0d,0x57,0x54,
            0xf7,0x2c,0xd7,0xdd,0x6d,0x96,0x98,0x6f,0xa9,0x81,0x54,0xd7,0x7b,0x64,0x6f,0xa6},
        // SHA-384
        {   0x74,0x25,0x12,0xa7,0xbd,0x3f,0xff,0x88,0xa3,0x6b,0xe0,0x95,0x31,0xdc,0xf6,0xbe,
            0x7c,0xc2,0x68,0xef,0x8c,0xdc,0xc7,0xa7,0xc2,0xbc,0x5e,0x95,0x96,0x09,0xb0,0x90,
            0xc8,0x5d,0xf7,0x41,0x96,0x32,0x4a,0xb2,0x98,0xf2,0xe4,0x09,0x37,0x72,0xce,0x75},
        // SHA-512
        {   0xf0,0x1c,0x13,0xc4,0x49,0x9f,0x6c,0x06,0x3e,0xe5,0x02,0x33,0x01,0x7b,0x49,0xb7,
            0x34,0xd4,0xa2,0x2c,0x52,0xab,0x7f,0x7b,0xd2,0x62,0x4f,0x5d,0x4c,0x70,0xe0,0x8f,
            0xe8,0x77,0xfe,0x67,0x1a,0x5d,0x3c,0xb0,0x0b,0x36,0x1f,0x8b,0x2e,0xee,0x75,0x9b,
            0xee,0x53,0x7a,0xbd,0xea,0x6e,0x08,0x18,0x9a,0xc0,0x5b,0x61,0x78,0x59,0x6c,0x32}
    }}
};

namespace digidoc
{

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return {const_cast<unsigned char*>(v.data()), v.size(), v.size(), false};
}

}

Signatures::Signatures()
    : asicsignature(make_unique<XAdESSignaturesType>())
{}


Signatures::Signatures(istream &data, ASiContainer *container)
{
    Properties properties;
    const auto xsdPath = Conf::instance()->xsdPath();
    properties.schema_location(XADES_NAMESPACE, File::fullPathUrl(xsdPath + "/XAdES01903v132-201601-relaxed.xsd"));
    properties.schema_location(XADESv141_NAMESPACE, File::fullPathUrl(xsdPath + "/XAdES01903v141-201601.xsd"));
    properties.schema_location(URI_ID_DSIG, File::fullPathUrl(xsdPath + "/xmldsig-core-schema.xsd"));
    properties.schema_location(ASIC_NAMESPACE, File::fullPathUrl(xsdPath + "/en_31916201v010101.xsd"));
    properties.schema_location(OPENDOCUMENT_NAMESPACE, File::fullPathUrl(xsdPath + "/OpenDocument_dsig.xsd"));
    copy << data.rdbuf();

    parseDOM(copy, properties.schema_location());

    try
    {
        /* http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf
         * 6.2.2
         * 3) The root element of each "*signatures*.xml" content shall be either:
         * a) <asic:XAdESSignatures> as specified in clause A.5, the recommended format; or
         * b) <document-signatures> as specified in OASIS Open Document Format [9]; or
         *
         * Case container is ADoc 1.0 then handle document-signatures root element
         */
        if(container->mediaType() == ASiC_E::MIMETYPE_ADOC)
        {
            odfsignature = document_signatures(*doc, Flags::dont_initialize, properties);
            if(odfsignature->signature().empty())
                THROW("Failed to parse signature XML");
        }
        else
        {
            asicsignature = xAdESSignatures(*doc, Flags::dont_initialize, properties);
            if(asicsignature->signature().empty())
                THROW("Failed to parse signature XML");
        }
        // For calcDigestOnNode
        data.clear();
        data.seekg(0);
        parseDOM(data);
    }
    catch(const Parsing& e)
    {
        stringstream s;
        s << e;
        THROW("Failed to parse signature XML: %s", s.str().c_str());
    }
    catch(const xsd::cxx::exception& e)
    {
        THROW("Failed to parse signature XML: %s", e.what());
    }
}

Signatures::~Signatures() = default;

size_t Signatures::count() const
{
    if(odfsignature)
        return odfsignature->signature().size();
    return asicsignature->signature().size();
}

xercesc::DOMElement* Signatures::element(string_view id) const
{
    DOMNodeList *nodeList = doc->getElementsByTagNameNS(xml::string(URI_ID_DSIG).c_str(), u"Signature");
    for(XMLSize_t i = 0, count = nodeList->getLength(); i < count; ++i)
    {
        auto *elem = static_cast<DOMElement*>(nodeList->item(i));
        if(id == xml::transcode<char>(elem->getAttribute(u"Id")))
            return elem;
    }
    return {};
}

void Signatures::parseDOM(istream &data, const std::string &schema_location)
{
    doc = SecureDOMParser(schema_location).parseIStream(data);
}

void Signatures::reloadDOM()
{
    // Parse Xerces DOM from file, to preserve the white spaces "as is"
    // and get the same digest value on XML node.
    // Canonical XML 1.0 specification (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
    // needs all the white spaces from XML file "as is", otherwise the digests won't match.
    // Therefore we have to use Xerces to parse the XML file each time a digest needs to be
    // calculated on a XML node. If you are parsing XML files with a parser that doesn't
    // preserve the white spaces you are DOOMED!
    // Parse and return a copy of the Xerces DOM tree.
    // Save to file an parse it again, to make XML Canonicalization work
    // correctly as expected by the Canonical XML 1.0 specification.
    // Hope, the next Canonical XMl specification fixes the white spaces preserving "bug".
    copy.str({});
    copy.clear();
    saveXML(copy);
    parseDOM(copy);
}

void Signatures::save(ostream &os) const
{
    if(copy.str().empty())
        return saveXML(os);
    os << copy.str();
}

void Signatures::saveXML(ostream &os) const
{
    try
    {
        static const NamespaceInfomap map{{
            {"ds", {URI_ID_DSIG, {}}},
            {"xades", {XADES_NAMESPACE, {}}},
            {"asic", {ASIC_NAMESPACE, {}}},
        }};
        xAdESSignatures(os, *asicsignature, map, "UTF-8", Flags::dont_initialize);
    }
    catch(const xml::invalid_utf8_string &)
    {
        THROW("Failed to create signature XML file. Parameters must be in UTF-8.");
    }
    if(os.fail())
        THROW("Failed to create signature XML file.");
}

/**
 * Creates an empty BDOC-BES signature with mandatory XML nodes.
 */
SignatureXAdES_B::SignatureXAdES_B(unsigned int id, ASiContainer *container, Signer *signer)
    : signatures(make_shared<Signatures>())
    , bdoc(container)
{
    X509Cert c = signer->cert();
    string nr = "S" + to_string(id);

    // Signature->SignedInfo
    auto signedInfo = make_unique<SignedInfoType>(
        make_unique<CanonicalizationMethodType>(URI_ID_C14N11_NOC),
        make_unique<SignatureMethodType>(X509Crypto(c).isRSAKey() ?
            Digest::toRsaUri(signer->method()) : Digest::toEcUri(signer->method())));

    // Signature->SignatureValue
    auto signatureValue = make_unique<SignatureValueType>();
    signatureValue->id(nr + "-SIG");

    // Signature (root)
    signatures->asicsignature->signature().push_back(make_unique<SignatureType>(std::move(signedInfo), std::move(signatureValue)));
    signature = &signatures->asicsignature->signature().back();
    signature->id(nr);

    // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties
    auto signedProperties = make_unique<SignedPropertiesType>();
    signedProperties->signedSignatureProperties(make_unique<SignedSignaturePropertiesType>());
    signedProperties->id(nr + "-SignedProperties");

    // Signature->Object->QualifyingProperties
    auto qualifyingProperties = make_unique<QualifyingPropertiesType>("#" + nr);
    qualifyingProperties->signedProperties(std::move(signedProperties));

    // Signature->Object
    auto object = make_unique<ObjectType>();
    object->qualifyingProperties().push_back(std::move(qualifyingProperties));

    signature->object().push_back(std::move(object));

    //Fill XML-DSIG/XAdES properties
    setKeyInfo(c);
    if(signer->usingENProfile())
    {
        setSigningCertificateV2(c);
        setSignatureProductionPlace<SignatureProductionPlaceV2Type>(signer->city(), signer->streetAddress(),
            signer->stateOrProvince(), signer->postalCode(), signer->countryName());
        setSignerRoles<SignerRoleV2Type>(signer->signerRoles());
    }
    else
    {
        setSigningCertificate(c);
        setSignatureProductionPlace<SignatureProductionPlaceType>(signer->city(), signer->streetAddress(),
            signer->stateOrProvince(), signer->postalCode(), signer->countryName());
        setSignerRoles<SignerRoleType>(signer->signerRoles());
    }
    setSigningTime(time(nullptr));

    string digestMethod = Conf::instance()->digestUri();
    for(const DataFile *f: bdoc->dataFiles())
    {
        string referenceId = addReference(File::toUriPath(f->fileName()), digestMethod, f->calcDigest(digestMethod));
        addDataObjectFormat("#" + referenceId, f->mediaType());
    }

    signatures->reloadDOM();
    Digest calc(digestMethod);
    calcDigestOnNode(&calc, Signatures::XADES_NAMESPACE, u"SignedProperties",
        signature->signedInfo().canonicalizationMethod().algorithm());
    addReference("#" + nr +"-SignedProperties", calc.uri(), calc.result(), "http://uri.etsi.org/01903#SignedProperties",
        signature->signedInfo().canonicalizationMethod().algorithm());
    signatures->reloadDOM();
}

/**
 * Load signature from the input stream.
 *
 * @param sigdata Input stream
 * @param bdoc BDOC container
 * @param relaxSchemaValidation Flag indicating if relaxed schema should be used for validation -
 *                              elements of SignatureProductionPlaceType can be in any order in signatures
 *                              produced by other systems; default = false
 * @throws SignatureException
 */
SignatureXAdES_B::SignatureXAdES_B(const std::shared_ptr<Signatures> &signatures, size_t i, ASiContainer *container)
    : signatures(signatures)
    , bdoc(container)
{
    if(signatures->odfsignature)
        signature = &signatures->odfsignature->signature().at(i);
    else
        signature = &signatures->asicsignature->signature().at(i);

    if(const auto &sp = qualifyingProperties().signedProperties())
    {
        if(const auto &sdop = sp->signedDataObjectProperties())
        {
            if(!sdop->commitmentTypeIndication().empty())
                DEBUG("CommitmentTypeIndicationType is not supported");
            if(!sdop->allDataObjectsTimeStamp().empty())
                THROW("AllDataObjectsTimeStamp is not supported");
            if(!sdop->individualDataObjectsTimeStamp().empty())
                THROW("IndividualDataObjectsTimeStampType is not supported");
        }
    }
    if(const auto &up = qualifyingProperties().unsignedProperties())
    {
        if(up->unsignedDataObjectProperties())
            THROW("UnsignedDataObjectProperties are not supported");
        if(const auto &usp = up->unsignedSignatureProperties())
        {
            if(!usp->counterSignature().empty())
                THROW("CounterSignature is not supported");
            if(!usp->completeCertificateRefs().empty())
                WARN("CompleteCertificateRefs are not supported");
            if(!usp->completeRevocationRefs().empty())
                WARN("CompleteRevocationRefs are not supported");
            if(!usp->attributeCertificateRefs().empty())
                THROW("AttributeCertificateRefs are not supported");
            if(!usp->attributeRevocationRefs().empty())
                THROW("AttributeRevocationRefs are not supported");
            if(!usp->sigAndRefsTimeStamp().empty())
                WARN("SigAndRefsTimeStamp is not supported");
            if(!usp->refsOnlyTimeStamp().empty())
                THROW("RefsOnlyTimeStamp is not supported");
            if(!usp->attrAuthoritiesCertValues().empty())
                THROW("AttrAuthoritiesCertValues are not supported");
            if(!usp->attributeRevocationValues().empty())
                THROW("AttributeRevocationValues are not supported");
            if(!usp->archiveTimeStamp().empty())
                THROW("ArchiveTimeStamp is not supported");
            if(!usp->timeStampValidationData().empty())
                WARN("TimeStampValidationData is not supported");
        }
    }

    // Base class has verified the signature to be valid according to XML-DSig.
    // Now perform additional checks here and throw if this signature is
    // ill-formed according to BDoc.

    getSignedSignatureProperties(); // assumed to throw in case this block doesn't exist
    signingCertificate(); // assumed to throw in case this block doesn't exist

    if(id().empty())
        THROW("Signature element mandatory attribute 'Id' is missing");
}

SignatureXAdES_B::~SignatureXAdES_B()
{
    auto &seq = signatures->odfsignature ? signatures->odfsignature->signature() : signatures->asicsignature->signature();
    if(auto i = std::find_if(seq.begin(), seq.end(), [this](const dsig::SignatureType &sig) {
            return sig.id().get() == signature->id().get();
        }); i != seq.end())
        seq.erase(i);
}

string SignatureXAdES_B::policy() const
{
    const SignedSignaturePropertiesType::SignaturePolicyIdentifierOptional &identifier =
            getSignedSignatureProperties().signaturePolicyIdentifier();
    if(!identifier)
        return {};

    const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
    if(!id)
        return {};

    const ObjectIdentifierType::IdentifierType &objid = id->sigPolicyId().identifier();
    if(!objid.qualifier() || objid.qualifier().get() != QualifierType::OIDAsURN)
        return {};

    return objid;
}

/**
 * @return returns signature mimetype.
 */
string SignatureXAdES_B::profile() const
{
    string base = policy().empty() ? "BES" : "EPES";
    try {
        auto up = qualifyingProperties().unsignedProperties();
        if(!up)
            return base;
        auto usp = up->unsignedSignatureProperties();
        if(!usp)
            return base;

        if(!usp->signatureTimeStamp().empty())
        {
            if(!usp->archiveTimeStampV141().empty())
                return (base + '/').append(ASiC_E::ASIC_TSA_PROFILE);
            return (base + '/').append(ASiC_E::ASIC_TS_PROFILE);
        }
        if(!usp->revocationValues().empty())
        {
            if(!usp->archiveTimeStampV141().empty())
                return (base + '/').append(ASiC_E::ASIC_TMA_PROFILE);
            return (base + '/').append(ASiC_E::ASIC_TM_PROFILE);
        }
    }
    catch(const Exception &) {}
    return base;
}

string SignatureXAdES_B::trustedSigningTime() const
{
    return claimedSigningTime();
}

string SignatureXAdES_B::SPUri() const
{
    const SignedSignaturePropertiesType::SignaturePolicyIdentifierOptional &identifier =
            getSignedSignatureProperties().signaturePolicyIdentifier();
    if(!identifier)
        return {};

    const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
    if(!id)
        return {};

    const SignaturePolicyIdType::SigPolicyQualifiersOptional &qual = id->sigPolicyQualifiers();
    if(!qual)
        return {};

    for(const SigPolicyQualifiersListType::SigPolicyQualifierType &i: qual->sigPolicyQualifier())
        if(i.sPURI())
            return i.sPURI().get();

    return {};
}

void SignatureXAdES_B::validate() const
{
    validate(POLv2);
}

/**
 * Check if signature is valid according to BDoc-BES format. Performs
 * any off-line checks that prove mathematical correctness.
 * However, there is no warranty against if the signature has expired. On-line
 * validation should be performed to check for signature expiration.
 *
 * @throws Exception containing details on what's wrong in this signature.
*/
void SignatureXAdES_B::validate(const string &policy) const
{
    DEBUG("SignatureXAdES_B::validate(%s)", policy.c_str());
    // A "master" exception containing all problems (causes) with this signature.
    // It'll be only thrown in case we have a reason (cause).
    Exception exception(EXCEPTION_PARAMS("Signature validation"));

    if(!Exception::hasWarningIgnore(Exception::SignatureDigestWeak) &&
       (signatureMethod() == URI_RSA_SHA1 || signatureMethod() == URI_ECDSA_SHA1))
    {
        Exception e(EXCEPTION_PARAMS("Signature digest weak"));
        e.setCode(Exception::SignatureDigestWeak);
        exception.addCause(e);
    }

    if(profile().find(ASiC_E::ASIC_TM_PROFILE) != string::npos)
    {
        if(SPUri().empty())
            EXCEPTION_ADD(exception, "Signature SPUri is missing");

        if(auto p = policylist.find(SignatureXAdES_B::policy()); p != policylist.cend())
        {
            if(const auto &identifier = getSignedSignatureProperties().signaturePolicyIdentifier())
            {
                if(const auto &id = identifier->signaturePolicyId())
                {
#if 0 //Disabled IB-3684
                    const DigestAlgAndValueType &hash = id->sigPolicyHash();
                    vector<unsigned char> digest(hash.digestValue().begin(), hash.digestValue().end());

                    bool valid = false;
                    if(hash.digestMethod().algorithm() == URI_SHA1) valid = digest == p->second.SHA1;
                    else if(hash.digestMethod().algorithm() == URI_SHA224) valid = digest == p->second.SHA224;
                    else if(hash.digestMethod().algorithm() == URI_SHA256) valid = digest == p->second.SHA256;
                    else if(hash.digestMethod().algorithm() == URI_SHA384) valid = digest == p->second.SHA384;
                    else if(hash.digestMethod().algorithm() == URI_SHA512) valid = digest == p->second.SHA512;
                    else
                        EXCEPTION_ADD(exception, "Signature policy unknwon digest method");

                    if(!valid)
                        EXCEPTION_ADD(exception, "Signature policy digest does not match");
#endif
                }
                else
                    EXCEPTION_ADD(exception, "Signature policy digest is missing");
            }
            else
                EXCEPTION_ADD(exception, "Signature policy digest is missing");
        }
        else
            EXCEPTION_ADD(exception, "Signature policy does not match BDOC 2.1 policy");
    }

    try {
        XSECProvider prov;
        auto deleteSig = [&](DSIGSignature *s) { prov.releaseSignature(s); };
        DOMNode *node = signatures->element(id());
        unique_ptr<DSIGSignature, decltype(deleteSig)> sig(prov.newSignatureFromDOM(node->getOwnerDocument(), node), deleteSig);
        unique_ptr<URIResolver> uriresolver = make_unique<URIResolver>(bdoc);
        unique_ptr<XSECKeyInfoResolverDefault> keyresolver = make_unique<XSECKeyInfoResolverDefault>();
        sig->setURIResolver(uriresolver.get());
        sig->setKeyInfoResolver(keyresolver.get());
        sig->registerIdAttributeName((const XMLCh*)u"Id");
        sig->setIdByAttributeName(true);
        sig->load();

        safeBuffer m_errStr;
        m_errStr.sbXMLChIn((const XMLCh*)u"");

        if(!DSIGReference::verifyReferenceList(sig->getReferenceList(), m_errStr))
        //if(!sig->verify()) //xml-security-c does not support URI_RSA_PSS_SHA
        {
            //string s = xml::transcode<char>(sig->getErrMsgs())
            string s = xml::transcode<char>(m_errStr.rawXMLChBuffer());
            EXCEPTION_ADD(exception, "Failed to validate signature: %s", s.c_str());
        }
    }
    catch(const Parsing &e)
    {
        stringstream s;
        s << e;
        EXCEPTION_ADD(exception, "Failed to validate signature: %s", s.str().c_str());
    }
    catch(const XSECException &e)
    {
        string s = xml::transcode<char>(e.getMsg());
        EXCEPTION_ADD(exception, "Failed to validate signature: %s", s.c_str());
    }
    catch(const XMLException &e)
    {
        string s = xml::transcode<char>(e.getMessage());
        EXCEPTION_ADD(exception, "Failed to validate signature: %s", s.c_str());
    }
    catch(...)
    {
        EXCEPTION_ADD(exception, "Failed to validate signature");
    }

    const SignedPropertiesType &sp = qualifyingProperties().signedProperties().get();
    map<string,string> mimeinfo;
    if(sp.signedDataObjectProperties())
    {
        for(const DataObjectFormatType &data: sp.signedDataObjectProperties()->dataObjectFormat())
        {
            if(data.mimeType())
                mimeinfo.insert({data.objectReference(), data.mimeType().get()});
        }
    }
    else
    {
        // ADoc 1.0 does not add DataObjectProperties>DataObjectFormat elements
        if(bdoc->mediaType() != ASiC_E::MIMETYPE_ADOC)
            EXCEPTION_ADD(exception, "DataObjectFormat element is missing");
    }

    map<string,string> signatureref;
    string signedPropertiesId = sp.id() ? "#" + sp.id().get() : string();
    bool signedInfoFound = false;
    for(const ReferenceType &ref: signature->signedInfo().reference())
    {
        if(!ref.uRI() || ref.uRI()->empty())
        {
            EXCEPTION_ADD(exception, "Reference URI missing");
            continue;
        }

        if((ref.digestMethod().algorithm() == URI_SHA1 ||
           ref.digestMethod().algorithm() == URI_SHA224) &&
           !Exception::hasWarningIgnore(Exception::ReferenceDigestWeak))
        {
            Exception e(EXCEPTION_PARAMS("Reference '%s' digest weak", ref.uRI().get().c_str()));
            e.setCode(Exception::ReferenceDigestWeak);
            exception.addCause(e);
        }

        if(ref.uRI().get() == signedPropertiesId)
            signedInfoFound = true;
        else if(!sp.signedDataObjectProperties())
            continue; // DataObjectProperties is missing, no need to match later MediaTypes
        else if(!ref.id())
            EXCEPTION_ADD(exception, "Reference '%s' ID  missing", ref.uRI().get().c_str());
        else
        {
            string uri = File::fromUriPath(ref.uRI().get());
            if(uri.front() == '/')
                uri.erase(0);
            signatureref.insert({ uri, mimeinfo["#"+ref.id().get()] });
        }
    }
    if(!signedInfoFound)
        EXCEPTION_ADD(exception, "SignedProperties not found");

    // Match DataObjectFormat element MediaTypes with Manifest
    if(!signatureref.empty())
    {
        for(const DataFile *file: bdoc->dataFiles())
        {
            if(auto i = signatureref.find(file->fileName()); i != signatureref.end())
            {
                if(bdoc->mediaType() != ASiContainer::MIMETYPE_ASIC_S && i->second != file->mediaType())
                    EXCEPTION_ADD(exception, "Manifest datafile '%s' mime '%s' does not match signature mime '%s'",
                        file->fileName().c_str(), file->mediaType().c_str(), i->second.c_str());
                static const regex reg(R"(([\w])*/([\w\-\+\.])*)");
                if(!file->mediaType().empty() && !regex_match(file->mediaType(), reg))
                {
                    Exception w(EXCEPTION_PARAMS("'%s' is not conformant mime-type string!", file->mediaType().c_str()));
                    w.setCode(Exception::MimeTypeWarning);
                    exception.addCause(w);
                }
                signatureref.erase(i);
            }
            else
                EXCEPTION_ADD(exception, "Manifest datafile not listed in signature references %s", file->fileName().c_str());
        }
    }

    if(bdoc->dataFiles().empty())
        EXCEPTION_ADD(exception, "No DataFiles signed");

    if(!signatureref.empty())
        EXCEPTION_ADD(exception, "Manifest references and signature references do not match");

    try { checkKeyInfo(); }
    catch(const Exception& e) { exception.addCause(e); }

    try { checkSignatureValue(); }
    catch(const Exception& e) { exception.addCause(e); }

    try { checkSigningCertificate(policy == POLv1); }
    catch(const Exception& e) { exception.addCause(e); }

    if(!exception.causes().empty())
        throw exception;
}

vector<unsigned char> SignatureXAdES_B::dataToSign() const
{
    // Calculate SHA digest of the Signature->SignedInfo node.
    Digest calc(signatureMethod());
    calcDigestOnNode(&calc, URI_ID_DSIG, u"SignedInfo",
        signature->signedInfo().canonicalizationMethod().algorithm());
    return calc.result();
}

void SignatureXAdES_B::checkCertID(const CertIDType &certID, const X509Cert &cert)
{
    const X509IssuerSerialType::X509IssuerNameType &certIssuerName = certID.issuerSerial().x509IssuerName();
    const X509IssuerSerialType::X509SerialNumberType &certSerialNumber = certID.issuerSerial().x509SerialNumber();
    if(X509Crypto(cert).compareIssuerToString(certIssuerName) == 0 && cert.serial() == certSerialNumber)
        return checkDigest(certID.certDigest(), cert);
    DEBUG("certIssuerName: \"%s\"", certIssuerName.c_str());
    DEBUG("x509.getCertIssuerName() \"%s\"", cert.issuerName().c_str());
    DEBUG("sertCerials = %s %s", cert.serial().c_str(), certSerialNumber.c_str());
    THROW("Signing certificate issuer information does not match");
}

void SignatureXAdES_B::checkDigest(const DigestAlgAndValueType &digest, const vector<unsigned char> &data)
{
    vector<unsigned char> calcDigest = Digest(digest.digestMethod().algorithm()).result(data);
    if(digest.digestValue().size() == calcDigest.size() &&
        memcmp(calcDigest.data(), digest.digestValue().data(), digest.digestValue().size()) == 0)
        return;
    DEBUGMEM("Document cert digest", digest.digestValue().data(), digest.digestValue().size());
    DEBUGMEM("Calculated cert digest", calcDigest.data(), calcDigest.size());
    THROW("Signing certificate digest does not match");
}

/**
 * Verify if SigningCertificate matches with
 * XAdES::SigningCertificate/SigningCertificateV2 Digest and IssuerSerial info
 */
void SignatureXAdES_B::checkKeyInfo() const
{
    X509Cert x509 = signingCertificate();
    if(const auto &sigCertOpt = getSignedSignatureProperties().signingCertificate())
    {
        const CertIDListType::CertSequence &certs = sigCertOpt->cert();
        if(certs.size() != 1)
            THROW("Number of SigningCertificates is %zu, must be 1", certs.size());
        return checkCertID(certs.front(), x509);
    }
    if(const auto &sigCertV2Opt = getSignedSignatureProperties().signingCertificateV2())
    {
        const CertIDListV2Type::CertSequence &certs = sigCertV2Opt->cert();
        if(certs.size() != 1)
            THROW("Number of SigningCertificatesV2 is %zu, must be 1", certs.size());

        // Verify IssuerSerialV2, optional parameter
        const auto &cert = certs.front();
        if(cert.issuerSerialV2())
        {
            if(!X509Crypto(x509).compareIssuerToDer(
                    {cert.issuerSerialV2()->begin(), cert.issuerSerialV2()->end()}))
                THROW("Signing certificate issuer information does not match");
        }

        return checkDigest(cert.certDigest(), x509);
    }
    THROW("SigningCertificate/SigningCertificateV2 not found");
}

/**
 * Check if signing certificate was issued by trusted party.
 * @throws Exception on a problem with signing certificate
 */
void SignatureXAdES_B::checkSigningCertificate(bool noqscd) const
{
    try
    {
        X509Cert signingCert = signingCertificate();
        vector<X509Cert::KeyUsage> usage = signingCert.keyUsage();
        if(find(usage.cbegin(), usage.cend(), X509Cert::NonRepudiation) == usage.cend())
            THROW("Signing certificate does not contain NonRepudiation key usage flag");
        if(!X509CertStore::instance()->verify(signingCert, noqscd))
            THROW("Unable to verify signing certificate");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE( e, "Unable to verify signing certificate" );
    }
}

/**
 * Validate signature value.
 *
 * @throws throws exception if signature value did not match.
 */
void SignatureXAdES_B::checkSignatureValue() const
{
    try
    {
        vector<unsigned char> sha = dataToSign();
        DEBUGMEM("Digest to sign", sha.data(), sha.size());
        if(!X509Crypto(signingCertificate()).verify(signatureMethod(), sha, getSignatureValue()))
            THROW_OPENSSLEXCEPTION("Signature is not valid.");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to validate signatureValue.");
    }
}

void SignatureXAdES_B::addDataObjectFormat(const string &uri, const string &mime)
{
    QualifyingPropertiesType::SignedPropertiesOptional& spOpt = qualifyingProperties().signedProperties();
    if(!spOpt)
        THROW("QualifyingProperties block 'SignedProperties' is missing.");

    if(!spOpt->signedDataObjectProperties())
        spOpt->signedDataObjectProperties(make_unique<SignedDataObjectPropertiesType>());

    auto dataObject = make_unique<DataObjectFormatType>(uri);
    dataObject->mimeType(mime);
    spOpt->signedDataObjectProperties()->dataObjectFormat().push_back(std::move(dataObject));
}

/**
 * Adds artifact digest value as reference in the signature.
 *
 * @param uri reference URI.
 * @param digestUri digest method URI (e.g. 'http://www.w3.org/2000/09/xmldsig#sha1' for SHA1)
 * @param digestValue digest value.
 * @param type reference type, optional parameter, default no type is added to the reference.
 *        For example 'http://uri.etsi.org/01903/#SignedProperties' for signed properties
 *        reference.
 * @returns referenece id
 * @throws SignatureException throws exception if the digest method is not supported.
 */
string SignatureXAdES_B::addReference(const string& uri, const string& digestUri,
        const vector<unsigned char> &digestValue, const string &type, const string &canon)
{
    auto reference = make_unique<ReferenceType>(make_unique<DigestMethodType>(digestUri), toBase64(digestValue));
    reference->uRI(make_unique<Uri>(uri));
    if(!type.empty())
        reference->type(type);

    if(!canon.empty())
    {
        reference->transforms(make_unique<TransformsType>());
        reference->transforms()->transform().push_back(make_unique<TransformType>(canon));
    }

    SignedInfoType::ReferenceSequence &seq = signature->signedInfo().reference();
    reference->id(make_unique<Id>(id() + Log::format("-RefId%zu", seq.size())));
    seq.push_back(std::move(reference));

    return seq.back().id().get();
}

/**
 * Adds signing certificate to the signature XML. The DER encoded X.509 certificate is added to
 * Signature->KeyInfo->X509Data->X509Certificate.
 *
 * @param cert certificate that is used for signing the signature XML.
 */
void SignatureXAdES_B::setKeyInfo(const X509Cert& x509)
{
    // BASE64 encoding of a DER-encoded X.509 certificate = PEM encoded.
    auto x509Data = make_unique<X509DataType>();
    x509Data->x509Certificate().push_back(toBase64(x509));

    auto keyInfo = make_unique<KeyInfoType>();
    keyInfo->x509Data().push_back(std::move(x509Data));
    signature->keyInfo(std::move(keyInfo));
}

/**
 * Adds signing certificate to the signature XML. Certificate info is added to
 * Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.
 *
 * @param cert certificate that is used for signing the signature XML.
 */
void SignatureXAdES_B::setSigningCertificate(const X509Cert& x509)
{
    // Calculate digest of the X.509 certificate.
    Digest digest;
    auto signingCertificate = make_unique<CertIDListType>();
    signingCertificate->cert().push_back(make_unique<CertIDType>(
        DigestAlgAndValueType(make_unique<DigestMethodType>(digest.uri()), toBase64(digest.result(x509))),
        X509IssuerSerialType(x509.issuerName(), x509.serial())));
    getSignedSignatureProperties().signingCertificate(std::move(signingCertificate));
}

/**
 * Adds signing certificate to the signature XML. Certificate info is added to
 * Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificateV2.
 *
 * @param cert certificate that is used for signing the signature XML.
 */
void SignatureXAdES_B::setSigningCertificateV2(const X509Cert& x509)
{
    // Calculate digest of the X.509 certificate.
    Digest digest;
    auto signingCertificate = make_unique<CertIDListV2Type>();
    signingCertificate->cert().push_back(make_unique<CertIDTypeV2>(
        make_unique<DigestAlgAndValueType>(make_unique<DigestMethodType>(digest.uri()), toBase64(digest.result(x509)))));
    getSignedSignatureProperties().signingCertificateV2(std::move(signingCertificate));
}

/**
 * Sets signature production place.
 *
 * @param spp signature production place.
 */
template<class T>
void SignatureXAdES_B::setSignatureProductionPlace(const string &city, const string &streetAddress,
    const string &stateOrProvince, const string &postalCode, const string &countryName)
{
    if(city.empty() && streetAddress.empty() && stateOrProvince.empty() &&
        postalCode.empty() && countryName.empty())
        return;

    auto signatureProductionPlace = make_unique<T>();
    if(!city.empty())
        signatureProductionPlace->city(city);
    if(!stateOrProvince.empty())
        signatureProductionPlace->stateOrProvince(stateOrProvince);
    if(!postalCode.empty())
        signatureProductionPlace->postalCode(postalCode);
    if(!countryName.empty())
        signatureProductionPlace->countryName(countryName);

    if constexpr (is_same_v<T, SignatureProductionPlaceV2Type>)
    {
        if(!streetAddress.empty())
            signatureProductionPlace->streetAddress(streetAddress);
        getSignedSignatureProperties().signatureProductionPlaceV2(std::move(signatureProductionPlace));
    }
    else
        getSignedSignatureProperties().signatureProductionPlace(std::move(signatureProductionPlace));
}

/**
 * Sets signer claimed roles to the signature.
 * NB! Only ClaimedRoles are supported. CerifiedRoles are not supported.
 *
 * @param roles signer roles.
 */
template<class T>
void SignatureXAdES_B::setSignerRoles(const vector<string> &roles)
{
    if(roles.empty())
        return;

    auto claimedRoles = make_unique<ClaimedRolesListType>();
    claimedRoles->claimedRole().reserve(roles.size());
    for(const string &role: roles)
        claimedRoles->claimedRole().push_back(role);

    auto signerRole = make_unique<T>();
    signerRole->claimedRoles(std::move(claimedRoles));

    if constexpr (is_same_v<T, SignerRoleV2Type>)
        getSignedSignatureProperties().signerRoleV2(std::move(signerRole));
    else
        getSignedSignatureProperties().signerRole(std::move(signerRole));
}

/**
 * Sets signature signing time.
 *
 * @param signingTime signing time.
 */
void SignatureXAdES_B::setSigningTime(time_t signingTime)
{
    getSignedSignatureProperties().signingTime(date::makeDateTime(signingTime));
}

/**
 * Sets signature value.
 *
 * @param signatureValue signature value.
 */
void SignatureXAdES_B::setSignatureValue(const vector<unsigned char> &signatureValue)
{
    SignatureValueType buffer = toBase64(signatureValue);
    signature->signatureValue().swap(buffer);
    signatures->reloadDOM();
}

/**
 * @return returns signature value.
 */
vector<unsigned char> SignatureXAdES_B::getSignatureValue() const
{
    const SignatureType::SignatureValueType &signatureValueType = signature->signatureValue();
    return {signatureValueType.begin(), signatureValueType.end()};
}

/**
 * Canonicalize XML node using one of the supported methods in XML-DSIG
 * Using Xerces for parsing XML to preserve the white spaces "as is" and get
 * the same digest value on XML node each time.
 *
 * @param calc digest calculator implementation.
 * @param ns signature tag namespace.
 * @param tagName signature tag name.
 */
void SignatureXAdES_B::calcDigestOnNode(Digest* calc, string_view ns,
    u16string_view tagName, string_view canonicalizationMethod) const
{
    try
    {
        auto *element = signatures->element(id());
        DOMNodeList *nodeList = element->getElementsByTagNameNS(xml::string(ns.data()).c_str(), tagName.data());
        if(nodeList->getLength() != 1)
            THROW("Could not find '%s' node which is in '%.*s' namespace in signature XML.",
                  xml::transcode<char>(tagName.data()).c_str(), int(ns.size()), ns.data());
        SecureDOMParser::calcDigestOnNode(calc, canonicalizationMethod, nodeList->item(0));
    }
    catch(const Exception& e)
    {
        THROW_CAUSE(e, "Failed to create Xerces DOM from signature XML.");
    }
    catch(const XMLException& e)
    {
        try {
            string msg = xml::transcode<char>(e.getMessage());
            THROW("Failed to parse signature XML: %s", msg.c_str());
        } catch(const xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to parse signature XML.");
        }
    }
    catch(const DOMException& e)
    {
        try {
            string msg = xml::transcode<char>(e.getMessage());
            THROW("Failed to parse signature XML: %s", msg.c_str());
        } catch(const xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to parse signature XML.");
        }
    }
    catch(const xml::invalid_utf16_string & /* ex */) {
        THROW("Failed to parse signature XML.");
    }
    catch(...)
    {
        THROW("Failed to parse signature XML.");
    }
}

string SignatureXAdES_B::city() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    if(const auto &sigProdPlace = getSignedSignatureProperties().signatureProductionPlace();
        sigProdPlace && sigProdPlace->city())
        return sigProdPlace->city().get();
    if(const auto &sigProdPlaceV2 = getSignedSignatureProperties().signatureProductionPlaceV2();
        sigProdPlaceV2 && sigProdPlaceV2->city())
        return sigProdPlaceV2->city().get();
    return {};
}

string SignatureXAdES_B::stateOrProvince() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    if(const auto &sigProdPlace = getSignedSignatureProperties().signatureProductionPlace();
        sigProdPlace && sigProdPlace->stateOrProvince())
        return sigProdPlace->stateOrProvince().get();
    if(const auto &sigProdPlaceV2 = getSignedSignatureProperties().signatureProductionPlaceV2();
        sigProdPlaceV2 && sigProdPlaceV2->stateOrProvince())
        return sigProdPlaceV2->stateOrProvince().get();
    return {};
}

string SignatureXAdES_B::streetAddress() const
{
    if(const auto &sigProdPlaceV2 = getSignedSignatureProperties().signatureProductionPlaceV2();
        sigProdPlaceV2 && sigProdPlaceV2->streetAddress())
        return sigProdPlaceV2->streetAddress().get();
    return {};
}

string SignatureXAdES_B::postalCode() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    if(const auto &sigProdPlace = getSignedSignatureProperties().signatureProductionPlace();
        sigProdPlace && sigProdPlace->postalCode())
        return sigProdPlace->postalCode().get();
    if(const auto &sigProdPlaceV2 = getSignedSignatureProperties().signatureProductionPlaceV2();
        sigProdPlaceV2 && sigProdPlaceV2->postalCode())
        return sigProdPlaceV2->postalCode().get();
    return {};
}

string SignatureXAdES_B::countryName() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    if(const auto &sigProdPlace = getSignedSignatureProperties().signatureProductionPlace();
        sigProdPlace && sigProdPlace->countryName())
        return sigProdPlace->countryName().get();
    if(const auto &sigProdPlaceV2 = getSignedSignatureProperties().signatureProductionPlaceV2();
        sigProdPlaceV2 && sigProdPlaceV2->countryName())
        return sigProdPlaceV2->countryName().get();
    return {};
}

vector<string> SignatureXAdES_B::signerRoles() const
{
    auto toRoles = [](const ClaimedRolesListType::ClaimedRoleSequence &claimedRoleSequence) -> vector<string> {
        vector<string> roles;
        roles.reserve(claimedRoleSequence.size());
        for(const auto &type: claimedRoleSequence)
            roles.emplace_back(type.text());
        return roles;
    };
    // return elements from SignerRole element or SignerRoleV2 when available
    if(const auto &role = getSignedSignatureProperties().signerRole();
        role && role->claimedRoles())
        return toRoles(role->claimedRoles()->claimedRole());
    if(const auto &roleV2 = getSignedSignatureProperties().signerRoleV2();
        roleV2 && roleV2->claimedRoles())
        return toRoles(roleV2->claimedRoles()->claimedRole());
    return {};
}

string SignatureXAdES_B::claimedSigningTime() const
{
    if(const auto &signingTime = getSignedSignatureProperties().signingTime())
        return date::to_string(signingTime.get());
    return {};
}

X509Cert SignatureXAdES_B::signingCertificate() const
{
    const SignatureType::KeyInfoOptional &keyInfoOptional = signature->keyInfo();
    if(!keyInfoOptional)
        THROW("Signature does not contain signer certificate");

    try
    {
        for(const KeyInfoType::X509DataType &x509Data: keyInfoOptional->x509Data())
        {
            if(x509Data.x509Certificate().empty())
                continue;
            const X509DataType::X509CertificateType &data = x509Data.x509Certificate().front();
            return X509Cert((const unsigned char*)data.data(), data.size());
        }
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to read X509 certificate");
    }
    THROW("Signature does not contain signer certificate");
}

string SignatureXAdES_B::id() const
{
    return signature->id() ? signature->id().get() : string();
}

string SignatureXAdES_B::signatureMethod() const
{
    return signature->signedInfo().signatureMethod().algorithm();
}

QualifyingPropertiesType& SignatureXAdES_B::qualifyingProperties() const
{
    SignatureType::ObjectSequence& oSeq = signature->object();
    if ( oSeq.empty() )
        THROW("Signature block 'Object' is missing.");
    if(oSeq.size() != 1)
        THROW("Signature block contains more than one 'Object' block.");

    // QualifyingProperties
    ObjectType::QualifyingPropertiesSequence& qpSeq = oSeq.front().qualifyingProperties();
    if ( qpSeq.empty() )
        THROW("Signature block 'QualifyingProperties' is missing.");
    if(qpSeq.size() != 1)
        THROW("Signature block 'Object' contains more than one 'QualifyingProperties' block.");

    return qpSeq.front();
}

/**
* Helper that retrieves SignedSignatureProperties xades object. It will throw
* in case the block is not present.
*
* @return returns the SignedSignaturePropertiesType object.
*/
SignedSignaturePropertiesType& SignatureXAdES_B::getSignedSignatureProperties() const
{
    QualifyingPropertiesType::SignedPropertiesOptional& spOpt = qualifyingProperties().signedProperties();
    if(!spOpt)
        THROW("QualifyingProperties block 'SignedProperties' is missing.");
    if(!spOpt->signedSignatureProperties())
        THROW("SignedProperties block 'SignedSignatureProperties' is missing.");
    return spOpt->signedSignatureProperties().get();
}
