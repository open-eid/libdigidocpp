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
#include "log.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/Signer.h"
#include "crypto/X509CertStore.h"
#include "crypto/X509Crypto.h"
#include "util/DateTime.h"
#include "util/File.h"
#include "xml/en_31916201v010101.hxx"
#include "xml/SecureDOMParser.h"
#include "xml/OpenDocument_dsig.hxx"
#include "xml/URIResolver.h"

#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wnull-conversion"
#endif
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif
#include <xsec/framework/XSECException.hpp>
#include <xsec/framework/XSECProvider.hpp>

#include <regex>
#if _MSC_VER >= 1900 || (__cplusplus >= 201103L &&                \
    (!defined(__GLIBCXX__) || (__cplusplus >= 201402L) || \
        (defined(_GLIBCXX_REGEX_DFS_QUANTIFIERS_LIMIT) || \
         defined(_GLIBCXX_REGEX_STATE_LIMIT)           || \
         (defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE > 4))))
#define HAVE_WORKING_REGEX
#endif

using namespace digidoc;
using namespace digidoc::asic;
using namespace digidoc::dsig;
using namespace digidoc::util;
using namespace digidoc::xades;
using namespace std;
using namespace xercesc;
using namespace xml_schema;
namespace xml = xsd::cxx::xml;

const string SignatureXAdES_B::XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";
const string SignatureXAdES_B::XADESv141_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#";
const string SignatureXAdES_B::ASIC_NAMESPACE = "http://uri.etsi.org/02918/v1.2.1#";
const string SignatureXAdES_B::OPENDOCUMENT_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
const string SignatureXAdES_B::POLICY_BDOC_2_1_OID = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
const map<string,SignatureXAdES_B::Policy> SignatureXAdES_B::policylist = {
    {SignatureXAdES_B::POLICY_BDOC_2_1_OID,{
        "BDOC – FORMAT FOR DIGITAL SIGNATURES",
        "https://www.sk.ee/repository/bdoc-spec21.pdf",
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
    {"urn:oid:1.3.6.1.4.1.10015.1000.3.2.3",{
        "BDOC – FORMAT FOR DIGITAL SIGNATURES",
        "http://id.ee/public/bdoc-spec212-eng.pdf",
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
    return Base64Binary(v.data(), v.size());
}

}

/**
 * Creates an empty BDOC-BES signature with mandatory XML nodes.
 */
SignatureXAdES_B::SignatureXAdES_B(unsigned int id, ASiContainer *bdoc, Signer *signer)
    : bdoc(bdoc)
{
    string nr = "S" + to_string(id);

    // Signature->SignedInfo
    SignedInfoType signedInfo(Uri(/*URI_ID_EXC_C14N_NOC*/URI_ID_C14N11_NOC), Uri(URI_ID_RSA_SHA256));

    // Signature->SignatureValue
    SignatureValueType signatureValue;
    signatureValue.id(nr + "-SIG");

    // Signature (root)
    asicsignature.reset(new XAdESSignaturesType());
    asicsignature->signature().push_back(SignatureType(signedInfo, signatureValue));
    signature = &asicsignature->signature()[0];
    signature->id(nr);

    // Signature->Object->QualifyingProperties->SignedProperties
    SignedPropertiesType signedProperties;
    signedProperties.signedSignatureProperties(SignedSignaturePropertiesType());
    signedProperties.id(nr + "-SignedProperties");
    if(signer->profile().find(ASiC_E::ASIC_TM_PROFILE) != string::npos ||
       signer->profile().find(ASiC_E::EPES_PROFILE) != string::npos)
    {
        map<string,Policy>::const_iterator p = policylist.find(POLICY_BDOC_2_1_OID);
        IdentifierType identifierid(p->first);
        identifierid.qualifier(QualifierType::OIDAsURN);

        ObjectIdentifierType identifier(identifierid);
        identifier.description(p->second.DESCRIPTION);

        string digestUri = Conf::instance()->digestUri();
        const vector<unsigned char> *data = &p->second.SHA256;
        if(Conf::instance()->digestUri() == URI_SHA224) data = &p->second.SHA224;
        else if(Conf::instance()->digestUri() == URI_SHA256) data = &p->second.SHA256;
        else if(Conf::instance()->digestUri() == URI_SHA384) data = &p->second.SHA384;
        else if(Conf::instance()->digestUri() == URI_SHA512) data = &p->second.SHA512;
        DigestAlgAndValueType policyDigest(DigestMethodType(digestUri),
            Base64Binary(&data->front(), data->size()));

        SignaturePolicyIdType policyId(identifier, policyDigest);

        SigPolicyQualifiersListType::SigPolicyQualifierType uri;
        uri.sPURI(p->second.URI);

        SigPolicyQualifiersListType qualifiers;
        qualifiers.sigPolicyQualifier().push_back(uri);
        policyId.sigPolicyQualifiers(qualifiers);

        SignaturePolicyIdentifierType policyidentifier;
        policyidentifier.signaturePolicyId(policyId);
        signedProperties.signedSignatureProperties()->signaturePolicyIdentifier(policyidentifier);
    }

    // Signature->Object->QualifyingProperties
    QualifyingPropertiesType qualifyingProperties("#" + nr);
    qualifyingProperties.signedProperties(signedProperties);

    // Signature->Object
    ObjectType object;
    object.qualifyingProperties().push_back(qualifyingProperties);

    signature->object().push_back(object);

    //Fill XML-DSIG/XAdES properties
    X509Cert c = signer->cert();
    setKeyInfo(c);
    if(signer->usingENProfile())
    {
        setSigningCertificateV2(c);
        setSignatureProductionPlaceV2(signer->city(), signer->streetAddress(), signer->stateOrProvince(), signer->postalCode(), signer->countryName());
        setSignerRolesV2(signer->signerRoles());
    }
    else
    {
        setSigningCertificate(c);
        setSignatureProductionPlace(signer->city(), signer->stateOrProvince(), signer->postalCode(), signer->countryName());
        setSignerRoles(signer->signerRoles());
    }
    signature->signedInfo().signatureMethod(Uri( X509Crypto(c).isRSAKey() ?
        Digest::toRsaUri(signer->method()) : Digest::toEcUri(signer->method()) ));
    time_t t = time(0);
    setSigningTime(gmtime(&t));

    string digestMethod = Conf::instance()->digestUri();
    for(const DataFile *f: bdoc->dataFiles())
    {
        string id = addReference(File::toUriPath(f->fileName()), digestMethod, f->calcDigest(digestMethod), "");
        addDataObjectFormat("#" + id, f->mediaType());
    }

    Digest calc(digestMethod);
    calcDigestOnNode(&calc, XADES_NAMESPACE, "SignedProperties");
    addReference("#" + nr +"-SignedProperties", calc.uri(), calc.result(), "http://uri.etsi.org/01903#SignedProperties");
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
SignatureXAdES_B::SignatureXAdES_B(istream &sigdata, ASiContainer *bdoc, bool relaxSchemaValidation)
    : bdoc(bdoc)
{
    try
    {
        stringstream is;
        is << sigdata.rdbuf();
        sigdata_ = is.str();

        Properties properties;
        const auto xadesShema = relaxSchemaValidation ? "/XAdES01903v132-201601-relaxed.xsd" : "/XAdES01903v132-201601.xsd";
        properties.schema_location(XADES_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + xadesShema));
        properties.schema_location(XADESv141_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + "/XAdES01903v141-201601.xsd"));
        properties.schema_location(URI_ID_DSIG, File::fullPathUrl(Conf::instance()->xsdPath() + "/xmldsig-core-schema.xsd"));
        properties.schema_location(ASIC_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + "/en_31916201v010101.xsd"));
        properties.schema_location(OPENDOCUMENT_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + "/OpenDocument_dsig.xsd"));
        unique_ptr<DOMDocument> doc(SecureDOMParser(properties.schema_location()).parseIStream(is));
        /* http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf
         * 6.2.2
         * 3) The root element of each "*signatures*.xml" content shall be either:
         * a) <asic:XAdESSignatures> as specified in clause A.5, the recommended format; or
         * b) <document-signatures> as specified in OASIS Open Document Format [9]; or
         *
         * Case container is ADoc 1.0 then handle document-signatures root element
         */
        if(bdoc->mediaType() == ASiC_E::MIMETYPE_ADOC)
        {
            odfsignature = document_signatures(*doc, Flags::dont_initialize, properties);
            if(odfsignature->signature().size() > 1)
                THROW("More than one signature in signatures.xml file is unsupported");
            if(odfsignature->signature().empty())
                THROW("Failed to parse signature XML");
            signature = &odfsignature->signature()[0];
        }
        else
        {
            asicsignature = xAdESSignatures(*doc, Flags::dont_initialize, properties);
            if(asicsignature->signature().size() > 1)
                THROW("More than one signature in signatures.xml file is unsupported");
            if(asicsignature->signature().empty())
                THROW("Failed to parse signature XML");
            signature = &asicsignature->signature()[0];
        }
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

    const QualifyingPropertiesType::SignedPropertiesOptional &sp = qualifyingProperties().signedProperties();
    if(sp.present())
    {
        const SignedPropertiesType::SignedDataObjectPropertiesOptional &sdop = sp->signedDataObjectProperties();
        if(sdop.present())
        {
            if(!sdop->commitmentTypeIndication().empty())
                DEBUG("CommitmentTypeIndicationType is not supported");
            if(!sdop->allDataObjectsTimeStamp().empty())
                THROW("AllDataObjectsTimeStamp is not supported");
            if(!sdop->individualDataObjectsTimeStamp().empty())
                THROW("IndividualDataObjectsTimeStampType is not supported");
        }
    }
    const QualifyingPropertiesType::UnsignedPropertiesOptional &up = qualifyingProperties().unsignedProperties();
    if(up.present())
    {
        if(up->unsignedDataObjectProperties().present())
            THROW("UnsignedDataObjectProperties are not supported");
        const UnsignedPropertiesType::UnsignedSignaturePropertiesOptional &usp = up->unsignedSignatureProperties();
        if(usp.present())
        {
            if(!usp->counterSignature().empty())
                THROW("CounterSignature is not supported");
            if(!usp->completeCertificateRefs().empty())
                THROW("CompleteCertificateRefs are not supported");
            if(!usp->completeRevocationRefs().empty())
                THROW("CompleteRevocationRefs are not supported");
            if(!usp->attributeCertificateRefs().empty())
                THROW("AttributeCertificateRefs are not supported");
            if(!usp->attributeRevocationRefs().empty())
                THROW("AttributeRevocationRefs are not supported");
            if(!usp->sigAndRefsTimeStamp().empty())
                THROW("SigAndRefsTimeStamp is not supported");
            if(!usp->refsOnlyTimeStamp().empty())
                THROW("RefsOnlyTimeStamp is not supported");
            if(!usp->attrAuthoritiesCertValues().empty())
                THROW("AttrAuthoritiesCertValues are not supported");
            if(!usp->attributeRevocationValues().empty())
                THROW("AttributeRevocationValues are not supported");
            if(!usp->archiveTimeStamp().empty())
                THROW("ArchiveTimeStamp is not supported");
            if(!usp->timeStampValidationData().empty())
                THROW("TimeStampValidationData is not supported");
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

SignatureXAdES_B::~SignatureXAdES_B() = default;

string SignatureXAdES_B::policy() const
{
    const SignedSignaturePropertiesType::SignaturePolicyIdentifierOptional &identifier =
            getSignedSignatureProperties().signaturePolicyIdentifier();
    if(!identifier.present())
        return string();

    const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
    if(!id.present())
        return string();

    const ObjectIdentifierType::IdentifierType &objid = id->sigPolicyId().identifier();
    if(!objid.qualifier().present() || objid.qualifier().get() != QualifierType::OIDAsURN)
        return string();

    return objid;
}

/**
 * @return returns signature mimetype.
 */
string SignatureXAdES_B::profile() const
{
    string base = policy().empty() ? ASiC_E::BES_PROFILE : ASiC_E::EPES_PROFILE;
    try {
        const QualifyingPropertiesType::UnsignedPropertiesOptional &up = qualifyingProperties().unsignedProperties();
        if(!up.present())
            return base;
        const UnsignedPropertiesType::UnsignedSignaturePropertiesOptional &usp = up->unsignedSignatureProperties();
        if(!usp.present())
            return base;

        if(!usp->signatureTimeStamp().empty())
        {
            if(!usp->archiveTimeStampV141().empty())
                return base + "/" + ASiC_E::ASIC_TSA_PROFILE;
            return base + "/" + ASiC_E::ASIC_TS_PROFILE;
        }
        if(!usp->revocationValues().empty())
        {
            if(!usp->archiveTimeStampV141().empty())
                return base + "/" + ASiC_E::ASIC_TMA_PROFILE;
            return base + "/" + ASiC_E::ASIC_TM_PROFILE;
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
    if(!identifier.present())
        return string();

    const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
    if(!id.present())
        return string();

    const SignaturePolicyIdType::SigPolicyQualifiersOptional &qual = id->sigPolicyQualifiers();
    if(!qual.present())
        return string();

    for(const SigPolicyQualifiersListType::SigPolicyQualifierType &i: qual->sigPolicyQualifier())
        if(i.sPURI().present())
            return i.sPURI().get();

    return string();
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
    Exception exception(__FILE__, __LINE__, "Signature validation");

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

        map<string,Policy>::const_iterator p = policylist.find(SignatureXAdES_B::policy());
        if(p != policylist.end())
        {
            const SignedSignaturePropertiesType::SignaturePolicyIdentifierOptional &identifier =
                    getSignedSignatureProperties().signaturePolicyIdentifier();
            if(identifier.present())
            {
                const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
                if(id.present())
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
        stringstream ofs;
        saveToXml(ofs);
        unique_ptr<SecureDOMParser> parser(new SecureDOMParser);
        unique_ptr<DOMDocument> doc(parser->parseIStream(ofs));

        XSECProvider prov;
        DSIGSignature *sig = prov.newSignatureFromDOM(doc.get());
        unique_ptr<URIResolver> uriresolver(new URIResolver(bdoc));
        unique_ptr<XSECKeyInfoResolverDefault> keyresolver(new XSECKeyInfoResolverDefault);
        sig->setURIResolver(uriresolver.get());
        sig->setKeyInfoResolver(keyresolver.get());
        sig->load();

        safeBuffer m_errStr;
        m_errStr.sbXMLChIn(DSIGConstants::s_unicodeStrEmpty);

        if(!DSIGReference::verifyReferenceList(sig->getReferenceList(), m_errStr))
        //if(!sig->verify()) does not support URI_ID_C14N11_NOC canonicalization
        {
            //string s = xml::transcode<char>(sig->getErrMsgs());
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
    catch(XSECException &e)
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
    if(sp.signedDataObjectProperties().present())
    {
        for(const DataObjectFormatType &data: sp.signedDataObjectProperties()->dataObjectFormat())
        {
            if(data.mimeType().present())
                mimeinfo.insert(pair<string,string>(data.objectReference(), data.mimeType().get()));
        }
    }
    else
    {
        // ADoc 1.0 does not add DataObjectProperties>DataObjectFormat elements
        if(bdoc->mediaType() != ASiC_E::MIMETYPE_ADOC)
            EXCEPTION_ADD(exception, "DataObjectFormat element is missing");
    }

    map<string,string> signatureref;
    string signedPropertiesId = sp.id().present() ? "#" + sp.id().get() : string();
    bool signedInfoFound = false;
    for(const ReferenceType &ref: signature->signedInfo().reference())
    {
        if(!ref.uRI().present() || ref.uRI()->empty())
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
        else if(!sp.signedDataObjectProperties().present())
            continue; // DataObjectProperties is missing, no need to match later MediaTypes
        else if(!ref.id().present())
            EXCEPTION_ADD(exception, "Reference '%s' ID  missing", ref.uRI().get().c_str());
        else
        {
            string uri = File::fromUriPath(ref.uRI().get());
            if(uri[0] == '/')
                uri.erase(0, 1);
            signatureref.insert({ uri, mimeinfo["#"+ref.id().get()] });
        }
    };
    if(!signedInfoFound)
        EXCEPTION_ADD(exception, "SignedProperties not found");

    // Match DataObjectFormat element MediaTypes with Manifest
    if(!signatureref.empty())
    {
        for(const DataFile *file: bdoc->dataFiles())
        {
            map<string,string>::const_iterator i = signatureref.find(file->fileName());
            if(i != signatureref.end())
            {
                if(i->second != file->mediaType())
                    EXCEPTION_ADD(exception, "Manifest datafile '%s' mime '%s' does not match signature mime '%s'",
                        file->fileName().c_str(), file->mediaType().c_str(), i->second.c_str());
#ifdef HAVE_WORKING_REGEX
                static regex reg("([\\w])*/([\\w\\-\\+\\.])*");
                if(!file->mediaType().empty() && !regex_match(file->mediaType(), reg))
                {
                    Exception w(EXCEPTION_PARAMS("'%s' is not conformant mime-type string!", file->mediaType().c_str()));
                    w.setCode(Exception::MimeTypeWarning);
                    exception.addCause(w);
                }
#endif
                signatureref.erase(i);
            }
            else
                EXCEPTION_ADD(exception, "Manifest datafile not listed in signature references %s", file->fileName().c_str());
        };
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
    calcDigestOnNode(&calc, URI_ID_DSIG, "SignedInfo");
    return calc.result();
}

/**
 * Verify if SigningCertificate matches with
 * XAdES::SigningCertificate/SigningCertificateV2 Digest and IssuerSerial info
 */
void SignatureXAdES_B::checkKeyInfo() const
{
    X509Cert x509 = signingCertificate();

    const SignedSignaturePropertiesType::SigningCertificateOptional &sigCertOpt =
            getSignedSignatureProperties().signingCertificate();
    const SignedSignaturePropertiesType::SigningCertificateV2Optional &sigCertV2Opt =
            getSignedSignatureProperties().signingCertificateV2();
    const DigestAlgAndValueType &certDigest = [&]{
        if(sigCertOpt.present())
        {
            const CertIDListType::CertSequence &certs = sigCertOpt->cert();
            if(certs.size() != 1)
                THROW("Number of SigningCertificates is %d, must be 1", certs.size());

            // Verify Issuer Name
            const X509IssuerSerialType::X509IssuerNameType &certIssuerName = certs[0].issuerSerial().x509IssuerName();
            const X509IssuerSerialType::X509SerialNumberType &certSerialNumber = certs[0].issuerSerial().x509SerialNumber();
            if(X509Crypto(x509).compareIssuerToString(certIssuerName) != 0 || x509.serial() != certSerialNumber)
            {
                DEBUG("certIssuerName: \"%s\"", certIssuerName.c_str());
                DEBUG("x509.getCertIssuerName() \"%s\"", x509.issuerName().c_str());
                DEBUG("sertCerials = %s %s", x509.serial().c_str(), certSerialNumber.c_str());
                THROW("Signing certificate issuer information does not match");
            }

            return certs[0].certDigest();
        }
        else if(sigCertV2Opt.present())
        {
            const CertIDListV2Type::CertSequence &certs = sigCertV2Opt->cert();
            if(certs.size() != 1)
                THROW("Number of SigningCertificatesV2 is %d, must be 1", certs.size());

            // Verify IssuerSerialV2, optional parameter
            if(certs[0].issuerSerialV2().present())
            {
                if(!X509Crypto(x509).compareIssuerToDer(
                            vector<unsigned char>(certs[0].issuerSerialV2()->begin(), certs[0].issuerSerialV2()->end())))
                    THROW("Signing certificate issuer information does not match");
            }

            return certs[0].certDigest();
        }
        else
            THROW("SigningCertificate/SigningCertificateV2 not found");
    }();

    // lets check digest with x509 that was in keyInfo
    Digest certDigestCalc(certDigest.digestMethod().algorithm());
    certDigestCalc.update(x509);
    vector<unsigned char> calcDigest = certDigestCalc.result();

    if(certDigest.digestValue().size() != calcDigest.size() ||
       memcmp(calcDigest.data(), certDigest.digestValue().data(), certDigest.digestValue().size()) != 0)
    {
        DEBUGMEM("Document cert digest", certDigest.digestValue().data(), certDigest.digestValue().size());
        DEBUGMEM("Calculated cert digest", calcDigest.data(), calcDigest.size());
        THROW("Signing certificate digest does not match");
    }
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
        DEBUGMEM("Digest", sha.data(), sha.size());
        if(!X509Crypto(signingCertificate()).verify(signatureMethod(), sha, getSignatureValue()))
            THROW_CAUSE(OpenSSLException(), "Signature is not valid.");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to validate signatureValue.");
    }
}

void SignatureXAdES_B::addDataObjectFormat(const string &uri, const string &mime)
{
    QualifyingPropertiesType::SignedPropertiesOptional& spOpt = qualifyingProperties().signedProperties();
    if(!spOpt.present())
        THROW("QualifyingProperties block 'SignedProperties' is missing.");

    if(!spOpt->signedDataObjectProperties().present())
         spOpt->signedDataObjectProperties(SignedDataObjectPropertiesType());

    DataObjectFormatType dataObject(uri);
    dataObject.mimeType(mime);
    spOpt->signedDataObjectProperties()->dataObjectFormat().push_back(dataObject);
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
        const vector<unsigned char> &digestValue, const string& type)
{
    ReferenceType reference(DigestMethodType(digestUri), toBase64(digestValue));
    reference.uRI(uri);
    if(!type.empty())
        reference.type(type);

    SignedInfoType::ReferenceSequence &seq = signature->signedInfo().reference();
    reference.id(id() + Log::format("-RefId%u", seq.size()));
    seq.push_back(reference);

    return reference.id().get();
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
    X509DataType x509Data;
    x509Data.x509Certificate().push_back(toBase64(x509));

    KeyInfoType keyInfo;
    keyInfo.x509Data().push_back(x509Data);
    signature->keyInfo(keyInfo);
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
    digest.update(x509);
    CertIDListType signingCertificate;
    signingCertificate.cert().push_back(CertIDType(
        DigestAlgAndValueType(DigestMethodType(digest.uri()), toBase64(digest.result())),
        X509IssuerSerialType(x509.issuerName(), x509.serial())));
    getSignedSignatureProperties().signingCertificate(signingCertificate);
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
    digest.update(x509);
    CertIDListV2Type signingCertificate;
    signingCertificate.cert().push_back(CertIDTypeV2(
        DigestAlgAndValueType(DigestMethodType(digest.uri()), toBase64(digest.result()))));
    getSignedSignatureProperties().signingCertificateV2(signingCertificate);
}

/**
 * Sets signature production place.
 *
 * @param spp signature production place.
 */
void SignatureXAdES_B::setSignatureProductionPlace(const string &city,
    const string &stateOrProvince, const string &postalCode, const string &countryName)
{
    if(city.empty() && stateOrProvince.empty() &&
        postalCode.empty() && countryName.empty())
        return;

    SignatureProductionPlaceType signatureProductionPlace;
    if(!city.empty())
        signatureProductionPlace.city(city);
    if(!stateOrProvince.empty())
        signatureProductionPlace.stateOrProvince(stateOrProvince);
    if(!postalCode.empty())
        signatureProductionPlace.postalCode(postalCode);
    if(!countryName.empty())
        signatureProductionPlace.countryName(countryName);

    getSignedSignatureProperties().signatureProductionPlace(signatureProductionPlace);
}

/**
 * Sets signature production place.
 *
 * @param spp signature production place.
 */
void SignatureXAdES_B::setSignatureProductionPlaceV2(const string &city, const string &streetAddress,
    const string &stateOrProvince, const string &postalCode, const string &countryName)
{
    if(city.empty() && streetAddress.empty() && stateOrProvince.empty() &&
        postalCode.empty() && countryName.empty())
        return;

    SignatureProductionPlaceV2Type signatureProductionPlace;
    if(!city.empty())
        signatureProductionPlace.city(city);
    if(!streetAddress.empty())
        signatureProductionPlace.streetAddress(streetAddress);
    if(!stateOrProvince.empty())
        signatureProductionPlace.stateOrProvince(stateOrProvince);
    if(!postalCode.empty())
        signatureProductionPlace.postalCode(postalCode);
    if(!countryName.empty())
        signatureProductionPlace.countryName(countryName);

    getSignedSignatureProperties().signatureProductionPlaceV2(signatureProductionPlace);
}

/**
 * Sets signer claimed roles to the signature.
 * NB! Only ClaimedRoles are supported. CerifiedRoles are not supported.
 *
 * @param roles signer roles.
 */
void SignatureXAdES_B::setSignerRoles(const vector<string> &roles)
{
    if(roles.empty())
        return;

    ClaimedRolesListType claimedRoles;
    for(const string &role: roles)
        claimedRoles.claimedRole().push_back(role);

    SignerRoleType signerRole;
    signerRole.claimedRoles(claimedRoles);
    getSignedSignatureProperties().signerRole(signerRole);
}

/**
 * Sets signer claimed roles to the signature.
 * NB! Only ClaimedRoles are supported. CerifiedRoles are not supported.
 *
 * @param roles signer roles.
 */
void SignatureXAdES_B::setSignerRolesV2(const vector<string> &roles)
{
    if(roles.empty())
        return;

    ClaimedRolesListType claimedRoles;
    for(const string &role: roles)
        claimedRoles.claimedRole().push_back(role);

    SignerRoleV2Type signerRole;
    signerRole.claimedRoles(claimedRoles);
    getSignedSignatureProperties().signerRoleV2(signerRole);
}

/**
 * Sets signature signing time.
 *
 * @param signingTime signing time.
 */
void SignatureXAdES_B::setSigningTime(const struct tm *signingTime)
{
    getSignedSignatureProperties().signingTime(util::date::makeDateTime(*signingTime));
}

/**
 * Sets signature value.
 *
 * @param signatureValue signature value.
 */
void SignatureXAdES_B::setSignatureValue(const vector<unsigned char> &signatureValue)
{
    // Make copy of current signature value id.
    string id = signature->signatureValue().id().get();

    // Set new signature value.
    signature->signatureValue(toBase64(signatureValue));

    // Set signature value id back to its old value.
    signature->signatureValue().id(id);
}

/**
 * @return returns signature value.
 */
vector<unsigned char> SignatureXAdES_B::getSignatureValue() const
{
    const SignatureType::SignatureValueType &signatureValueType = signature->signatureValue();
    return vector<unsigned char>(signatureValueType.begin(), signatureValueType.end());
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
void SignatureXAdES_B::calcDigestOnNode(Digest* calc, const string& ns,
        const string& tagName, const string &id) const
{
    try
    {
        // Parse Xerces DOM from file, to preserve the white spaces "as is"
        // and get the same digest value on XML node.
        // Canonical XML 1.0 specification (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
        // needs all the white spaces from XML file "as is", otherwise the digests won't match.
        // Therefore we have to use Xerces to parse the XML file each time a digest needs to be
        // calculated on a XML node. If you are parsing XML files with a parser that doesn't
        // preserve the white spaces you are DOOMED!

        // Initialize Xerces parser.
        unique_ptr<SecureDOMParser> parser(new SecureDOMParser);

        // Parse and return a copy of the Xerces DOM tree.
        // Save to file an parse it again, to make XML Canonicalization work
        // correctly as expected by the Canonical XML 1.0 specification.
        // Hope, the next Canonical XMl specification fixes the white spaces preserving "bug".
        stringstream ofs;
        saveToXml(ofs);
        unique_ptr<DOMDocument> doc(parser->parseIStream(ofs));

        DOMNode *node = nullptr;
        // Select node, on which the digest is calculated.
        if(id.empty())
        {
            DOMNodeList* nodeList = doc->getElementsByTagNameNS(X(ns), X(tagName));
            if(nodeList->getLength() == 1)
                node = nodeList->item(0);
        }
        else
            node = doc->getElementById(X(id));

        // Make sure that exactly one node was found.
        if(!node)
            THROW("Could not find '%s' node which is in '%s' namespace in signature XML.", tagName.c_str(), ns.c_str());

        string algorithmType = signature->signedInfo().canonicalizationMethod().algorithm();
        SecureDOMParser::calcDigestOnNode(calc, algorithmType, doc.get(), node);
    }
    catch(const Exception& e)
    {
        THROW_CAUSE(e, "Failed to create Xerces DOM from signature XML.");
    }
    catch(const XMLException& e)
    {
        ArrayJanitor<char> msg(XMLString::transcode(e.getMessage()));
        THROW( "Failed to parse signature XML: %s", msg.get() );
    }
    catch(const DOMException& e)
    {
        ArrayJanitor<char> msg(XMLString::transcode(e.getMessage()));
        THROW( "Failed to parse signature XML: %s", msg.get() );
    }
    catch(...)
    {
        THROW("Failed to parse signature XML.");
    }
}

/**
 * Saves signature to file using XAdES XML format.
 *
 * @param os out stream, where the signature XML file is saved.
 * @throws Exception throws exception if the signature file creation failed.
 */
void SignatureXAdES_B::saveToXml(ostream &os) const
{
    if(!sigdata_.empty())
    {
        os << sigdata_;
        return;
    }

    try
    {
        NamespaceInfomap map;
        map["ds"].name = URI_ID_DSIG;
        map["xades"].name = XADES_NAMESPACE;
        map["asic"].name = ASIC_NAMESPACE;
        XAdESSignaturesType asic;
        asic.signature().push_back(*signature);
        xAdESSignatures(os, asic, map, "UTF-8", Flags::dont_initialize);
    }
    catch(const xml::invalid_utf8_string &)
    {
        THROW("Failed to create signature XML file. Parameters must be in UTF-8.");
    }
    if(os.fail())
        THROW("Failed to create signature XML file.");
}

string SignatureXAdES_B::city() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->city().present())
        return sigProdPlaceOptional->city().get();
    const SignedSignaturePropertiesType::SignatureProductionPlaceV2Optional &sigProdPlaceV2Optional =
            getSignedSignatureProperties().signatureProductionPlaceV2();
    if(sigProdPlaceV2Optional.present() && sigProdPlaceV2Optional->city().present())
        return sigProdPlaceV2Optional->city().get();
    return string();
}

string SignatureXAdES_B::stateOrProvince() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->stateOrProvince().present())
        return sigProdPlaceOptional->stateOrProvince().get();
    const SignedSignaturePropertiesType::SignatureProductionPlaceV2Optional &sigProdPlaceV2Optional =
            getSignedSignatureProperties().signatureProductionPlaceV2();
    if(sigProdPlaceV2Optional.present() && sigProdPlaceV2Optional->stateOrProvince().present())
        return sigProdPlaceV2Optional->stateOrProvince().get();
    return string();
}

string SignatureXAdES_B::streetAddress() const
{
    const SignedSignaturePropertiesType::SignatureProductionPlaceV2Optional &sigProdPlaceV2Optional =
            getSignedSignatureProperties().signatureProductionPlaceV2();
    if(sigProdPlaceV2Optional.present() && sigProdPlaceV2Optional->streetAddress().present())
        return sigProdPlaceV2Optional->streetAddress().get();
    return string();
}

string SignatureXAdES_B::postalCode() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->postalCode().present())
        return sigProdPlaceOptional->postalCode().get();
    const SignedSignaturePropertiesType::SignatureProductionPlaceV2Optional &sigProdPlaceV2Optional =
            getSignedSignatureProperties().signatureProductionPlaceV2();
    if(sigProdPlaceV2Optional.present() && sigProdPlaceV2Optional->postalCode().present())
        return sigProdPlaceV2Optional->postalCode().get();
    return string();
}

string SignatureXAdES_B::countryName() const
{
    // return elements from SignatureProductionPlace element or SignatureProductionPlaceV2 when available
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional &sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->countryName().present())
        return sigProdPlaceOptional->countryName().get();
    const SignedSignaturePropertiesType::SignatureProductionPlaceV2Optional &sigProdPlaceV2Optional =
            getSignedSignatureProperties().signatureProductionPlaceV2();
    if(sigProdPlaceV2Optional.present() && sigProdPlaceV2Optional->countryName().present())
        return sigProdPlaceV2Optional->countryName().get();
    return string();
}

vector<string> SignatureXAdES_B::signerRoles() const
{
    vector<string> roles;
    const SignedSignaturePropertiesType::SignerRoleOptional &roleOpt =
        getSignedSignatureProperties().signerRole();
    const SignedSignaturePropertiesType::SignerRoleV2Optional &roleV2Opt =
        getSignedSignatureProperties().signerRoleV2();
    auto claimedRoleSequence = [&]() -> ClaimedRolesListType::ClaimedRoleSequence const {
        // return elements from SignerRole element or SignerRoleV2 when available
        if(roleOpt.present() && roleOpt->claimedRoles().present())
            return roleOpt->claimedRoles()->claimedRole();
        else if(roleV2Opt.present() && roleV2Opt->claimedRoles().present())
            return roleV2Opt->claimedRoles()->claimedRole();
        else
            return ClaimedRolesListType::ClaimedRoleSequence();
    };
    for(const ClaimedRolesListType::ClaimedRoleType &type: claimedRoleSequence())
        roles.push_back(type.text());
    return roles;
}

string SignatureXAdES_B::claimedSigningTime() const
{
    const SignedSignaturePropertiesType::SigningTimeOptional& sigTimeOpt =
        getSignedSignatureProperties().signingTime();
    if ( !sigTimeOpt.present() )
        return string();
    return util::date::xsd2string(sigTimeOpt.get());
}

X509Cert SignatureXAdES_B::signingCertificate() const
{
    const SignatureType::KeyInfoOptional& keyInfoOptional = signature->keyInfo();
    if(!keyInfoOptional.present())
        THROW("Signature does not contain signer certificate");

    const KeyInfoType::X509DataSequence& x509DataSeq = keyInfoOptional->x509Data();
    if ( x509DataSeq.empty() )
        THROW("Signature does not contain signer certificate");
    else if(x509DataSeq.size() != 1)
        THROW("Signature contains more than one signers certificate");

    const X509DataType::X509CertificateSequence& x509CertSeq = x509DataSeq.front().x509Certificate();
    if(x509CertSeq.empty())
        THROW("Signature does not contain signer certificate");
    else if(x509CertSeq.size() != 1)
        THROW("Signature contains more than one signers certificate");
    try
    {
        const X509DataType::X509CertificateType& data = x509CertSeq.back();
        return X509Cert((const unsigned char*)data.data(), data.size());
    }
    catch(const Exception &e)
    {
        THROW_CAUSE( e, "Failed to read X509 certificate" );
    }
    return X509Cert();
}

string SignatureXAdES_B::id() const
{
    return signature->id().present() ? signature->id().get() : string();
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
    else if ( oSeq.size() != 1 )
        THROW("Signature block contains more than one 'Object' block.");

    // QualifyingProperties
    ObjectType::QualifyingPropertiesSequence& qpSeq = oSeq.front().qualifyingProperties();
    if ( qpSeq.empty() )
        THROW("Signature block 'QualifyingProperties' is missing.");
    else if ( qpSeq.size() != 1 )
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
    if(!spOpt.present())
        THROW("QualifyingProperties block 'SignedProperties' is missing.");
    if(!spOpt->signedSignatureProperties().present())
        THROW("SignedProperties block 'SignedSignatureProperties' is missing.");
    return spOpt->signedSignatureProperties().get();
}
