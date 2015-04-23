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

#include "SignatureBES.h"

#include "BDoc.h"
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
#include "xml/ts_102918v010201.hxx"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/util/BinInputStream.hpp>
#include <xsec/canon/XSECC14n20010315.hpp>
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
#include <xsec/framework/XSECURIResolverXerces.hpp>

using namespace digidoc;
using namespace digidoc::asic;
using namespace digidoc::dsig;
using namespace digidoc::util;
using namespace digidoc::xades;
using namespace std;
using namespace xercesc;
using namespace xml_schema;

static vector<unsigned char> toVector(const char *data, size_t size)
{
    return vector<unsigned char>(data, data + size);
}

const string SignatureBES::XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";
const string SignatureBES::XADESv141_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#";
const string SignatureBES::ASIC_NAMESPACE = "http://uri.etsi.org/02918/v1.2.1#";
const map<string,SignatureBES::Policy> SignatureBES::policylist = [](){
    map<string,SignatureBES::Policy> result;
    SignatureBES::Policy p210 = {
        "BDOC – FORMAT FOR DIGITAL SIGNATURES",
        "https://www.sk.ee/repository/bdoc-spec21.pdf",
        toVector(
            "\x80\x81\xe2\x69\xeb\x44\x13\xde\x20\x6e\x40\x91\xca\x04\x3d\x5a"
            "\xca\x71\x51\xdc", 20),
        toVector(
            "\xc8\xeb\x95\x3f\xc8\xe5\x93\x74\xaa\x81\x5a\x1e\x24\x3f\xcb\x42"
            "\x30\xd2\x0a\xf0\xc4\x0d\xc4\xb4\x80\xa5\xb0\xdf", 28),
        toVector(
            "\xdd\x39\x75\xa0\x82\xd2\xbc\xe0\x16\xa2\x67\x48\xf5\x57\x96\x57"
            "\xa2\x00\xff\x7d\x9e\x49\x74\x54\xae\x2f\x64\x3c\x4c\xf5\x21\x5b", 32),
        toVector(
            "\x81\xfa\xa3\x7b\x82\xf1\x8d\xc2\x8c\x71\x2e\xc1\xb9\x7b\xf9\x79"
            "\xaf\x08\x99\x77\xb7\x55\x42\x62\xfc\x07\x0d\x6b\xb3\x06\x0b\x44"
            "\x40\xa8\x1c\x9d\xbc\x67\x4c\xb5\x0c\x97\x33\xc6\x33\x17\x1a\x4e", 48),
        toVector(
            "\x8e\x1d\x3f\xa0\xe7\x66\x0c\xa7\x1c\xcf\xb0\x80\x13\x39\x1e\xbf"
            "\x29\x73\xcf\x25\xff\x6d\xd1\xe1\xc8\xc4\x5b\x84\xdd\xb1\xca\x3e"
            "\xa6\x7b\x18\x86\x04\xd8\x20\x9b\xf8\x54\x4e\xb0\x5f\xb3\x67\x58"
            "\x39\xb9\xef\xfe\xf7\x75\x7d\x34\x5e\x39\xa8\xa5\xbf\x4a\xa1\xd7", 64)
    };
    result.insert(pair<string,SignatureBES::Policy>("urn:oid:1.3.6.1.4.1.10015.1000.3.2.1",p210));
#if 0
    SignatureBES::Policy p212 = {
        "BDOC – FORMAT FOR DIGITAL SIGNATURES",
        "https://www.sk.ee/repository/bdoc-spec212.pdf",
        toVector(
            "\x15\x57\xb5\x48\x73\x0c\x5f\x2c\xf5\x71\x91\xce\x78\xc9\x7b\x7a"
            "\x24\x09\xa0\x19", 20),
        toVector(
            "\x32\x81\x72\xc2\x7a\x7b\x8a\xe4\x43\xa5\xb3\xab\xaf\x55\x2a\xaf"
            "\xff\x74\xde\xe3\x54\x05\x89\x75\x66\xa8\x30\xd5", 28),
        toVector(
            "\xaf\xe4\x20\xd3\x69\x42\x07\x0b\x28\x36\x35\xed\x17\x46\x9e\xdd"
            "\xd7\x6d\x2d\xec\x72\x17\xd5\x40\x0d\xcb\x9b\x56\x80\xd8\x75\xbc", 32),
        toVector(
            "\x3b\x29\xfc\x6c\xc0\x8c\x7d\x51\xe8\x3a\x43\xa9\xa7\x48\xa9\xb0"
            "\x78\x5b\x98\xca\x9b\xd8\x73\x21\x9b\x3b\x59\xec\xd5\x25\x4b\x56"
            "\x50\xfa\x2e\xc4\xde\x87\xa4\x6b\x0d\xa7\x4a\xef\x91\x53\x30\x89", 48),
        toVector(
            "\x7e\x96\xa2\xb4\x21\x86\x64\x46\x4a\x7a\xc0\x39\x50\x0d\xa0\x79"
            "\x7d\xcf\x16\x09\x62\x0c\xac\x4b\x69\x22\x39\x98\x40\x34\xb7\xf6"
            "\x86\x6e\x3c\x00\xe4\x91\x6d\x23\x51\x32\x9d\x92\x8a\x3e\x92\x6b"
            "\x5b\x14\x99\xee\xc5\x3e\xa6\x17\xa2\xc7\xb0\x38\xe7\x2a\x76\x85", 64)
    };
    result.insert(pair<string,SignatureBES::Policy>("urn:oid:1.3.6.1.4.1.10015.1000.3.2.3",p212));
#endif
#if 0
    result.insert(make_pair<string,SignatureBES::Policy>("urn:oid:1.3.6.1.4.1.10015.1000.3.1.1",{
        "BDOC – FORMAT FOR DIGITAL SIGNATURES",
        "https://www.sk.ee/repository/bdoc-spec20.pdf",
        toVector(
            "\x14\x5b\x43\x5b\x85\x82\xcf\xee\x79\x55\xea\xee\x94\x12\xac\xc5"
            "\xca\x75\x3b\x7d", 20),
        toVector(
            "\xa3\xad\xaa\x8e\xfc\x35\x3a\x69\x0f\x8b\xf4\x18\x83\x93\x89\x39"
            "\xcd\x22\x20\x86\x9e\xc1\xef\x11\xc7\x3d\x17\xaa", 28),
        toVector(
            "\x62\x0c\x3d\x13\x1e\xf0\x09\x2a\xde\xa7\x63\x27\x8e\xef\x8c\x97"
            "\x7a\x4e\x3d\x96\x41\x99\xde\xaf\x89\xc4\x24\xbc\xe4\x0a\xc7\x2a", 32),
        toVector(
            "\x71\x00\x5d\x0a\xc3\x90\x0f\x28\x3e\xdf\xca\xd7\x02\xaa\xd9\xf4"
            "\xa8\xd9\x01\x88\x93\xd0\xa2\xc6\xb4\x95\xbf\x85\xb9\xf4\xe9\xdc"
            "\xbf\x91\x75\x58\xb8\x3d\xa7\x31\x7e\x09\xda\x7e\xd3\xae\xad\xef", 48),
        toVector(
            "\xb6\x57\x3d\x28\xbf\x8f\x2c\x54\xd7\xba\x9e\xc6\xad\x5b\xbf\x03"
            "\x56\x3e\x58\x2b\x18\x13\xda\x69\x09\xe4\x5b\xc3\xb9\xda\x67\xb9"
            "\x7e\x90\xd1\xfe\xfb\xbd\x76\x13\xc9\x9b\x20\x37\x94\x53\xe5\x0e"
            "\x60\x36\x93\x18\x23\xdf\xf6\x69\xe7\xa2\x6d\xdb\x3f\xa0\x47\xeb", 64)
    }));
#endif
    return result;
}();

namespace digidoc
{

class IStreamInputStream: public BinInputStream
{
public:
    IStreamInputStream(istream *is): is_(is)
    {
        is_->clear();
        is_->seekg(0);
    }

    XMLFilePos curPos() const
    {
        return is_->tellg();
    }

    XMLSize_t readBytes(XMLByte * const toFill, const XMLSize_t maxToRead)
    {
        is_->read((char*)toFill, maxToRead);
        return XMLSize_t(is_->gcount());
    }

    const XMLCh *getContentType() const
    {
        return 0;
    }

    istream *is_;
};

class URIResolver: public XSECURIResolverXerces
{
public:
    URIResolver(BDoc *doc):doc_(doc) {}

    BinInputStream *resolveURI(const XMLCh *uri)
    {
        if(!uri)
            throw XSECException(XSECException::ErrorOpeningURI,
                "XSECURIResolverXerces - anonymous references not supported in default URI Resolvers");

#ifdef _WIN32
        string _uri = File::decodeName(uri);
#else
        char *enc = XMLString::transcode(uri);
        string _uri = enc;
        XMLString::release(&enc);
#endif
        if(strncmp(_uri.c_str(), "/", 1) == 0) _uri.erase(0, 1);
        for(const DataFile &file: doc_->dataFiles())
        {
            if(file.fileName() == File::fromUriPath(_uri))
                return new IStreamInputStream(file.d->is);
        }

        return XSECURIResolverXerces::resolveURI(uri);
    }

    XSECURIResolver *clone(void)
    {
        return new URIResolver(doc_);
    }

private:
    BDoc *doc_;
};

static Base64Binary toBase64(const vector<unsigned char> &v)
{
    return v.empty() ? Base64Binary() : Base64Binary(&v[0], v.size());
}

}

/**
 * Creates an empty BDOC-BES signature with mandatory XML nodes.
 */
SignatureBES::SignatureBES(unsigned int id, BDoc *bdoc)
 : signature(0)
 , asicsignature(0)
 , bdoc(bdoc)
{
    string nr = "S" + to_string(id);

    // Signature->SignedInfo
    SignedInfoType signedInfo(Uri(/*URI_ID_EXC_C14N_NOC*/URI_ID_C14N11_NOC), Uri(URI_ID_RSA_SHA256));

    // Signature->SignatureValue
    SignatureValueType signatureValue;
    signatureValue.id(nr + "-SIG");

    // Signature (root)
    asicsignature = new XAdESSignaturesType();
    asicsignature->signature().push_back(SignatureType(signedInfo, signatureValue));
    signature = &asicsignature->signature()[0];
    signature->id(nr);

    // Signature->Object->QualifyingProperties->SignedProperties
    SignedPropertiesType signedProperties;
    signedProperties.signedSignatureProperties(SignedSignaturePropertiesType());
    signedProperties.id(nr + "-SignedProperties");

    // Signature->Object->QualifyingProperties
    QualifyingPropertiesType qualifyingProperties("#" + nr);
    qualifyingProperties.signedProperties(signedProperties);

    // Signature->Object
    ObjectType object;
    object.qualifyingProperties().push_back(qualifyingProperties);

    signature->object().push_back(object);
}

/**
 *
 * @param path
 * @throws SignatureException
 */
SignatureBES::SignatureBES(istream &sigdata, BDoc *bdoc)
 : signature(nullptr)
 , asicsignature(nullptr)
 , bdoc(bdoc)
{
    try
    {
        stringstream is;
        is << sigdata.rdbuf();
        sigdata_ = is.str();

        Properties properties;
        properties.schema_location(XADES_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + "/XAdES.xsd"));
        properties.schema_location(XADESv141_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + "/XAdESv141.xsd"));
        properties.schema_location(URI_ID_DSIG, File::fullPathUrl(Conf::instance()->xsdPath() + "/xmldsig-core-schema.xsd"));
        properties.schema_location(ASIC_NAMESPACE, File::fullPathUrl(Conf::instance()->xsdPath() + "/ts_102918v010201.xsd"));
        asicsignature = xAdESSignatures(is, Flags::dont_initialize, properties).release();
        if(asicsignature->signature().size() > 1)
            THROW("More than one signature in signatures.xml file is unsupported");
        if(asicsignature->signature().empty())
            THROW("Failed to parse signature XML");
        signature = &asicsignature->signature()[0];
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

#if 0
    for(const ReferenceType &ref: signature->signedInfo().reference())
        if(ref.transforms().present())
            THROW("Transforms are not supported");
#endif
    const QualifyingPropertiesType::SignedPropertiesOptional &sp = qualifyingProperties().signedProperties();
    if(sp.present())
    {
        const SignedPropertiesType::SignedDataObjectPropertiesOptional &sdop = sp->signedDataObjectProperties();
        if(sdop.present())
        {
            if(!sdop->commitmentTypeIndication().empty())
                THROW("CommitmentTypeIndicationType is not supported");
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
            if(!usp->archiveTimeStampV141().empty())
                THROW("ArchiveTimeStampV141 is not supported");
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

SignatureBES::~SignatureBES()
{
    delete asicsignature;
}

void SignatureBES::addEPES()
{
    map<string,Policy>::const_iterator p = policylist.cbegin();
    IdentifierType identifierid(p->first);
    identifierid.qualifier(QualifierType::OIDAsURN);

    ObjectIdentifierType identifier(identifierid);
    identifier.description(p->second.DESCRIPTION);

    string digestUri = Conf::instance()->digestUri();
    const vector<unsigned char> *data = &p->second.SHA256;
    if(Conf::instance()->digestUri() == URI_SHA1) data = &p->second.SHA1;
    else if(Conf::instance()->digestUri() == URI_SHA224) data = &p->second.SHA224;
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
    getSignedSignatureProperties().signaturePolicyIdentifier(policyidentifier);
}

string SignatureBES::policy() const
{
    const SignedSignaturePropertiesType::SignaturePolicyIdentifierOptional &identifier =
            getSignedSignatureProperties().signaturePolicyIdentifier();
    if(!identifier.present())
        return "";

    const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
    if(!id.present())
        return "";

    const ObjectIdentifierType::IdentifierType &objid = id->sigPolicyId().identifier();
    if(!objid.qualifier().present() || objid.qualifier().get() != QualifierType::OIDAsURN)
        return "";

    return objid;
}

/**
 * @return returns signature mimetype.
 */
string SignatureBES::profile() const
{
    string base = policy().empty() ? BDoc::BES_PROFILE : BDoc::EPES_PROFILE;
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
                return base + "/" + BDoc::ASIC_TSA_PROFILE;
            return base + "/" + BDoc::ASIC_TS_PROFILE;
        }
        if(!usp->revocationValues().empty())
        {
            if(!usp->archiveTimeStampV141().empty())
                return base + "/" + BDoc::ASIC_TMA_PROFILE;
            return base + "/" + BDoc::ASIC_TM_PROFILE;
        }
    }
    catch(const Exception &) {}
    return base;
}

string SignatureBES::realTime() const
{
    return signingTime();
}

string SignatureBES::SPUri() const
{
    const SignedSignaturePropertiesType::SignaturePolicyIdentifierOptional &identifier =
            getSignedSignatureProperties().signaturePolicyIdentifier();
    if(!identifier.present())
        return "";

    const SignaturePolicyIdentifierType::SignaturePolicyIdOptional &id = identifier->signaturePolicyId();
    if(!id.present())
        return "";

    const SignaturePolicyIdType::SigPolicyQualifiersOptional &qual = id->sigPolicyQualifiers();
    if(!qual.present())
        return "";

    const SigPolicyQualifiersListType::SigPolicyQualifierSequence &list = qual->sigPolicyQualifier();
    for(SigPolicyQualifiersListType::SigPolicyQualifierConstIterator i = list.begin(); i != list.end(); ++i)
        if(i->sPURI().present())
            return i->sPURI().get();

    return "";
}

/**
 * Check if signature is valid according to BDoc-BES format. Performs
 * any off-line checks that prove mathematical correctness.
 * However, there is no warranty against if the signature has expired. On-line
 * validation should be performed to check for signature expiration.
 *
 * @throws SignatureException containing details on what's wrong in this signature.
*/
void SignatureBES::validate(Validate) const
{
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

    if(signerRoles().size() > 1)
        EXCEPTION_ADD(exception, "More than 1 signer role is not supported");

    if(profile().find(BDoc::ASIC_TM_PROFILE) != string::npos)
    {
        if(SPUri().empty())
            EXCEPTION_ADD(exception, "Signature SPUri is missing");

        map<string,Policy>::const_iterator p = policylist.find(policy());
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
        unique_ptr<XercesDOMParser> parser(new XercesDOMParser());
        parser->setDoNamespaces(true);
        parser->setValidationScheme(XercesDOMParser::Val_Always);
        parser->setDoSchema(true);
        parser->setCreateEntityReferenceNodes(false);
        stringstream ofs;
        saveToXml(ofs);
        string data = ofs.str();
        MemBufInputSource source((XMLByte*)data.c_str(), data.size(), "temp");
        parser->parse(source);

        XSECProvider prov;
        DSIGSignature *sig = prov.newSignatureFromDOM(parser->getDocument());
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
            //string s = xsd::cxx::xml::transcode<char>(sig->getErrMsgs());
            string s = xsd::cxx::xml::transcode<char>(m_errStr.rawXMLChBuffer());
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
        string s = xsd::cxx::xml::transcode<char>(e.getMsg());
        EXCEPTION_ADD(exception, "Failed to validate signature: %s", s.c_str());
    }
    catch(XMLException &e)
    {
        string s = xsd::cxx::xml::transcode<char>(e.getMessage());
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
        EXCEPTION_ADD(exception, "DataObjectFormat element is missing");
    }

    map<string,string> signatureref;
    string signedPropertiesId;
    bool signedInfoFound = false, weak = false;
    if(sp.id().present())
        signedPropertiesId = "#" + sp.id().get();
    for(const ReferenceType &ref: signature->signedInfo().reference())
    {
        if(ref.digestMethod().algorithm() == URI_SHA1 ||
           ref.digestMethod().algorithm() == URI_SHA224 )
            weak = true;
        if(ref.uRI().present() && ref.uRI().get() != signedPropertiesId)
        {
            string uri = File::fromUriPath(ref.uRI().get());
            if(strncmp(uri.c_str(), "/", 1) == 0)
                uri.erase(0, 1);
            signatureref.insert({ uri, mimeinfo["#"+ref.id().get()] });
        }
        if(ref.uRI().present() && ref.uRI().get() == signedPropertiesId)
            signedInfoFound = true;
    };
    if(!signedInfoFound)
        EXCEPTION_ADD(exception, "SignedProperties not found");
    if(!Exception::hasWarningIgnore(Exception::ReferenceDigestWeak) && weak)
    {
        Exception e(EXCEPTION_PARAMS("Reference digest weak"));
        e.setCode(Exception::ReferenceDigestWeak);
        exception.addCause(e);
    }

    for(const DataFile &file: bdoc->dataFiles())
    {
        map<string,string>::const_iterator i = signatureref.find(file.fileName());
        if(i != signatureref.end())
        {
            if(i->second != file.mediaType())
                EXCEPTION_ADD(exception, "Manifest datafile '%s' mime '%s' does not match signature mime '%s'",
                    file.fileName().c_str(), file.mediaType().c_str(), i->second.c_str());
            signatureref.erase(i);
        }
        else
            EXCEPTION_ADD(exception, "Manifest datafile not listed in signature references %s", file.fileName().c_str());
    };

    if(bdoc->dataFiles().empty())
        EXCEPTION_ADD(exception, "No DataFiles signed");

    if(!signatureref.empty())
        EXCEPTION_ADD(exception, "Manifest references and signature references do not match");

    try { checkKeyInfo(); }
    catch(const Exception& e) { exception.addCause(e); }

    try { checkSignatureValue(); }
    catch(const Exception& e) { exception.addCause(e); }

    try { checkSigningCertificate(); }
    catch(const Exception& e) { exception.addCause(e); }

    if(!exception.causes().empty())
        throw exception;
}

/**
 * Prepares SignedInfo
 *
 * @param signer signer that signs the signature object.
 * @throws Exception exception is throws if signing failed.
 */
vector<unsigned char> SignatureBES::prepareSignedInfo(Signer* signer)
{
    X509Cert c = signer->cert();
    setSigningCertificate(c);
    signature->signedInfo().signatureMethod(Uri( X509Crypto(c).rsaModulus().empty() ?
        Digest::toEcUri(signer->method()) : Digest::toRsaUri(signer->method()) ));

    setSignatureProductionPlace(signer->city(), signer->stateOrProvince(), signer->postalCode(), signer->countryName());
    setSignerRoles(signer->signerRoles());
    time_t t = time(0);
    setSigningTime(gmtime(&t));

    Digest calc;
    calcDigestOnNode(&calc, XADES_NAMESPACE, "SignedProperties");
    addReference("#" + id() +"-SignedProperties", calc.uri(), calc.result(), "http://uri.etsi.org/01903#SignedProperties");

    calc.reset(signatureMethod());
    calcDigestOnNode(&calc, URI_ID_DSIG, "SignedInfo");
    return calc.result();
}

/// TODO: comment
///
/// @throws SignatureException on a problem in signature
void SignatureBES::checkKeyInfo() const
{
    X509Cert x509 = signingCertificate();

    const SignedSignaturePropertiesType::SigningCertificateOptional &sigCertOpt =
            getSignedSignatureProperties().signingCertificate();
    if ( !sigCertOpt.present() )
        THROW("SigningCertificate not found");

    const CertIDListType::CertSequence &certs = sigCertOpt->cert();
    if ( certs.size() != 1 )
        THROW("Number of SigningCertificates is %d, must be 1", certs.size());

    X509IssuerSerialType::X509IssuerNameType certIssuerName = certs[0].issuerSerial().x509IssuerName();
    X509IssuerSerialType::X509SerialNumberType certSerialNumber = certs[0].issuerSerial().x509SerialNumber();
    if(X509Crypto(x509).compareIssuerToString(certIssuerName) != 0 || x509.serial() != certSerialNumber)
    {
        DEBUG("certIssuerName: \"%s\"", certIssuerName.c_str());
        DEBUG("x509.getCertIssuerName() \"%s\"", x509.issuerName().c_str());
        DEBUG("sertCerials = %s %s", x509.serial().c_str(), certSerialNumber.c_str());
        THROW("Signing certificate issuer information does not match");
    }

    // lets check digest with x509 that was in keyInfo
    Digest certDigestCalc(certs[0].certDigest().digestMethod().algorithm());
    certDigestCalc.update(x509);
    vector<unsigned char> calcDigest = certDigestCalc.result();

    DigestAlgAndValueType::DigestValueType const& certDigestValue = certs[0].certDigest().digestValue();
    if(certDigestValue.size() != calcDigest.size() ||
       memcmp(&calcDigest[0], certDigestValue.data(), certDigestValue.size()) != 0)
    {
        DEBUGMEM("Document cert digest", certDigestValue.data(), certDigestValue.size());
        DEBUGMEM("Calculated cert digest", &calcDigest[0], calcDigest.size());
        THROW("Signing certificate digest does not match");
    }
}

/// Check if signing certificate was issued by trusted party.
/// @throws SignatureException on a problem with signing certificate
void SignatureBES::checkSigningCertificate() const
{
    try
    {
        X509Cert signingCert = signingCertificate();
        vector<X509Cert::KeyUsage> usage = signingCert.keyUsage();
        if(find(usage.begin(), usage.end(), X509Cert::NonRepudiation) == usage.end())
            THROW("Signing certificate does not contain NonRepudiation key usage flag");
        string time = realTime();
        if(time.empty())
            THROW("SigningTime missing");
        time_t signingTime_t = util::date::string2time_t(time);
        if(!X509CertStore::instance()->verify(signingCert, &signingTime_t))
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
void SignatureBES::checkSignatureValue() const
{
    DEBUG("SignatureBES::checkSignatureValue()");
    try
    {
        // Calculate SHA digest of the Signature->SignedInfo node.
        Digest calc(signatureMethod());
        calcDigestOnNode(&calc, URI_ID_DSIG, "SignedInfo");
        vector<unsigned char> sha = calc.result();
        DEBUGMEM("Digest", &sha[0], sha.size());

        if(!X509Crypto(signingCertificate()).verify(signatureMethod(), sha, getSignatureValue()))
            THROW_CAUSE(OpenSSLException(), "Signature is not valid.");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to validate signature.");
    }
}

void SignatureBES::addDataObjectFormat(const string &uri, const string &mime)
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
string SignatureBES::addReference(const string& uri, const string& digestUri,
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
 * Signature->KeyInfo->X509Data->X509Certificate. Certificate info is also added to
 * Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.
 *
 * @param cert certificate that is used for signing the signature XML.
 */
void SignatureBES::setSigningCertificate(const X509Cert& x509)
{
    DEBUG("SignatureBES::setSigningCertificate()");
    // Signature->KeyInfo->X509Data->X509Certificate
    // BASE64 encoding of a DER-encoded X.509 certificate = PEM encoded.
    X509DataType x509Data;
    x509Data.x509Certificate().push_back(toBase64(x509));

    KeyInfoType keyInfo;
    keyInfo.x509Data().push_back(x509Data);
    signature->keyInfo(keyInfo);

    // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate
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
 * Sets signature production place.
 *
 * @param spp signature production place.
 */
void SignatureBES::setSignatureProductionPlace(const string &city,
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
 * Sets signer claimed roles to the signature.
 * NB! Only ClaimedRoles are supported. CerifiedRoles are not supported.
 *
 * @param roles signer roles.
 */
void SignatureBES::setSignerRoles(const vector<string> &roles)
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
 * Sets signature signing time.
 *
 * @param signingTime signing time.
 */
void SignatureBES::setSigningTime(const struct tm *signingTime)
{
    getSignedSignatureProperties().signingTime(util::date::makeDateTime(*signingTime));
}

/**
 * Sets signature value.
 *
 * @param sigValue signature value.
 */
void SignatureBES::setSignatureValue(const vector<unsigned char> &sigValue)
{
    // Make copy of current signature value id.
    string id = signature->signatureValue().id().get();

    // Set new signature value.
    signature->signatureValue(toBase64(sigValue));

    // Set signature value id back to its old value.
    signature->signatureValue().id(id);
}

/**
 * @return returns signature value.
 */
vector<unsigned char> SignatureBES::getSignatureValue() const
{
    const SignatureType::SignatureValueType &signatureValueType = signature->signatureValue();
    return vector<unsigned char>(signatureValueType.data(),
        signatureValueType.data() + signatureValueType.size());
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
void SignatureBES::calcDigestOnNode(Digest* calc, const string& ns,
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
        unique_ptr<XercesDOMParser> parser(new XercesDOMParser());
        parser->setDoNamespaces(true);
        parser->setValidationScheme(XercesDOMParser::Val_Always);
        parser->setDoSchema(true);
        parser->setCreateEntityReferenceNodes(false);
        //ErrorHandler* errorHandler = /*(ErrorHandler*)*/ new HandlerBase();
        //parser->setErrorHandler(errorHandler);

        // Parse and return a copy of the Xerces DOM tree.
        // Save to file an parse it again, to make XML Canonicalization work
        // correctly as expected by the Canonical XML 1.0 specification.
        // Hope, the next Canonical XMl specification fixes the white spaces preserving "bug".
        stringstream ofs;
        saveToXml(ofs);
        string data = ofs.str();
        MemBufInputSource source((XMLByte*)data.c_str(), data.size(), "temp");
        parser->parse(source);
        DOMDocument *dom = parser->getDocument();

        DOMNode *node = nullptr;
        // Select node, on which the digest is calculated.
        if(id.empty())
        {
            XMLCh *tagNs = XMLString::transcode(ns.c_str());
            XMLCh *tag = XMLString::transcode(tagName.c_str());
            DOMNodeList* nodeList = dom->getElementsByTagNameNS(tagNs, tag);
            if(nodeList->getLength() == 1)
                node = nodeList->item(0);
            XMLString::release(&tagNs);
            XMLString::release(&tag);
        }
        else
        {
            XMLCh *tagId = XMLString::transcode(id.c_str());
            node = dom->getElementById(tagId);
            XMLString::release(&tagId);
        }

        // Make sure that exactly one node was found.
        if(!node)
            THROW("Could not find '%s' node which is in '%s' namespace in signature XML.", tagName.c_str(), ns.c_str());

        // Canocalize XML using one of the three methods supported by XML-DSIG
        XSECC14n20010315 canonicalizer(dom, node);
        canonicalizer.setCommentsProcessing(false);
        canonicalizer.setUseNamespaceStack(true);

        // Find the method identifier
        SignedInfoType& signedInfo = signature->signedInfo();
        CanonicalizationMethodType& canonMethod = signedInfo.canonicalizationMethod();
        CanonicalizationMethodType::AlgorithmType& algorithmType = canonMethod.algorithm();

        DEBUG("C14N ns(%s) tagName(%s) algorithmType(%s)", ns.c_str(), tagName.c_str(), algorithmType.c_str());

        // Set processing flags according to algorithm type.
        if(algorithmType == URI_ID_C14N_NOC) {
            // Default behaviour, nothing needs to be changed
        } else if(algorithmType == URI_ID_C14N_COM) {
            canonicalizer.setCommentsProcessing(true);
        } else if(algorithmType == URI_ID_EXC_C14N_NOC) {
            // Exclusive mode needs to include xml-dsig in root element
            // in order to maintain compatibility with existing implementations
            canonicalizer.setExclusive();
        } else if(algorithmType == URI_ID_EXC_C14N_COM) {
            canonicalizer.setExclusive();
            canonicalizer.setCommentsProcessing(true);
        } else if(algorithmType == URI_ID_C14N11_NOC) {
            canonicalizer.setInclusive11();
        } else if(algorithmType == URI_ID_C14N11_COM) {
            canonicalizer.setInclusive11();
            canonicalizer.setCommentsProcessing(true);
        } else {
            // Unknown algorithm.
            THROW("Unsupported SignedInfo canonicalization method '%s'", algorithmType.c_str());
        }

        string c14n;
        unsigned char buffer[1024];
        xsecsize_t bytes = 0;
        while((bytes = canonicalizer.outputBuffer(buffer, 1024)) > 0)
        {
            calc->update(buffer, (unsigned int)bytes);
            c14n.append( (char*)&buffer[0], size_t(bytes));
        }
        //DEBUG("c14n = \n%s", c14n.c_str());
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
 * @param path path, where the signature XML file is saved.
 * @throws IOException throws exception if the signature file creation failed.
 */
void SignatureBES::saveToXml(ostream &os) const
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
        if(profile().find("archive") != string::npos)
            map["xadesv141"].name = XADESv141_NAMESPACE;
        XAdESSignaturesType asic;
        asic.signature().push_back(*signature);
        xAdESSignatures(os, asic, map, "UTF-8", Flags::dont_initialize);
    }
    catch ( xsd::cxx::xml::invalid_utf8_string )
    {
        THROW("Failed to create signature XML file. Parameters must be in UTF-8.");
    }
    if(os.fail())
        THROW("Failed to create signature XML file.");
}

/**
 * The address where was the signature given.
 *
 * @return returns structure containing the address of signing place.
 */
string SignatureBES::city() const
{
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->city().present())
        return sigProdPlaceOptional->city().get();
    return "";
}

string SignatureBES::stateOrProvince() const
{
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->stateOrProvince().present())
        return sigProdPlaceOptional->stateOrProvince().get();
    return "";
}

string SignatureBES::postalCode() const
{
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->postalCode().present())
        return sigProdPlaceOptional->postalCode().get();
    return "";
}

string SignatureBES::countryName() const
{
    const SignedSignaturePropertiesType::SignatureProductionPlaceOptional& sigProdPlaceOptional =
        getSignedSignatureProperties().signatureProductionPlace();
    if(sigProdPlaceOptional.present() && sigProdPlaceOptional->countryName().present())
        return sigProdPlaceOptional->countryName().get();
    return "";
}

/**
 * The role that signer claims to hold while signing.
 *
 * @return returns the claimed role of the signer.
 */
vector<string> SignatureBES::signerRoles() const
{
    vector<string> roles;
    const SignedSignaturePropertiesType::SignerRoleOptional& roleOpt =
        getSignedSignatureProperties().signerRole();
    if ( !roleOpt.present() )
        return roles;

    const SignerRoleType::ClaimedRolesOptional& claimedRoleOpt = roleOpt->claimedRoles();
    if ( !claimedRoleOpt.present() )
        return roles;

    const ClaimedRolesListType::ClaimedRoleSequence& claimedRolesSequence = claimedRoleOpt->claimedRole();
    roles.insert( roles.end(), claimedRolesSequence.begin(), claimedRolesSequence.end() );
    return roles;
}

// FIXME: return date object not string.
// FIXME: wrong comments
/**
* The role that signer claims to hold while signing.
*
* @return returns the claimed role of the signer.
*/
string SignatureBES::signingTime() const
{
    const SignedSignaturePropertiesType::SigningTimeOptional& sigTimeOpt =
        getSignedSignatureProperties().signingTime();
    if ( !sigTimeOpt.present() )
        return "";
    return util::date::xsd2string(sigTimeOpt.get());
}


/**
 * Signer certificate taken from current signature.
 *
 * @return returns the SignedSignaturePropertiesType object.
 * @throws SignatureException
*/
X509Cert SignatureBES::signingCertificate() const
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
        return X509Cert(vector<unsigned char>(data.data(), data.data()+data.size()));
    }
    catch(const Exception &e)
    {
        THROW_CAUSE( e, "Failed to read X509 certificate" );
    }
    return X509Cert();
}

/**
 * Signature id
 *
 * @return returns signature id
 */
string SignatureBES::id() const
{
    return signature->id().present() ? signature->id().get() : string();
}

/**
 * Signer signature method
 *
 * @return returns the signature method.
 */
string SignatureBES::signatureMethod() const
{
    return signature->signedInfo().signatureMethod().algorithm();
}

QualifyingPropertiesType& SignatureBES::qualifyingProperties() const
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
SignedSignaturePropertiesType& SignatureBES::getSignedSignatureProperties() const
{
    QualifyingPropertiesType::SignedPropertiesOptional& spOpt = qualifyingProperties().signedProperties();
    if(!spOpt.present())
        THROW("QualifyingProperties block 'SignedProperties' is missing.");
    if(!spOpt->signedSignatureProperties().present())
        THROW("SignedProperties block 'SignedSignatureProperties' is missing.");
    return spOpt->signedSignatureProperties().get();
}
