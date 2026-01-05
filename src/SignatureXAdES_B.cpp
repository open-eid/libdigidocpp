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
#include "crypto/Signer.h"
#include "crypto/X509CertStore.h"
#include "crypto/X509Crypto.h"
#include "util/DateTime.h"
#include "util/algorithm.h"
#include "util/log.h"
#include "util/File.h"

#include <xmlsec/io.h>
#include <xmlsec/errors.h>

#include <regex>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

const map<string_view,SignatureXAdES_B::Policy> SignatureXAdES_B::policylist{
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

constexpr XMLName X509IssuerName {"X509IssuerName", DSIG_NS};
constexpr XMLName X509SerialNumber {"X509SerialNumber", DSIG_NS};

thread_local ASiContainer *cb_doc {};
thread_local Exception *cb_exception {};

int initXmlSecCallback()
{
    xmlSecErrorsSetCallback([](const char *file, int line, const char *func,
                               const char *errorObject, const char *errorSubject, int reason, const char *msg) {
        auto orUnknown = [](const char *str) { return str ? str : "unknown"; };
        const char *error_msg = "";
        const char *ofile {}, *ofunc = "NULL";
        int oline {};
        for(size_t i = 0; i < XMLSEC_ERRORS_MAX_NUMBER; ++i)
        {
            if(xmlSecErrorsGetCode(i) == reason)
            {
                error_msg = xmlSecErrorsGetMsg(i);
                break;
            }
        }
        if(cb_exception)
        {
            if(reason == XMLSEC_ERRORS_R_CRYPTO_FAILED)
            {
                Exception e(orUnknown(file), line, Log::format("%s:obj=%s:subj=%s:reason=%d - %s",
                    func, orUnknown(errorObject), orUnknown(errorSubject), reason, error_msg));
                while(unsigned long error = ERR_get_error_all(&ofile, &oline, &ofunc, nullptr, nullptr))
                {
                    Exception err(ofile, oline, ERR_error_string(error, nullptr));
#ifndef LIBRESSL_VERSION_NUMBER
                    if(ERR_GET_LIB(error) == ERR_R_BIO_LIB && ERR_GET_REASON(error) == ERR_R_SYS_LIB)
                        e.setCode(Exception::ExceptionCode::HostNotFound);
#endif
                    e.addCause(err);
                }
                cb_exception->addCause(e);
            }
            else
                cb_exception->addCause({orUnknown(file), line, Log::format("%s:obj=%s:subj=%s:reason=%d - %s %s",
                    func, orUnknown(errorObject), orUnknown(errorSubject), reason, error_msg, msg)});
        }
        else
        {
            Log::out(Log::WarnType, orUnknown(file), unsigned(line), "%s:obj=%s:subj=%s:reason=%d - %s %s",
                func, orUnknown(errorObject), orUnknown(errorSubject), reason, error_msg, msg);
            if(reason == XMLSEC_ERRORS_R_CRYPTO_FAILED)
            {
                while(unsigned long error = ERR_get_error_all(&ofile, &oline, &ofunc, nullptr, nullptr))
                    Log::out(Log::WarnType, ofile, unsigned(oline), "%s: %s",
                        ofunc, ERR_error_string(error, nullptr));
            }
        }
    });

    return xmlSecIORegisterCallbacks(
        [](const char */*name*/) -> int {
            return cb_doc ? 1 : 0;
        },
        [](const char *name) -> void * {
            if(!cb_doc)
            {
                xmlSecError(__FILE__,__LINE__, "xmlSecIORegisterCallbacks", nullptr, nullptr, 0,
                    "Container is not open");
                return {};
            }

            auto find = [name](auto files) -> const DataFile* {
                for(const DataFile *file: files)
                {
                    if(file->fileName() == name)
                        return file;
                }
                return {};
            };

            const DataFile *file = find(cb_doc->dataFiles());
            if(!file && cb_doc->mediaType() == ASiC_E::MIMETYPE_ADOC)
                file = find(static_cast<ASiC_E*>(cb_doc)->metaFiles());

            if(!file)
            {
                xmlSecError(__FILE__,__LINE__, "xmlSecIORegisterCallbacks", nullptr, nullptr, 0,
                    "Failed to locate file '%s' in container", name);
                return {};
            }

            auto *is = static_cast<const DataFilePrivate*>(file)->m_is.get();
            is->clear();
            is->seekg(0);
            return is;
        },
        [](void *ctx, char *buf, int len) -> int {
            auto *is = static_cast<istream*>(ctx);
            is->read(buf, len);
            return int(is->gcount());
        },
        [](void */*ctx*/) -> int {
            return 0;
        });
}
}

Signatures::Signatures()
    : XMLDocument(create("XAdESSignatures", ASiContainer::ASIC_NS, "asic"))
{
    addNS(DSIG_NS, "ds");
    addNS(XADES_NS, "xades");
}

Signatures::Signatures(XMLDocument &&doc, string_view mediaType)
    : XMLDocument(std::move(doc))
{
    /* http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf
     * 6.2.2
     * 3) The root element of each "*signatures*.xml" content shall be either:
     * a) <asic:XAdESSignatures> as specified in clause A.5, the recommended format; or
     * b) <document-signatures> as specified in OASIS Open Document Format [9]; or
     *
     * Case container is ADoc 1.0 then handle document-signatures root element
     */
    try {
        if(mediaType == ASiC_E::MIMETYPE_ADOC && name() == "document-signatures" && ns() == OPENDOCUMENT_NS)
            validateSchema(File::path(Conf::instance()->xsdPath(), "OpenDocument_dsig.xsd"));
        else
            validateSchema(File::path(Conf::instance()->xsdPath(), "en_31916201v010101.xsd"));
    }
    catch(const Exception &e) {
        THROW_CAUSE(e, "Failed to validate signature XML");
    }
}



/**
 * Creates an empty BDOC-BES signature with mandatory XML nodes.
 */
SignatureXAdES_B::SignatureXAdES_B(const shared_ptr<Signatures> &signatures, unsigned int id, ASiContainer *container, Signer *signer)
    : signatures(signatures)
    , bdoc(container)
{
    X509Cert c = signer->cert();
    string nr = "S" + to_string(id);
    auto canonMethod = XMLDocument::C14D_ID_1_1;

    signature = *signatures + XMLName{"Signature", DSIG_NS};
    signature.setProperty("Id", nr);
    auto signedInfo = signature + "SignedInfo";
    (signedInfo + CanonicalizationMethod).setProperty("Algorithm", canonMethod);
    (signedInfo + "SignatureMethod").setProperty("Algorithm", X509Crypto(c).isRSAKey() ?
            Digest::toRsaUri(signer->method()) : Digest::toEcUri(signer->method()));

    (signature + "SignatureValue").setProperty("Id", nr + "-SIG");
    signature + "KeyInfo" + "X509Data" + "X509Certificate" = c;

    auto qualifyingProperties = signature + "Object" + QualifyingProperties;
    qualifyingProperties.setProperty("Target", "#" + nr);

    auto signedProperties = qualifyingProperties + "SignedProperties";
    signedProperties.setProperty("Id", nr + "-SignedProperties");
    auto signedSignatureProperties = signedProperties + "SignedSignatureProperties";
    signedSignatureProperties + "SigningTime" = date::to_string(time({}));

    //Fill XML-DSIG/XAdES properties
    if(signer->usingENProfile())
    {
        setSigningCertificate("SigningCertificateV2", c);
        setSignatureProductionPlace("SignatureProductionPlaceV2",
            signer->city(), signer->streetAddress(), signer->stateOrProvince(), signer->postalCode(), signer->countryName());
        setSignerRoles("SignerRoleV2", signer->signerRoles());
    }
    else
    {
        setSigningCertificate("SigningCertificate", c);
        setSignatureProductionPlace("SignatureProductionPlace",
            signer->city(), signer->streetAddress(), signer->stateOrProvince(), signer->postalCode(), signer->countryName());
        setSignerRoles("SignerRole", signer->signerRoles());
    }

    string digestMethod = Conf::instance()->digestUri();
    for(const DataFile *f: bdoc->dataFiles())
    {
        string referenceId = addReference(File::toUriPath(f->fileName()), digestMethod, f->calcDigest(digestMethod));
        addDataObjectFormat("#" + referenceId, f->mediaType());
    }

    Digest calc(digestMethod);
    signatures->c14n(calc, canonMethod, signedProperties);
    addReference("#" + nr + "-SignedProperties", calc.uri(), calc.result(), REF_TYPE, canonMethod);
}

/**
 * Load signature from the input stream.
 *
 * @param sigdata Input stream
 * @param bdoc BDOC container
 * @throws SignatureException
 */
SignatureXAdES_B::SignatureXAdES_B(const shared_ptr<Signatures> &signatures, XMLNode s, ASiContainer *container)
    : signatures(signatures)
    , signature(s)
    , bdoc(container)
{
    XMLNode object = signature/"Object";
    if(!object)
        THROW("Signature block 'Object' is missing.");
    if(object + 1)
        THROW("Signature block contains more than one 'Object' block.");

    // QualifyingProperties
    XMLNode qp = object/QualifyingProperties;
    if(!qp)
        THROW("Signature block 'QualifyingProperties' is missing.");
    if(qp + 1)
        THROW("Signature block 'Object' contains more than one 'QualifyingProperties' block.");

    XMLNode sp = qp/"SignedProperties";
    if(!sp)
        THROW("QualifyingProperties block 'SignedProperties' is missing.");
    if(!(sp/"SignedSignatureProperties"))
        THROW("SignedProperties block 'SignedSignatureProperties' is missing.");

    signingCertificate(); // assumed to throw in case this block doesn't exist

    if(id().empty())
        THROW("Signature element mandatory attribute 'Id' is missing");

    if(auto sdop = qp/"SignedProperties"/"SignedDataObjectProperties")
    {
        if(sdop/"CommitmentTypeIndication")
            DEBUG("CommitmentTypeIndicationType is not supported");
        for(const char *elem: {"AllDataObjectsTimeStamp", "IndividualDataObjectsTimeStamp"})
            if(sdop/elem)
                THROW("%s is not supported", elem);
    }

    if(auto up = qp/"UnsignedProperties")
    {
        if(up/"UnsignedDataObjectProperties")
            THROW("UnsignedDataObjectProperties are not supported");
        if(auto usp = up/"UnsignedSignatureProperties")
        {
            for(const char *elem: {"CounterSignature", "AttributeCertificateRefs", "AttributeRevocationRefs", "RefsOnlyTimeStamp",
                    "AttrAuthoritiesCertValues", "AttributeRevocationValues", "ArchiveTimeStamp"})
                if(usp/elem)
                    THROW("%s is not supported", elem);
            for(const char *elem: {"CompleteCertificateRefs", "CompleteRevocationRefs", "SigAndRefsTimeStamp", "TimeStampValidationData"})
                if(usp/elem)
                    WARN("%s are not supported", elem);
        }
    }
}

SignatureXAdES_B::~SignatureXAdES_B()
{
    signatures->erase({signature.d});
}

string_view SignatureXAdES_B::canonicalizationMethod() const noexcept
{
    return (signature/"SignedInfo"/CanonicalizationMethod)["Algorithm"];
}

string SignatureXAdES_B::policy() const
{
    if(auto id = signedSignatureProperties()/"SignaturePolicyIdentifier"/"SignaturePolicyId"/"SigPolicyId"/"Identifier";
        id && id["Qualifier"] == "OIDAsURN")
        return string(trim_prefix(id));
    return {};
}

/**
 * @return returns signature mimetype.
 */
string SignatureXAdES_B::profile() const
{
    string base = policy().empty() ? "BES" : "EPES";
    auto usp = qualifyingProperties()/"UnsignedProperties"/"UnsignedSignatureProperties";
    if(!usp)
        return base;
    if(usp/"SignatureTimeStamp")
        return (base + '/').append(
            usp/XMLName{"ArchiveTimeStamp", XADESv141_NS} ? ASiC_E::ASIC_TSA_PROFILE : ASiC_E::ASIC_TS_PROFILE);
    if(usp/"RevocationValues")
        return (base + '/').append(
            usp/XMLName{"ArchiveTimeStamp", XADESv141_NS} ? ASiC_E::ASIC_TMA_PROFILE : ASiC_E::ASIC_TM_PROFILE);
    return base;
}

string SignatureXAdES_B::trustedSigningTime() const
{
    return claimedSigningTime();
}

string SignatureXAdES_B::SPUri() const
{
    return string(trim_prefix(signedSignatureProperties()
        /"SignaturePolicyIdentifier"/"SignaturePolicyId"/"SigPolicyQualifiers"/"SigPolicyQualifier"/"SPURI"));
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

    try {
        if(!Exception::hasWarningIgnore(Exception::SignatureDigestWeak) &&
            Digest::isWeakDigest(signatureMethod()))
        {
            Exception e(EXCEPTION_PARAMS("Signature digest weak"));
            e.setCode(Exception::SignatureDigestWeak);
            exception.addCause(e);
        }

        if(profile().find(ASiC_E::ASIC_TM_PROFILE) != string::npos)
        {
            if(SPUri().empty())
                EXCEPTION_ADD(exception, "Signature SPUri is missing");
            if(auto p = policylist.find(SignatureXAdES_B::policy()); p == policylist.cend())
                EXCEPTION_ADD(exception, "Signature policy does not match BDOC 2.1 policy");
            else if(auto identifier = signedSignatureProperties()/"SignaturePolicyIdentifier"; !identifier)
                EXCEPTION_ADD(exception, "Signature policy digest is missing");
            else if(auto id = identifier/"SignaturePolicyId"; !id)
                EXCEPTION_ADD(exception, "Signature policy digest is missing");
            else
            {
#if 0 //Disabled IB-3684
                auto hash = id/"SigPolicyHash";
                auto algo = (hash/DigestMethod)["Algorithm"];
                vector<unsigned char> digest = hash/DigestValue;

                bool valid = false;
                if(algo == URI_SHA1) valid = digest == p->second.SHA1;
                else if(algo == URI_SHA224) valid = digest == p->second.SHA224;
                else if(algo == URI_SHA256) valid = digest == p->second.SHA256;
                else if(algo == URI_SHA384) valid = digest == p->second.SHA384;
                else if(algo == URI_SHA512) valid = digest == p->second.SHA512;
                else
                    EXCEPTION_ADD(exception, "Signature policy unknwon digest method");

                if(!valid)
                    EXCEPTION_ADD(exception, "Signature policy digest does not match");
#endif
            }
        }

        cb_doc = bdoc;
        cb_exception = &exception;
        bool result = XMLDocument::verifySignature(signature, &exception);
        cb_doc = {};
        cb_exception = {};
        if(!result)
            EXCEPTION_ADD(exception, "Failed to validate signature");

        auto sp = qualifyingProperties()/"SignedProperties";
        auto sdop = sp/"SignedDataObjectProperties";
        map<string,string> mimeinfo;
        if(sdop)
        {
            for(auto data = sdop/"DataObjectFormat"; data; data++)
            {
                if(auto mime = data/"MimeType")
                    mimeinfo.emplace(data["ObjectReference"], mime);
            }
        }
        else
        {
            // ADoc 1.0 does not add DataObjectProperties>DataObjectFormat elements
            if(bdoc->mediaType() != ASiC_E::MIMETYPE_ADOC)
                EXCEPTION_ADD(exception, "DataObjectFormat element is missing");
        }

        map<string,string> signatureref;
        string_view signedPropertiesId = sp["Id"];
        bool signedInfoFound = false;
        for(auto ref = signature/"SignedInfo"/"Reference"; ref; ref++)
        {
            auto uri = ref["URI"];
            if(uri.empty())
            {
                EXCEPTION_ADD(exception, "Reference URI missing");
                continue;
            }

            if(!Exception::hasWarningIgnore(Exception::ReferenceDigestWeak) &&
                Digest::isWeakDigest((ref/DigestMethod)["Algorithm"]))
            {
                Exception e(EXCEPTION_PARAMS("Reference '%.*s' digest weak", int(uri.size()), uri.data()));
                e.setCode(Exception::ReferenceDigestWeak);
                exception.addCause(e);
            }

            if(uri.front() == '#' && uri.substr(1) == signedPropertiesId && ref["Type"] == REF_TYPE)
                signedInfoFound = true;
            else if(!sdop)
                continue; // DataObjectProperties is missing, no need to match later MediaTypes
            else if(ref["Id"].empty())
                EXCEPTION_ADD(exception, "Reference '%.*s' ID  missing", int(uri.size()), uri.data());
            else
            {
                string uriPath = File::fromUriPath(uri);
                if(uriPath.front() == '/')
                    uriPath.erase(0);
                signatureref.emplace(uriPath, mimeinfo[string("#").append(ref["Id"])]);
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

        try { checkSigningCertificate(policy == POLv1); }
        catch(const Exception& e) { exception.addCause(e); }
    } catch(const Exception &e) {
        exception.addCause(e);
    } catch(...) {
        EXCEPTION_ADD(exception, "Failed to validate signature");
    }

    if(!exception.causes().empty())
        throw exception;
}

vector<unsigned char> SignatureXAdES_B::dataToSign() const
{
    Digest calc(signatureMethod());
    auto signedInfo = signature/"SignedInfo";
    signatures->c14n(calc, (signedInfo/CanonicalizationMethod)["Algorithm"], signedInfo);
    return calc.result();
}

void SignatureXAdES_B::checkCertID(XMLNode certID, const X509Cert &cert)
{
    auto issuerSerial = certID/"IssuerSerial";
    string_view certIssuerName = issuerSerial/X509IssuerName;
    string_view certSerialNumber = issuerSerial/X509SerialNumber;
    if(X509Crypto(cert).compareIssuerToString(certIssuerName) == 0 && cert.serial() == certSerialNumber)
        return checkDigest(certID/"CertDigest", cert);
    DEBUG("certIssuerName: \"%.*s\"", int(certIssuerName.size()), certIssuerName.data());
    DEBUG("x509.getCertIssuerName() \"%s\"", cert.issuerName().c_str());
    DEBUG("sertCerials = %s %.*s", cert.serial().c_str(), int(certSerialNumber.size()), certSerialNumber.data());
    THROW("Signing certificate issuer information does not match");
}

void SignatureXAdES_B::checkDigest(XMLNode digest, const vector<unsigned char> &data)
{
    auto calcDigest = Digest((digest/DigestMethod)["Algorithm"]).result(data);
    vector<unsigned char> digestValue = digest/DigestValue;
    if(digestValue == calcDigest)
        return;
    DEBUGMEM("Document cert digest", digestValue.data(), digestValue.size());
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
    if(auto sigCert = signedSignatureProperties()/"SigningCertificate")
    {
        if(auto certs = sigCert/"Cert"; certs || !(certs + 1))
            return checkCertID(certs, x509);
        THROW("Number of SigningCertificates must be 1");
    }
    if(auto sigCertV2 = signedSignatureProperties()/"SigningCertificateV2")
    {
        auto certs = sigCertV2/"Cert";
        if(!certs || certs + 1)
            THROW("Number of SigningCertificatesV2 must be 1");

        // Verify IssuerSerialV2, optional parameter
        if(vector<unsigned char> issuerSerialV2 = certs/"IssuerSerialV2"; !issuerSerialV2.empty())
        {
            if(!X509Crypto(x509).compareIssuerToDer(issuerSerialV2))
                THROW("Signing certificate issuer information does not match");
        }

        return checkDigest(certs/"CertDigest", x509);
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
        if(!contains(usage, X509Cert::NonRepudiation))
            THROW("Signing certificate does not contain NonRepudiation key usage flag");
        if(!signingCertificate().verify(noqscd))
            THROW("Unable to verify signing certificate");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE( e, "Unable to verify signing certificate" );
    }
}

void SignatureXAdES_B::addDataObjectFormat(const string &uri, const string &mime)
{
    auto sp = qualifyingProperties()/"SignedProperties";
    auto sdop = sp/"SignedDataObjectProperties";
    if(!sdop)
        sdop = sp + "SignedDataObjectProperties";

    auto dataObjectFormat = sdop + "DataObjectFormat";
    dataObjectFormat.setProperty("ObjectReference", uri);
    dataObjectFormat + "MimeType" = mime;
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
        const vector<unsigned char> &digestValue, string_view type, string_view canon)
{
    auto signedInfo = signature/"SignedInfo";
    size_t i = 0;
    for(auto reference = signedInfo/"Reference"; reference; reference++, ++i);
    auto refId = Log::format("%s-RefId%zu", id().c_str(), i);

    auto reference = signedInfo + "Reference";
    reference.setProperty("Id", refId);
    if(!type.empty())
        reference.setProperty("Type", type);
    reference.setProperty("URI", uri);

    if(!canon.empty())
        (reference + "Transforms" + "Transform").setProperty("Algorithm", canon);
    (reference + DigestMethod).setProperty("Algorithm", digestUri);
    reference + DigestValue = digestValue;

    return refId;
}

/**
 * Adds signing certificate to the signature XML. Certificate info is added to
 * Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.
 *
 * @param cert certificate that is used for signing the signature XML.
 */
void SignatureXAdES_B::setSigningCertificate(string_view name, const X509Cert& x509)
{
    // Calculate digest of the X.509 certificate.
    auto cert = signedSignatureProperties() + name.data() + "Cert";

    Digest digest;
    auto certDigest = cert + "CertDigest";
    (certDigest + DigestMethod).setProperty("Algorithm", digest.uri());
    certDigest + DigestValue = digest.result(x509);

    if(name == "SigningCertificate")
    {
        auto issuerSerial = cert + "IssuerSerial";
        issuerSerial + X509IssuerName = x509.issuerName();
        issuerSerial + X509SerialNumber = x509.serial();
    }
}

/**
 * Sets signature production place.
 *
 * @param spp signature production place.
 */
void SignatureXAdES_B::setSignatureProductionPlace(string_view name,
    const string &city, const string &streetAddress, const string &stateOrProvince,
    const string &postalCode, const string &countryName) noexcept
{
    if(city.empty() && streetAddress.empty() && stateOrProvince.empty() &&
        postalCode.empty() && countryName.empty())
        return;

    auto signatureProductionPlace = signedSignatureProperties() + name.data();
    if(!city.empty())
        signatureProductionPlace + "City" = city;
    if(name == "SignatureProductionPlaceV2" && !streetAddress.empty())
        signatureProductionPlace + "StreetAddress" = streetAddress;
    if(!stateOrProvince.empty())
        signatureProductionPlace + "StateOrProvince" = stateOrProvince;
    if(!postalCode.empty())
        signatureProductionPlace + "PostalCode" = postalCode;
    if(!countryName.empty())
        signatureProductionPlace + "CountryName" = countryName;
}

/**
 * Sets signer claimed roles to the signature.
 * NB! Only ClaimedRoles are supported. CerifiedRoles are not supported.
 *
 * @param roles signer roles.
 */
void SignatureXAdES_B::setSignerRoles(string_view name, const vector<string> &roles)
{
    if(roles.empty())
        return;
    auto claimedRoles = signedSignatureProperties() + name.data() + "ClaimedRoles";
    for(const string &role: roles)
        claimedRoles + "ClaimedRole" = role;
}

/**
 * Sets signature value.
 *
 * @param signatureValue signature value.
 */
void SignatureXAdES_B::setSignatureValue(const vector<unsigned char> &value)
{
    signatureValue() = value;
}

string SignatureXAdES_B::city() const
{
    return string(V1orV2("SignatureProductionPlace", "SignatureProductionPlaceV2")/"City");
}

string SignatureXAdES_B::stateOrProvince() const
{
    return string(V1orV2("SignatureProductionPlace", "SignatureProductionPlaceV2")/"StateOrProvince");
}

string SignatureXAdES_B::streetAddress() const
{
    return string(signedSignatureProperties()/"SignatureProductionPlaceV2"/"StreetAddress");
}

string SignatureXAdES_B::postalCode() const
{
    return string(V1orV2("SignatureProductionPlace", "SignatureProductionPlaceV2")/"PostalCode");
}

string SignatureXAdES_B::countryName() const
{
    return string(V1orV2("SignatureProductionPlace", "SignatureProductionPlaceV2")/"CountryName");
}

vector<string> SignatureXAdES_B::signerRoles() const
{
    vector<string> claimedRoles;
    for(auto claimedRole = V1orV2("SignerRole", "SignerRoleV2")/"ClaimedRoles"/"ClaimedRole"; claimedRole; claimedRole++)
        claimedRoles.emplace_back(claimedRole);
    return claimedRoles;
}

string SignatureXAdES_B::claimedSigningTime() const
{
    return string(signedSignatureProperties()/"SigningTime");
}

X509Cert SignatureXAdES_B::signingCertificate() const
{
    try {
        for(auto x509Data = signature/"KeyInfo"/"X509Data"; x509Data; x509Data++)
        {
            if(vector<unsigned char> cert = x509Data/"X509Certificate"; !cert.empty())
                return X509Cert(cert);
        }
        THROW("Signature does not contain signer certificate");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to read X509 certificate");
    }
}

string SignatureXAdES_B::id() const
{
    return string(signature["Id"]);
}

string SignatureXAdES_B::signatureMethod() const
{
    return string((signature/"SignedInfo"/"SignatureMethod")["Algorithm"]);
}

/**
* Helper that retrieves SignedSignatureProperties xades object.
*
* @return returns the XMLNode object.
*/
constexpr XMLNode SignatureXAdES_B::signedSignatureProperties() const noexcept
{
    return qualifyingProperties()/"SignedProperties"/"SignedSignatureProperties";
}

constexpr XMLNode SignatureXAdES_B::V1orV2(string_view v1, string_view v2) const noexcept
{
    auto ssp = signedSignatureProperties();
    auto elem = ssp/v1;
    return elem ? elem : ssp/v2;
}
