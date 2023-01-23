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

#include "SignatureXAdES_LTA.h"

#include "ASiC_E.h"
#include "Conf.h"
#include "crypto/Digest.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "util/log.h"
#include "xml/SecureDOMParser.h"
#include "xml/XAdES01903v141-201601.hxx"
#include "xml/URIResolver.h"

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_CLANG("-Wnull-conversion")
DIGIDOCPP_WARNING_DISABLE_GCC("-Wunused-parameter")
DIGIDOCPP_WARNING_DISABLE_MSVC(4005)
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/utils/XSECBinTXFMInputStream.hpp>
DIGIDOCPP_WARNING_POP

using namespace digidoc;
using namespace digidoc::dsig;
using namespace digidoc::util;
using namespace digidoc::xades;
using namespace xercesc;
using namespace xml_schema;
using namespace std;

void SignatureXAdES_LTA::calcArchiveDigest(Digest *digest,
    std::string_view canonicalizationMethod) const
{
    try {
        stringstream ofs;
        saveToXml(ofs);
        XSECProvider prov;
        auto deleteSig = [&](DSIGSignature *s) { prov.releaseSignature(s); };
        auto doc = SecureDOMParser().parseIStream(ofs);
        unique_ptr<DSIGSignature,decltype(deleteSig)> sig(prov.newSignatureFromDOM(doc.get()), deleteSig);
        unique_ptr<URIResolver> uriresolver = make_unique<URIResolver>(bdoc);
        unique_ptr<XSECKeyInfoResolverDefault> keyresolver = make_unique<XSECKeyInfoResolverDefault>();
        sig->setURIResolver(uriresolver.get());
        sig->setKeyInfoResolver(keyresolver.get());
        sig->registerIdAttributeName((const XMLCh*)u"ID");
        sig->setIdByAttributeName(true);
        sig->load();

        safeBuffer m_errStr;
        m_errStr.sbXMLChIn((const XMLCh*)u"");

        XMLByte buf[1024];
        DSIGReferenceList *list = sig->getReferenceList();
        for(size_t i = 0; i < list->getSize(); ++i)
        {
            XSECBinTXFMInputStream *stream = list->item(i)->makeBinInputStream();
            for(XMLSize_t size = stream->readBytes(buf, 1024); size > 0;
                 size = stream->readBytes(buf, 1024))
                digest->update(buf, size);
            delete stream;
        }
    }
    catch(const Parsing &e)
    {
        stringstream s;
        s << e;
        THROW("Failed to calculate digest: %s", s.str().c_str());
    }
    catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
        THROW("Failed to calculate digest");
    }
    catch(const XSECException &e)
    {
        try {
            string result = xsd::cxx::xml::transcode<char>(e.getMsg());
            THROW("Failed to calculate digest: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to calculate digest");
        }
    }
    catch(XMLException &e)
    {
        try {
            string result = xsd::cxx::xml::transcode<char>(e.getMessage());
            THROW("Failed to calculate digest: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to calculate digest");
        }
    }
    catch(...)
    {
        THROW("Failed to calculate digest");
    }

    for(auto name: {u"SignedInfo", u"SignatureValue", u"KeyInfo"})
    {
        try {
            calcDigestOnNode(digest, URI_ID_DSIG, name, canonicalizationMethod);
        } catch(const Exception &) {
            DEBUG("Element %s not found", xsd::cxx::xml::transcode<char>(name).data());
        }
    }

    for(auto name: {
             u"SignatureTimeStamp",
             u"CounterSignature",
             u"CompleteCertificateRefs",
             u"CompleteRevocationRefs",
             u"AttributeCertificateRefs",
             u"AttributeRevocationRefs",
             u"CertificateValues",
             u"RevocationValues",
             u"SigAndRefsTimeStamp",
             u"RefsOnlyTimeStamp" })
    {
        try {
            calcDigestOnNode(digest, XADES_NAMESPACE, name, canonicalizationMethod);
        } catch(const Exception &) {
            DEBUG("Element %s not found", xsd::cxx::xml::transcode<char>(name).data());
        }
    }

    try {
        calcDigestOnNode(digest, XADESv141_NAMESPACE, u"TimeStampValidationData", canonicalizationMethod);
    } catch(const Exception &) {
        DEBUG("Element TimeStampValidationData not found");
    }
    //ds:Object
}

void SignatureXAdES_LTA::extendSignatureProfile(const std::string &profile)
{
    SignatureXAdES_LT::extendSignatureProfile(profile);
    if(profile != ASiC_E::ASIC_TSA_PROFILE && profile != ASiC_E::ASIC_TMA_PROFILE)
        return;

    Digest calc;
    calcArchiveDigest(&calc, signature->signedInfo().canonicalizationMethod().algorithm());
    TS tsa(CONF(TSUrl), calc, " Profile: " + profile);
    vector<unsigned char> der = tsa;
    auto &usp = unsignedSignatureProperties();
    auto ts = make_unique<xadesv141::ArchiveTimeStampType>();
    ts->id(id() + "-A0");
    ts->canonicalizationMethod(signature->signedInfo().canonicalizationMethod());
    ts->encapsulatedTimeStamp().push_back(make_unique<EncapsulatedPKIDataType>(
        Base64Binary(der.data(), der.size(), der.size(), false)));
    usp.archiveTimeStampV141().push_back(move(ts));
    usp.contentOrder().push_back(UnsignedSignaturePropertiesType::ContentOrderType(
        UnsignedSignaturePropertiesType::archiveTimeStampV141Id,
        usp.archiveTimeStampV141().size() - 1));
    sigdata_.clear();
}

TS SignatureXAdES_LTA::tsaFromBase64() const
{
    try {
        if(unsignedSignatureProperties().archiveTimeStampV141().empty())
            return {};
        const xadesv141::ArchiveTimeStampType &ts = unsignedSignatureProperties().archiveTimeStampV141().front();
        if(ts.encapsulatedTimeStamp().empty())
            return {};
        const GenericTimeStampType::EncapsulatedTimeStampType &bin =
                ts.encapsulatedTimeStamp().front();
        return {(const unsigned char*)bin.data(), bin.size()};
    } catch(const Exception &) {}
    return {};
}

X509Cert SignatureXAdES_LTA::ArchiveTimeStampCertificate() const
{
    return tsaFromBase64().cert();
}

string SignatureXAdES_LTA::ArchiveTimeStampTime() const
{
    return date::to_string(tsaFromBase64().time());
}

void SignatureXAdES_LTA::validate(const string &policy) const
{
    Exception exception(EXCEPTION_PARAMS("Signature validation"));
    try {
        SignatureXAdES_LT::validate(policy);
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

        verifyTS(ts, exception, [this](Digest *digest, std::string_view canonicalizationMethod) {
            calcArchiveDigest(digest, canonicalizationMethod);
        });
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}
