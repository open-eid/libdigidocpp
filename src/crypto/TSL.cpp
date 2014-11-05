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

#include "crypto/TSL.h"

#include "Conf.h"
#include "log.h"
#include "crypto/Connect.h"
#include "crypto/Digest.h"
#include "util/DateTime.h"
#include "util/File.h"
#include "xml/ts_119612v010101.hxx"

#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnull-conversion"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/framework/XSECProvider.hpp>
#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif

#include <fstream>

using namespace digidoc;
using namespace digidoc::tsl;
using namespace digidoc::util;
using namespace digidoc::util::date;
using namespace std;
using namespace xercesc;
using namespace xml_schema;
namespace digidoc { vector<unsigned char> tslcert(); }

#define CONFV2(method) ConfV2::instance() ? ConfV2::instance()->method() : ConfV2().method()

TSL::TSL(const string &file, const string &_url)
    : path(file)
    , url(_url)
{
    if(file.empty())
        path = CONFV2(TSLCache) + "/" + File::fileName(TSL_URL);
    if(!File::fileExists(path))
        return;

    //TSL Type
    static const string SCHEMES_URI_V1 = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/schemes";
    static const string SCHEMES_URI_V2 = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
    static const string GENERIC_URI_V1 = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic";
    static const string GENERIC_URI_V3 = "http://uri.etsi.org/TrstSvc/TSLtype/generic/eSigDir-1999-93-EC-TrustedList";
    static const string GENERIC_URI_V2 = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
    //Service Type
    static const vector<string> SERVICETYPE = {
        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
        "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC",
        "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP",
        "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
        "http://uri.etsi.org/TrstSvc/Svctype/TSA",
        "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
        "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC",
        "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES",
    };
    //Service Status
    static const vector<string> SERVICESTATUS = {
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision",
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation",
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited",
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw",
    };

    try {
        Properties properties;
        properties.schema_location("http://uri.etsi.org/02231/v2#", Conf::instance()->xsdPath() + "/ts_119612v010101.xsd");
        tsl = trustServiceStatusList(path,
            Flags::keep_dom|Flags::dont_initialize|Flags::dont_validate, properties);

        const TSLSchemeInformationType &info = tsl->schemeInformation();
        type = info.tSLType();
        operatorName = toString(info.schemeOperatorName());
        //BIO_printf(bio, "Name: %s\n", toString(info.schemeName()).c_str());
        if(info.schemeTerritory().present())
            territory = info.schemeTerritory().get();
        issueDate = xsd2string(info.listIssueDateTime());
        if(info.nextUpdate().dateTime().present())
            nextUpdate = xsd2string(info.nextUpdate().dateTime().get());
        if(info.distributionPoints().present() && !info.distributionPoints().get().uRI().empty())
            url = info.distributionPoints().get().uRI().front();
        if(tsl->signature().present() &&
            tsl->signature()->keyInfo().present() &&
            !tsl->signature()->keyInfo()->x509Data().empty() &&
            !tsl->signature()->keyInfo()->x509Data().front().x509Certificate().empty())
        {
            const Base64Binary &base64 = tsl->signature()->keyInfo()->x509Data().front().x509Certificate().front();
            signingCert = X509Cert(vector<unsigned char>(base64.data(), base64.data() + base64.capacity()));
        }

        if((info.tSLType() == SCHEMES_URI_V1 || info.tSLType() == SCHEMES_URI_V2) &&
                info.pointersToOtherTSL().present())
        {
            for(const OtherTSLPointersType::OtherTSLPointerType &other:
                info.pointersToOtherTSL()->otherTSLPointer())
            {
                if(!other.additionalInformation().present() ||
                   !other.serviceDigitalIdentities().present() ||
                   other.additionalInformation()->mimeType() != "application/vnd.etsi.tsl+xml")
                    continue;

                Pointer p;
                p.territory = other.additionalInformation()->schemeTerritory();
                p.location = string(other.tSLLocation());
                for(const ServiceDigitalIdentityListType::ServiceDigitalIdentityType &identity:
                    other.serviceDigitalIdentities()->serviceDigitalIdentity())
                {
                    for(const DigitalIdentityListType::DigitalIdType &id: identity.digitalId())
                    {
                        if(!id.x509Certificate().present())
                            continue;
                        const Base64Binary &base64 = id.x509Certificate().get();
                        p.certs.push_back(X509Cert(vector<unsigned char>(base64.data(), base64.data() + base64.capacity())));
                    }
                }
                pointer.push_back(p);
            }
        }
        else if((info.tSLType() == GENERIC_URI_V1 || info.tSLType() == GENERIC_URI_V2 || info.tSLType() == GENERIC_URI_V3) &&
                tsl->trustServiceProviderList().present())
        {
            for(const TrustServiceProviderListType::TrustServiceProviderType &pointer:
                tsl->trustServiceProviderList()->trustServiceProvider())
            {
                for(const TSPServicesListType::TSPServiceType &service:
                    pointer.tSPServices().tSPService())
                {
                    const TSPServiceInformationType &serviceInfo = service.serviceInformation();
                    if(find(SERVICESTATUS.begin(), SERVICESTATUS.end(), serviceInfo.serviceStatus()) == SERVICESTATUS.end() ||
                        find(SERVICETYPE.begin(), SERVICETYPE.end(), serviceInfo.serviceTypeIdentifier()) == SERVICETYPE.end())
                        continue;

                    //BIO_printf(bio, "Provider name: %sn\n", toString(i->tSPInformation().tSPName()).c_str());
                    //BIO_printf(bio, " Serivce type: %s\n", serviceInfo.serviceTypeIdentifier().c_str());
                    //BIO_printf(bio, " Service name: %s\n", toString(serviceInfo.serviceName()).c_str());
                    for(const DigitalIdentityListType::DigitalIdType id:
                        serviceInfo.serviceDigitalIdentity().digitalId())
                    {
                        if(!id.x509Certificate().present())
                            continue;
                        const Base64Binary &base64 = id.x509Certificate().get();
                        certs.push_back(X509Cert(vector<unsigned char>(base64.data(), base64.data() + base64.capacity())));
                    }

                    if(!service.serviceHistory().present())
                        continue;
                    for(const ServiceHistoryInstanceType &history: service.serviceHistory()->serviceHistoryInstance())
                    {
                        if(find(SERVICESTATUS.begin(), SERVICESTATUS.end(), history.serviceStatus()) == SERVICESTATUS.end() ||
                            find(SERVICETYPE.begin(), SERVICETYPE.end(), history.serviceTypeIdentifier()) == SERVICETYPE.end())
                            continue;

                        for(const DigitalIdentityListType::DigitalIdType id:
                            history.serviceDigitalIdentity().digitalId())
                        {
                            if(!id.x509Certificate().present())
                                continue;
                            const Base64Binary &base64 = id.x509Certificate().get();
                            certs.push_back(X509Cert(vector<unsigned char>(base64.data(), base64.data() + base64.capacity())));
                        }
                    }
                }
            }
        }
    }
    catch(const Parsing &e)
    {
        stringstream s;
        s << e;
        WARN("Failed to parse TSL %s %s: %s", territory.c_str(), file.c_str(), s.str().c_str());
    }
    catch(const xsd::cxx::exception &e)
    {
        WARN("Failed to parse TSL %s %s: %s", territory.c_str(), file.c_str(), e.what());
    }
    catch(XMLException &e)
    {
        string msg = xsd::cxx::xml::transcode<char>(e.getMessage());
        WARN("Failed to parse TSL %s %s: %s", territory.c_str(), file.c_str(), msg.c_str());
    }
    catch(const Exception &e)
    {
        WARN("Failed to parse TSL %s %s: %s", territory.c_str(), file.c_str(), e.msg().c_str());
    }
    catch(...)
    {
        WARN("Failed to parse TSL %s %s", territory.c_str(), file.c_str());
    }
}

TSL::~TSL()
{
}

void TSL::parse(vector<X509Cert> &list)
{
    string cache = CONFV2(TSLCache);
    std::vector<X509Cert> cert;
    cert.push_back(X509Cert(tslcert(), X509Cert::Pem));
    File::createDirectory(cache);
    parse(list, TSL_URL, cert, cache, File::fileName(TSL_URL));
}

void TSL::parse(vector<X509Cert> &list, const string &url, const vector<X509Cert> &certs, const string &cache, const string &territory)
{
    INFO("TSL Url: %s", url.c_str());
    string path = cache + "/" + territory;
    TSL tsl(path, url);
    try {
        tsl.validate(certs);
        tsl.validateRemoteDigest();
        DEBUG("TSL %s signature is valid", territory.c_str());
    } catch(const Exception &e) {
        ERR("TSL %s status: %s", territory.c_str(), e.msg().c_str());
        bool autoupdate = CONFV2(TSLAutoUpdate);
        if(!autoupdate)
            return;

        try
        {
            ofstream file(File::encodeName(path).c_str(), ofstream::binary);
            Connect::Result r = Connect(url, "GET").exec();
            if(r.result.find("301") != string::npos) //Redirect
                r = Connect(r.headers["Location"], "GET").exec();
            file << r.content;
            file.close();
        }
        catch(const Exception &)
        {
            ERR("TSL: Failed to download %s list", tsl.territory.c_str());
            return;
        }

        tsl = TSL(path, url);
        try {
            tsl.validate(certs);
            DEBUG("TSL %s signature is valid", territory.c_str());
        } catch(const Exception &) {
            ERR("TSL %s signature is invalid", territory.c_str());
            return;
        }
    }

    if(!tsl.pointer.empty())
    {
        for(const TSL::Pointer &p: tsl.pointer)
        {
            if(p.territory == "EE" || p.territory == "FI" || p.territory == "LV" || p.territory == "LT" ||
               p.territory == "EE_T" || p.territory == "FI_T" || p.territory == "LV_T" || p.territory == "LT_T")
                parse(list, p.location, p.certs, cache, p.territory + ".xml");
        }
    }
    else
        list.insert(list.end(), tsl.certs.begin(), tsl.certs.end());
}

string TSL::toString(const InternationalNamesType &obj, const string &lang) const
{
    for(const InternationalNamesType::NameType &name: obj.name())
        if(name.lang() == lang)
            return name;
    return obj.name().front();
}

void TSL::validate(const std::vector<X509Cert> &certs)
{
    if(!tsl || nextUpdate.empty())
        THROW_CAUSE(Exception(EXCEPTION_PARAMS("Failed to parse XML")), "TSL Signature is invalid");

    time_t t = time(0);
    struct tm *time = gmtime(&t);
    if(nextUpdate.compare(0, 19, xsd2string(makeDateTime(*time))) <= 0)
        THROW_CAUSE(Exception(EXCEPTION_PARAMS("TSL is expired")), "TSL Signature is invalid");

    if(find(certs.begin(), certs.end(), signingCert) == certs.end())
        THROW("TSL Signature is signed with untrusted certificate");

    try {
        XSECProvider prov;
        DSIGSignature *sig = prov.newSignatureFromDOM(tsl->_node()->getOwnerDocument());
        //sig->setKeyInfoResolver(new XSECKeyInfoResolverDefault);
        sig->setSigningKey(OpenSSLCryptoX509(signingCert.handle()).clonePublicKey());
        //sig->registerIdAttributeName(MAKE_UNICODE_STRING("ID"));
        sig->load();
        if(!sig->verify())
        {
            string msg = xsd::cxx::xml::transcode<char>(sig->getErrMsgs());
            THROW("TLS Signature is invalid: %s", msg.c_str());
        }
    }
    catch(XSECException &e)
    {
        string msg = xsd::cxx::xml::transcode<char>(e.getMsg());
        DEBUG("%s", msg.c_str());
        THROW_CAUSE(Exception(EXCEPTION_PARAMS(msg.c_str())), "TSL Signature is invalid: %s", msg.c_str());
    }
    catch(const Exception &)
    {
        throw;
    }
    catch(...)
    {
        THROW("TSL Signature is invalid");
    }
}

void TSL::validateRemoteDigest()
{
    Connect::Result r = Connect(url.substr(0, url.size() - 3) + "sha2", "GET").exec();
    if(r.result.find("200") == string::npos)
        return;

    Digest sha(URI_RSA_SHA256);
    vector<unsigned char> buf(10240, 0);
    fstream is(path);
    while(is)
    {
        is.read((char*)&buf[0], buf.size());
        if(is.gcount() > 0)
            sha.update(&buf[0], (unsigned long)is.gcount());
    }

    vector<unsigned char> digest;
    if(r.content.size() == 64)
    {
        char data[] = "00";
        for(string::const_iterator i = r.content.cbegin(); i != r.content.end();)
        {
            data[0] = *(i++);
            data[1] = *(i++);
            digest.push_back(static_cast<unsigned char>(strtoul(data, 0, 16)));
        }
    }
    else if(r.content.size() == 32)
        digest.assign(r.content.c_str(), r.content.c_str() + r.content.size());

    if(!digest.empty() && digest != sha.result())
        THROW("Remote digest does not match");
}
