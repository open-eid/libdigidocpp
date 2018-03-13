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
#include "xml/ts_119612v020201_201601xsd.hxx"

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

#include <cmath>
#include <fstream>
#include <future>

using namespace digidoc;
using namespace digidoc::tsl;
using namespace digidoc::util;
using namespace digidoc::util::date;
using namespace std;
using namespace xercesc;
using namespace xml_schema;

const set<string> TSL::SCHEMES_URI = {
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/schemes",
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists",
};

const set<string> TSL::GENERIC_URI = {
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic",
    "http://uri.etsi.org/TrstSvc/TSLtype/generic/eSigDir-1999-93-EC-TrustedList",
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
};

const set<string> TSL::SERVICESTATUS_START = {
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision",
    //ts_119612v010201
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw",
    //ts_119612v020201
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
};

const set<string> TSL::SERVICESTATUS_END = {
    //ts_119612v010201
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked",
    //ts_119612v020201
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel",
};



TSL::TSL(const string &file)
    : path(file)
{
    if(file.empty())
    {
        path = CONF(TSLCache);
        path += "/" + File::fileName(CONF(TSLUrl));
    }
    if(!File::fileExists(path))
        return;

    try {
        Properties properties;
        properties.schema_location("http://uri.etsi.org/02231/v2#",
            Conf::instance()->xsdPath() + "/ts_119612v020201_201601xsd.xsd");
        tsl = trustServiceStatusList(path,
            Flags::keep_dom|Flags::dont_initialize|Flags::dont_validate, properties);
    }
    catch(const Parsing &e)
    {
        stringstream s;
        s << e;
        WARN("Failed to parse TSL %s %s: %s", territory().c_str(), file.c_str(), s.str().c_str());
    }
    catch(const xsd::cxx::exception &e)
    {
        WARN("Failed to parse TSL %s %s: %s", territory().c_str(), file.c_str(), e.what());
    }
    catch(XMLException &e)
    {
        string msg = xsd::cxx::xml::transcode<char>(e.getMessage());
        WARN("Failed to parse TSL %s %s: %s", territory().c_str(), file.c_str(), msg.c_str());
    }
    catch(const Exception &e)
    {
        WARN("Failed to parse TSL %s %s: %s", territory().c_str(), file.c_str(), e.msg().c_str());
    }
    catch(...)
    {
        WARN("Failed to parse TSL %s %s", territory().c_str(), file.c_str());
    }
}

bool TSL::activate(const string &territory)
{
    if(territory.size() != 2)
        return false;
    string cache = CONF(TSLCache);
    string path = cache + "/" + territory + ".xml";
    if(File::fileExists(path))
        return false;
    ofstream file(File::encodeName(path).c_str(), ofstream::binary);
    file << " ";
    file.close();
    return true;
}

vector<TSL::Service> TSL::services() const
{
    vector<Service> services;
    if(GENERIC_URI.find(type()) == GENERIC_URI.cend() ||
        !tsl->trustServiceProviderList().present())
        return services;

    for(const TSPType &pointer: tsl->trustServiceProviderList()->trustServiceProvider())
    {
        for(const TSPServiceType &service: pointer.tSPServices().tSPService())
        {
            static const set<string> supported{
                "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
                //"http://uri.etsi.org/TrstSvc/Svctype/CA/PKC", //???
                //"http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC", //???
                "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP",
                "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
                "http://uri.etsi.org/TrstSvc/Svctype/TSA",
                "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
                "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC", //???
                "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES", //???
            };
            const TSPServiceInformationType &serviceInfo = service.serviceInformation();
            if(supported.find(serviceInfo.serviceTypeIdentifier()) == supported.cend())
                continue;
            Service s;
            s.type = serviceInfo.serviceTypeIdentifier();
            time_t previousTime = 0;
            if(!parseInfo(serviceInfo, s, previousTime))
                continue;
            if(service.serviceHistory().present())
            {
                for(const ServiceHistoryInstanceType &history: service.serviceHistory()->serviceHistoryInstance())
                {
                    if(history.serviceTypeIdentifier() != serviceInfo.serviceTypeIdentifier())
                        DEBUG("History service type is not supported %s", history.serviceTypeIdentifier().c_str());
                    else
                        parseInfo(history, s, previousTime);
                }
            }
            services.push_back(s);
        }
    }
    return services;
}

void TSL::debugException(const digidoc::Exception &e)
{
    Log::out(Log::DebugType, e.file().c_str(), e.line(), e.msg().c_str());
    for(const Exception &ex: e.causes())
        debugException(ex);
}

bool TSL::isExpired() const
{
    return !tsl || !tsl->schemeInformation().nextUpdate().dateTime().present() ||
        xsd2time_t(tsl->schemeInformation().nextUpdate().dateTime().get()) < time(0);
}

string TSL::issueDate() const
{
    return !tsl ? string() : xsd2string(tsl->schemeInformation().listIssueDateTime());
}

string TSL::nextUpdate() const
{
    return !tsl || !tsl->schemeInformation().nextUpdate().dateTime().present() ?
        string() : xsd2string(tsl->schemeInformation().nextUpdate().dateTime().get());
}

string TSL::operatorName() const
{
    return !tsl ? string() : toString(tsl->schemeInformation().schemeOperatorName());
}

vector<TSL::Service> TSL::parse(int timeout)
{
    string url = CONF(TSLUrl);
    string cache = CONF(TSLCache);
    std::vector<X509Cert> cert = CONF(TSLCerts);
    File::createDirectory(cache);
    return parse(url, cert, cache, File::fileName(url), timeout).services;
}

TSL::Result TSL::parse(const string &url, const vector<X509Cert> &certs,
    const string &cache, const string &territory, int timeout)
{
    string path = cache + "/" + territory;
    TSL tsl(path);
    Result result = { vector<Service>(), false };
    bool valid = false;
    try {
        tsl.validate(certs);
        valid = true;
        result = { tsl.services(), tsl.isExpired() };
        if(result.expired)
            THROW("TSL %s (%llu) is expired", territory.c_str(), tsl.sequenceNumber());
        tsl.validateRemoteDigest(url, timeout);
        DEBUG("TSL %s (%llu) signature is valid", territory.c_str(), tsl.sequenceNumber());
    } catch(const Exception &e) {
        ERR("TSL %s status: %s", territory.c_str(), e.msg().c_str());
        if((CONF(TSLAutoUpdate)))
        {
            string tmp = path + ".tmp";
            try
            {
                ofstream file(File::encodeName(tmp).c_str(), ofstream::binary);
                Connect::Result r = Connect(url, "GET", timeout).exec({{"Accept-Encoding", "gzip"}}, vector<unsigned char>());
                if(r.isRedirect())
                    r = Connect(r.headers["Location"], "GET", timeout).exec({{"Accept-Encoding", "gzip"}}, vector<unsigned char>());
                if(!r.isOK() || r.content.empty())
                    THROW("HTTP status code is not 200 or content is empty");
                file << r.content;
                file.close();

                TSL tslnew = TSL(tmp);
                try {
                    tslnew.validate(certs);
                    ofstream o(File::encodeName(path).c_str(), ofstream::binary);
                    ifstream i(File::encodeName(tmp).c_str(), ifstream::binary);
                    o << i.rdbuf();
                    o.close();
                    i.close();
                    File::removeFile(tmp);
                    tsl = tslnew;
                    valid = true;
                    
                    ofstream ots(File::encodeName(path + ".ts").c_str(), ofstream::out|ofstream::trunc);
                    ots << r.headers["Last-Modified"];
                    ots.close();

                    result = { tsl.services(), tsl.isExpired() };
                    DEBUG("TSL %s (%llu) signature is valid", territory.c_str(), tsl.sequenceNumber());
                } catch(const Exception &e) {
                    debugException(e);
                    ERR("TSL %s signature is invalid", territory.c_str());
                }
            }
            catch(const Exception &e)
            {
                debugException(e);
                ERR("TSL %s Failed to download list", tsl.territory().c_str());
            }
        }
    }

    if(!valid)
        return { vector<Service>(), false };

    if(tsl.pointers().empty())
        return result;

    if(result.expired && !(CONF(TSLAllowExpired)))
        return { vector<Service>(), false };

    vector< future< Result > > futures;
    for(const TSL::Pointer &p: tsl.pointers())
    {
        if(!File::fileExists(cache + "/" + p.territory + ".xml"))
            continue;
        futures.push_back(async(launch::async, [=]{
            return parse(p.location, p.certs, cache, p.territory + ".xml", timeout);
        }));
    }
    vector<Service> list;
    for(auto &f: futures)
    {
        Result data = f.get();
        if(!data.expired || (CONF(TSLAllowExpired)))
            list.insert(list.end(), data.services.cbegin(), data.services.cend());
    }
    return { list, false };
}

template<class X>
bool TSL::parseInfo(const X &info, Service &s, time_t &previousTime)
{
    vector<Qualifier> qualifiers;
    if(info.serviceInformationExtensions().present())
    {
        for(const ExtensionType &extension: info.serviceInformationExtensions()->extension())
        {
            if(extension.critical())
            {
                if(extension.takenOverByType().present())
                    WARN("Found critical extension TakenOverByType '%s'", toString(extension.takenOverByType()->tSPName()).c_str());
                if(extension.expiredCertsRevocationInfo().present())
                {
                    WARN("Found critical extension ExpiredCertsRevocationInfo");
                    return false;
                }
            }
            if(extension.additionalServiceInformationType().present())
                s.additional = extension.additionalServiceInformationType()->uRI();
            if(extension.qualificationsType().present())
            {
                for(const QualificationElementType &element: extension.qualificationsType()->qualificationElement())
                {
                    Qualifier q;
                    for(const QualifierType &qualifier: element.qualifiers().qualifier())
                    {
                        if(qualifier.uri().present())
                            q.qualifiers.push_back(qualifier.uri().get());
                    }
                    const CriteriaListType &criteria = element.criteriaList();
                    if(criteria.assert_().present())
                        q.assert_ = criteria.assert_().get();
                    for(const KeyUsageType &keyUsage: criteria.keyUsage())
                    {
                        map<X509Cert::KeyUsage,bool> usage;
                        for(const KeyUsageBitType &bit: keyUsage.keyUsageBit())
                        {
                            if(!bit.name().present())
                                continue;
                            if(bit.name().get() == "digitalSignature")
                                usage[X509Cert::DigitalSignature] = bit;
                            if(bit.name().get() == "nonRepudiation")
                                usage[X509Cert::NonRepudiation] = bit;
                            if(bit.name().get() == "keyEncipherment")
                                usage[X509Cert::KeyEncipherment] = bit;
                            if(bit.name().get() == "dataEncipherment")
                                usage[X509Cert::DataEncipherment] = bit;
                            if(bit.name().get() == "keyAgreement")
                                usage[X509Cert::KeyAgreement] = bit;
                            if(bit.name().get() == "keyCertSign")
                                usage[X509Cert::KeyCertificateSign] = bit;
                            if(bit.name().get() == "crlSign")
                                usage[X509Cert::CRLSign] = bit;
                            if(bit.name().get() == "encipherOnly")
                                usage[X509Cert::EncipherOnly] = bit;
                            if(bit.name().get() == "decipherOnly")
                                usage[X509Cert::DecipherOnly] = bit;
                        }
                        q.keyUsage.push_back(usage);
                    }
                    for(const PoliciesListType &policySet: criteria.policySet())
                    {
                        vector<string> policies;
                        for(const xades::ObjectIdentifierType &policy: policySet.policyIdentifier())
                            policies.push_back(policy.identifier());
                        q.policySet.push_back(policies);
                    }
                    qualifiers.push_back(q);
                }
            }
        }
    }

    for(const DigitalIdentityType &id: info.serviceDigitalIdentity().digitalId())
    {
        if(!id.x509Certificate().present())
            continue;
        const Base64Binary &base64 = id.x509Certificate().get();
        s.certs.push_back(X509Cert((const unsigned char*)base64.data(), base64.capacity()));
    }

    if(SERVICESTATUS_START.find(info.serviceStatus()) != SERVICESTATUS_START.cend())
        s.validity.push_back({xsd2time_t(info.statusStartingTime()), previousTime, qualifiers});
    else if(SERVICESTATUS_END.find(info.serviceStatus()) == SERVICESTATUS_END.cend())
        DEBUG("Unknown service status %s", info.serviceStatus().c_str());
    previousTime = xsd2time_t(info.statusStartingTime());
    return true;
}

std::vector<TSL::Pointer> TSL::pointers() const
{
    std::vector<Pointer> pointer;
    if(SCHEMES_URI.find(type()) != SCHEMES_URI.cend() &&
        tsl->schemeInformation().pointersToOtherTSL().present())
    {
        for(const OtherTSLPointersType::OtherTSLPointerType &other:
            tsl->schemeInformation().pointersToOtherTSL()->otherTSLPointer())
        {
            if(!other.additionalInformation().present() ||
               !other.serviceDigitalIdentities().present() ||
               other.additionalInformation()->mimeType() != "application/vnd.etsi.tsl+xml")
                continue;

            Pointer p;
            p.territory = other.additionalInformation()->schemeTerritory();
            p.location = string(other.tSLLocation());
            for(const DigitalIdentityListType &identity: other.serviceDigitalIdentities()->serviceDigitalIdentity())
            {
                for(const DigitalIdentityType &id: identity.digitalId())
                {
                    if(!id.x509Certificate().present())
                        continue;
                    const Base64Binary &base64 = id.x509Certificate().get();
                    try {
                        p.certs.push_back(X509Cert((const unsigned char*)base64.data(), base64.capacity()));
                        continue;
                    } catch(const Exception &e) {
                        DEBUG("Failed to parse %s certificate, Testing also parse as PEM: %s", p.territory.c_str(), e.msg().c_str());
                    }
                    try {
                        p.certs.push_back(X509Cert((const unsigned char*)base64.data(), base64.capacity(), X509Cert::Pem));
                    } catch(const Exception &e) {
                        DEBUG("Failed to parse %s certificate as PEM: %s", p.territory.c_str(), e.msg().c_str());
                    }
                }
            }
            pointer.push_back(p);
        }
    }
    return pointer;
}

unsigned long long  TSL::sequenceNumber() const
{
    return !tsl ? 0 : tsl->schemeInformation().tSLSequenceNumber();
}

string TSL::territory() const
{
    return !tsl || !tsl->schemeInformation().schemeTerritory().present() ?
        string() : tsl->schemeInformation().schemeTerritory().get();
}

string TSL::toString(const InternationalNamesType &obj, const string &lang)
{
    for(const InternationalNamesType::NameType &name: obj.name())
        if(name.lang() == lang)
            return name;
    return obj.name().front();
}

string TSL::type() const
{
    return !tsl ? string() : tsl->schemeInformation().tSLType();
}

string TSL::url() const
{
    if(!tsl)
        return string();
    const TSLSchemeInformationType &info = tsl->schemeInformation();
    if(!info.distributionPoints().present() || info.distributionPoints().get().uRI().empty())
        return string();
    return info.distributionPoints().get().uRI().front();
}

void TSL::validate(const std::vector<X509Cert> &certs)
{
    if(!tsl)
        THROW("Failed to parse XML");

    X509Cert signingCert;
    if(tsl->signature().present() &&
        tsl->signature()->keyInfo().present() &&
        !tsl->signature()->keyInfo()->x509Data().empty() &&
        !tsl->signature()->keyInfo()->x509Data().front().x509Certificate().empty())
    {
        const Base64Binary &base64 = tsl->signature()->keyInfo()->x509Data().front().x509Certificate().front();
        signingCert = X509Cert((const unsigned char*)base64.data(), base64.capacity());
    }

    if(find(certs.cbegin(), certs.cend(), signingCert) == certs.cend())
        THROW("TSL %s Signature is signed with untrusted certificate", territory().c_str());

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
            THROW("TSL %s Signature is invalid: %s", territory().c_str(), msg.c_str());
        }
    }
    catch(XSECException &e)
    {
        string msg = xsd::cxx::xml::transcode<char>(e.getMsg());
        THROW("TSL %s Signature is invalid: %s", territory().c_str(), msg.c_str());
    }
    catch(const Exception &)
    {
        throw;
    }
    catch(...)
    {
        THROW("TSL %s Signature is invalid", territory().c_str());
    }
}

/**
 * Check if HTTP Last-Modified header is the same as timestamp of the cached TSL
 * @param url Url of the TSL
 * @param timeout Time to wait for downloading
 * @throws Exception if Last-Modified does not match cached ts and TSL loading should be triggered
 */
void TSL::validateLastModified(const string &url, int timeout)
{
    Connect::Result r = Connect(url, "HEAD", timeout).exec();
    if(r.isRedirect())
        r = Connect(r.headers["Location"], "HEAD", timeout).exec();
    if(r.result.find("200") == string::npos)
        return;
    
    map<string,string>::iterator it = r.headers.find("Last-Modified");
    if(it != r.headers.end())
    {
        string failureReason;
        DEBUG("Last modified: %s", it->second.c_str());
        try
        {
            tm timestamp = httpTimeToTM(it->second);
            
            string line;
            ifstream is(File::encodeName(path + ".ts"));
            if(is.is_open())
            {
                getline(is, line);
                DEBUG("Cached timestamp: %s", line.c_str());
                try
                {
                    tm time = httpTimeToTM(line);
                    if ((int)round(difftime(mkgmtime(timestamp), mkgmtime(time))))
                    {
                        failureReason = "Remote timestamp does not match";
                    }
                }
                catch(const Exception& e)
                {
                    failureReason = "Cached timestamp does not exist";
                }
            }
            else
            {
                failureReason = "Cached timestamp does not exist";
            }
            
        }
        catch(const Exception& e)
        {
            WARN("Failed to parse TSL last modified date: %s", e.msg().c_str());
        }
        
        if(!failureReason.empty())
        {
            THROW(failureReason.c_str());
        }
    }
}

void TSL::validateRemoteDigest(const std::string &url, int timeout)
{
    size_t pos = url.find_last_of("/.");
    if(!(CONF(TSLOnlineDigest)) || pos == string::npos)
        return;

    Connect::Result r;
    bool checkTimestamp = false;
    try
    {
        r= Connect(url.substr(0, pos) + ".sha2", "GET", timeout).exec();
        if(r.isRedirect())
            r = Connect(r.headers["Location"], "GET", timeout).exec();
        if(r.result.find("404") != string::npos)
            checkTimestamp = true;
        else if(r.result.find("200") == string::npos)
            return;
    } catch(const Exception &e) {
        debugException(e);
        return DEBUG("Failed to get remote digest %s", url.c_str());
    }

    if(checkTimestamp)
    {
        validateLastModified(url, timeout);
        return;
    }
    
    Digest sha(URI_RSA_SHA256);
    vector<unsigned char> buf(10240, 0);
    ifstream is(path, ifstream::binary);
    while(is)
    {
        is.read((char*)buf.data(), buf.size());
        if(is.gcount() > 0)
            sha.update(buf.data(), (unsigned long)is.gcount());
    }

    vector<unsigned char> digest;
    if(r.content.size() == 32)
        digest.assign(r.content.c_str(), r.content.c_str() + r.content.size());
    else
    {
        r.content.erase(r.content.find_last_not_of(" \n\r\t") + 1);
        if(r.content.size() != 64)
            return;
        digest = File::hexToBin(r.content);
    }

    if(!digest.empty() && digest != sha.result())
        THROW("TSL %s remote digest does not match local. TSL might be outdated", territory().c_str());
}
