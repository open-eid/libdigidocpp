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
#include "XMLDocument.h"
#include "crypto/Connect.h"
#include "util/DateTime.h"
#include "util/File.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <future>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

namespace digidoc {

constexpr string_view TSL_NS {"http://uri.etsi.org/02231/v2#"};
constexpr string_view ADD_NS {"http://uri.etsi.org/02231/v2/additionaltypes#"};
constexpr string_view ECC_NS {"http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"};
constexpr string_view DSIG_NS {"http://www.w3.org/2000/09/xmldsig#"};
constexpr string_view XADES_NS {"http://uri.etsi.org/01903/v1.3.2#"};
constexpr string_view XML_NS {"http://www.w3.org/XML/1998/namespace"};

constexpr array SCHEMES_URI {
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/schemes",
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists",
};

constexpr array GENERIC_URI {
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic",
    "http://uri.etsi.org/TrstSvc/TSLtype/generic/eSigDir-1999-93-EC-TrustedList",
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
};

constexpr array SERVICESTATUS_START {
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

constexpr array SERVICESTATUS_END {
    //ts_119612v010201
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked",
    //ts_119612v020201
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel",
};

constexpr array SERVICES_SUPPORTED {
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

template<typename C, typename T>
constexpr bool contains(const C &list, const T &value)
{
    return find(list.begin(), list.end(), value) != list.end();
}

}



TSL::TSL(string file)
    : XMLDocument(file, {"TrustServiceStatusList", TSL_NS})
    , schemeInformation((*this)/"SchemeInformation")
    , path(std::move(file))
{
    if(path.empty())
        return;
    if(get())
    {
        static array<const xmlChar*,2> ids { pcxmlChar("Id"), nullptr };
        xmlSecAddIDs(get(), nullptr, ids.data());
    }
    else
        WARN("Failed to parse configuration: %s", path.c_str());
}

bool TSL::activate(const string &territory)
{
    if(territory.size() != 2)
        return false;
    string cache = CONF(TSLCache);
    string path = cache + '/' + territory + ".xml";
    if(File::fileExists(path))
        return false;
    ofstream(File::encodeName(path), ofstream::binary) << ' ';
    return true;
}

vector<TSL::Service> TSL::services() const
{
    if(!contains(GENERIC_URI, type()))
        return {};

    vector<Service> services;
    for(auto pointer = (*this)/"TrustServiceProviderList"/"TrustServiceProvider"; pointer; pointer++)
    {
        for(auto service = pointer/"TSPServices"/"TSPService"; service; service++)
        {
            auto serviceInfo = service/"ServiceInformation";
            string_view type = serviceInfo/"ServiceTypeIdentifier";
            if(!contains(SERVICES_SUPPORTED, type))
                continue;
            Service s;
            s.type = type;
            s.name = toString(serviceInfo/"ServiceName");
            if(!parseInfo(serviceInfo, s))
                continue;
            for(auto history = service/"ServiceHistory"/"ServiceHistoryInstance"; history; history++)
            {
                if(string_view historyType = history/"ServiceTypeIdentifier"; historyType != s.type)
                    DEBUG("History service type is not supported %.*s", int(historyType.size()), historyType.data());
                else
                    parseInfo(history, s);
            }
            services.push_back(std::move(s));
        }
    }
    return services;
}

void TSL::debugException(const digidoc::Exception &e)
{
    Log::out(Log::DebugType, e.file().c_str(), unsigned(e.line()), "%s", e.msg().c_str());
    for(const Exception &ex: e.causes())
        debugException(ex);
}

string TSL::fetch(const string &url, const string &path)
{
    try
    {
        Connect::Result r = Connect(url, "GET", CONF(TSLTimeOut)).exec({{"Accept-Encoding", "gzip"}});
        if(!r || r.content.empty())
            THROW("HTTP status code is not 200 or content is empty");
        ofstream(File::encodeName(path), fstream::binary|fstream::trunc) << r.content;
        return r.headers["etag"];
    }
    catch(const Exception &)
    {
        ERR("TSL %s Failed to download list", url.c_str());
        throw;
    }
}

bool TSL::isExpired() const
{
    return nextUpdate() < date::to_string(time(nullptr));
}

string_view TSL::issueDate() const noexcept
{
    return schemeInformation/"ListIssueDateTime";
}

string_view TSL::nextUpdate() const noexcept
{
    return schemeInformation/"NextUpdate"/"dateTime";
}

string_view TSL::operatorName() const noexcept
{
    return toString(schemeInformation/"SchemeOperatorName");
}

vector<TSL::Service> TSL::parse()
{
    string url = CONF(TSLUrl);
    string cache = CONF(TSLCache);
    vector<X509Cert> cert = CONF(TSLCerts);
    File::createDirectory(cache);
    return parse(url, cert, cache, string(File::fileName(url)));
}

vector<TSL::Service> TSL::parse(const string &url, const vector<X509Cert> &certs,
    const string &cache, const string &territory)
{
    try {
        TSL tsl = parseTSL(url, certs, cache, territory);
        if(tsl.pointers().empty())
            return tsl.services();

        vector< future< vector<TSL::Service> > > futures;
        for(const TSL::Pointer &p: tsl.pointers())
        {
            if(!File::fileExists(cache + "/" + p.territory + ".xml"))
                continue;
            futures.push_back(async(launch::async, [p, cache]{
                return parse(p.location, p.certs, cache, p.territory + ".xml");
            }));
        }
        vector<Service> list;
        for(auto &f: futures)
        {
            vector<Service> services = f.get();
            list.insert(list.end(), make_move_iterator(services.begin()), make_move_iterator(services.end()));
        }
        return list;
    }
    catch(const Exception &e)
    {
        debugException(e);
        ERR("TSL %s Failed to validate list", territory.c_str());
        return {};
    }
}

TSL TSL::parseTSL(const string &url, const vector<X509Cert> &certs,
    const string &cache, const string &territory)
{
    string path = File::path(cache, territory);
    TSL valid;
    try {
        TSL tsl(path);
        tsl.validate(certs);
        valid = std::move(tsl);
        DEBUG("TSL %s (%llu) signature is valid", territory.c_str(), valid.sequenceNumber());

        if(valid.isExpired())
        {
            if(!CONF(TSLAutoUpdate) && CONF(TSLAllowExpired))
                return valid;
            THROW("TSL %s (%llu) is expired", territory.c_str(), valid.sequenceNumber());
        }

        if(CONF(TSLOnlineDigest) && (File::modifiedTime(valid.path) < (time(nullptr) - (60 * 60 * 24))))
        {
            if(valid.validateETag(url))
                File::updateModifiedTime(valid.path, time(nullptr));
        }

        return valid;
    } catch(const Exception &) {
        ERR("TSL %s signature is invalid", territory.c_str());
        if(!CONF(TSLAutoUpdate))
            throw;
    }

    try {
        string tmp = path + ".tmp";
        string etag = fetch(url, tmp);
        TSL tsl = TSL(std::move(tmp));
        tsl.validate(certs);
        valid = std::move(tsl);

        ofstream(File::encodeName(path), ofstream::binary|fstream::trunc)
            << ifstream(File::encodeName(valid.path), fstream::binary).rdbuf();
        error_code ec;
        filesystem::remove(filesystem::u8path(valid.path), ec);

        ofstream(File::encodeName(path + ".etag"), ofstream::trunc) << etag;

        DEBUG("TSL %s (%llu) signature is valid", territory.c_str(), valid.sequenceNumber());
    } catch(const Exception &) {
        ERR("TSL %s signature is invalid", territory.c_str());
        if(!valid)
            throw;
    }

    if(valid.isExpired() && !CONF(TSLAllowExpired))
        THROW("TSL %s (%llu) is expired", territory.c_str(), valid.sequenceNumber());

    return valid;
}

bool TSL::parseInfo(XMLNode info, Service &s)
{
    vector<Qualifier> qualifiers;
    for(auto extension = info/"ServiceInformationExtensions"/"Extension"; extension; extension++)
    {
        if(extension.property("Critical") == "true")
        {
            if(auto takenOverByType = extension/"TakenOverByType")
                WARN("Found critical extension TakenOverByType '%s'", toString(takenOverByType/"TSPName").data());
            if(extension/"ExpiredCertsRevocationInfo")
            {
                WARN("Found critical extension ExpiredCertsRevocationInfo");
                return false;
            }
        }
        if(auto additional = extension/"AdditionalServiceInformation")
            s.additional = additional/"URI";
        for(auto element = extension/XMLName{"Qualifications", ECC_NS}/"QualificationElement"; element; element++)
        {
            Qualifier &q = qualifiers.emplace_back();
            for(auto qualifier = element/"Qualifiers"/"Qualifier"; qualifier; qualifier++)
            {
                if(auto uri = qualifier.property("uri"); !uri.empty())
                    q.qualifiers.emplace_back(uri);
            }
            auto criteriaList = element/"CriteriaList";
            q.assert_ = criteriaList.property("assert");
            for(auto criteria: criteriaList)
            {
                if(criteria.name() == "KeyUsage" && criteria.ns() == ECC_NS)
                {
                    map<X509Cert::KeyUsage,bool> &usage = q.keyUsage.emplace_back();
                    for(auto bit = criteria/"KeyUsageBit"; bit; bit++)
                    {
                        auto name = bit.property("name");
                        auto value = string_view(bit) == "true";
                        if(name == "digitalSignature")
                            usage[X509Cert::DigitalSignature] = value;
                        if(name == "nonRepudiation")
                            usage[X509Cert::NonRepudiation] = value;
                        if(name == "keyEncipherment")
                            usage[X509Cert::KeyEncipherment] = value;
                        if(name == "dataEncipherment")
                            usage[X509Cert::DataEncipherment] = value;
                        if(name == "keyAgreement")
                            usage[X509Cert::KeyAgreement] = value;
                        if(name == "keyCertSign")
                            usage[X509Cert::KeyCertificateSign] = value;
                        if(name == "crlSign")
                            usage[X509Cert::CRLSign] = value;
                        if(name == "encipherOnly")
                            usage[X509Cert::EncipherOnly] = value;
                        if(name == "decipherOnly")
                            usage[X509Cert::DecipherOnly] = value;
                    }
                }
                if(criteria.name() == "PolicySet" && criteria.ns() == ECC_NS)
                {
                    vector<string> &policies = q.policySet.emplace_back();
                    for(auto policy = criteria/"PolicyIdentifier"; policy; policy++)
                    {
                        if(string_view identifier = policy/XMLName{"Identifier", XADES_NS}; !identifier.empty())
                            policies.emplace_back(identifier);
                    }
                }
            }
        }
    }
    auto certs = serviceDigitalIdentity(info, s.name);
    s.certs.insert(s.certs.cend(), make_move_iterator(certs.begin()), make_move_iterator(certs.end()));

    if(string_view serviceStatus = info/"ServiceStatus"; contains(SERVICESTATUS_START, serviceStatus))
        s.validity.emplace(info/"StatusStartingTime", std::move(qualifiers));
    else if(contains(SERVICESTATUS_END, serviceStatus))
        s.validity.emplace(info/"StatusStartingTime", nullopt);
    else
        DEBUG("Unknown service status %s", serviceStatus.data());
    return true;
}

vector<string> TSL::pivotURLs() const
{
    if(!*this)
        return {};
    auto current = File::fileName(path);
    if(size_t pos = current.find_first_of('.');
        current.find("pivot") != string::npos && pos != string::npos)
        current = current.substr(0, pos);
    vector<string> result;
    for(auto uriNode = schemeInformation/"SchemeInformationURI"/"URI"; uriNode; uriNode++)
    {
        if(uriNode.property("lang", XML_NS) != "en")
            continue;
        if(string_view uri = uriNode; uri.find("pivot") != string::npos && uri.find(current) == string::npos)
            result.emplace_back(uri);
    }
    return result;
}

vector<TSL::Pointer> TSL::pointers() const
{
    if(!contains(SCHEMES_URI, type()))
        return {};
    vector<Pointer> pointer;
    for(auto other = schemeInformation/"PointersToOtherTSL"/"OtherTSLPointer"; other; other++)
    {
        Pointer p;
        string_view mimeType;
        for(auto info = other/"AdditionalInformation"/"OtherInformation"; info; info++)
        {
            if(auto mime = info/XMLName{"MimeType", ADD_NS})
                mimeType = mime;
            if(auto territory = info/"SchemeTerritory")
                p.territory = territory;
        }
        if(mimeType != "application/vnd.etsi.tsl+xml")
            continue;
        p.location = other/"TSLLocation";
        p.certs = serviceDigitalIdentities(other, p.territory);
        if(!p.certs.empty())
            pointer.push_back(std::move(p));
    }
    return pointer;
}

unsigned long long TSL::sequenceNumber() const
{
    unsigned long long value{};
    if(string_view num = schemeInformation/"TSLSequenceNumber"; !num.empty())
        from_chars(num.data(), num.data() + num.size(), value);
    return value;
}

vector<X509Cert> TSL::serviceDigitalIdentity(XMLNode service, string_view ctx)
{
    vector<X509Cert> result;
    for(auto serviceID = service/"ServiceDigitalIdentity"; serviceID; serviceID++)
    {
        for(auto id = serviceID/"DigitalId"; id; id++)
        {
            vector<unsigned char> cert = id/"X509Certificate";
            if(cert.empty())
                continue;
            try {
                result.emplace_back(cert);
                continue;
            } catch(const Exception &e) {
                DEBUG("Failed to parse %.*s certificate, Testing also parse as PEM: %s", int(ctx.size()), ctx.data(), e.msg().c_str());
            }
            try {
                result.emplace_back(cert, X509Cert::Pem);
            } catch(const Exception &e) {
                DEBUG("Failed to parse %.*s certificate as PEM: %s", int(ctx.size()), ctx.data(), e.msg().c_str());
            }
        }
    }
    return result;
}

vector<X509Cert> TSL::serviceDigitalIdentities(XMLNode other, string_view ctx)
{
    return serviceDigitalIdentity(other/"ServiceDigitalIdentities", ctx);
}

X509Cert TSL::signingCert() const
{
    vector<unsigned char> cert = (*this)/XMLName{"Signature", DSIG_NS}/"KeyInfo"/"X509Data"/"X509Certificate";
    return cert.empty() ? X509Cert() : X509Cert(cert);
}

vector<X509Cert> TSL::signingCerts() const
{
    vector<X509Cert> result;
    for(auto other = schemeInformation/"PointersToOtherTSL"/"OtherTSLPointer"; other; other++)
    {
        vector<X509Cert> certs = serviceDigitalIdentities(other, "pivot");
        result.insert(result.cend(), make_move_iterator(certs.begin()), make_move_iterator(certs.end()));
    }
    return result;
}

string_view TSL::territory() const noexcept
{
    return schemeInformation/"SchemeTerritory";
}

string_view TSL::toString(XMLNode obj, string_view lang) noexcept
{
    for(auto n = obj/"Name"; n; n++)
        if(n.property("lang", XML_NS) == lang)
            return n;
    return obj/"Name";
}

string_view TSL::type() const noexcept
{
    return schemeInformation/"TSLType";
}

string_view TSL::url() const noexcept
{
    return schemeInformation/"DistributionPoints"/"URI";
}

void TSL::validate() const
{
    if(!*this)
        THROW("Failed to parse XML");
    auto signature = (*this)/XMLName{"Signature", DSIG_NS};
    if(!signature)
        THROW("TSL %s Failed to verify signature", territory().data());
    if(!XMLDocument::verifySignature(signature))
        THROW("TSL %s Signature is invalid", territory().data());
}

void TSL::validate(const vector<X509Cert> &certs, int recursion) const
{
    if(recursion > 3)
        THROW("PIVOT TSL recursion parsing limit");
    if(certs.empty())
        THROW("TSL trusted signing certificates empty");
    if(contains(certs, signingCert()))
    {
        validate();
        return;
    }

    vector<string> urls = pivotURLs();
    if(urls.empty())
        THROW("TSL %s Signature is signed with untrusted certificate", territory().data());

    // https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html
    string path = File::path(CONF(TSLCache), File::fileName(urls[0]));
    TSL pivot(path);
    if(!pivot)
    {
        string etag = fetch(urls[0], path);
        ofstream(File::encodeName(path + ".etag"), ofstream::trunc) << etag;
        pivot = TSL(std::move(path));
    }
    pivot.validate(certs, recursion + 1);
    validate(pivot.signingCerts(), recursion);
}

/**
 * Check if HTTP ETag header is the same as ETag of the cached TSL
 * @param url Url of the TSL
 * @param timeout Time to wait for downloading
 * @throws Exception if ETag does not match cached ETag and TSL loading should be triggered
 */
bool TSL::validateETag(const string &url)
{
    Connect::Result r;
    try {
        r = Connect(url, "HEAD", CONF(TSLTimeOut)).exec({{"Accept-Encoding", "gzip"}});
        if(!r)
            return false;
    } catch(const Exception &e) {
        debugException(e);
        DEBUG("Failed to get ETag %s", url.c_str());
        return false;
    }

    auto it = r.headers.find("etag");
    if(it == r.headers.cend())
        return validateRemoteDigest(url);

    DEBUG("Remote ETag: %s", it->second.c_str());
    ifstream is(File::encodeName(path + ".etag"));
    if(!is.is_open())
        THROW("Cached ETag does not exist");
    string etag(istreambuf_iterator<char>(is), {});
    DEBUG("Cached ETag: %s", etag.c_str());
    if(etag != it->second)
        THROW("Remote ETag does not match");
    return true;
}

bool TSL::validateRemoteDigest(const string &url)
{
    size_t pos = url.find_last_of("/.");
    if(pos == string::npos)
        return false;

    Connect::Result r;
    try
    {
        r = Connect(url.substr(0, pos) + ".sha2", "GET", CONF(TSLTimeOut)).exec();
        if(!r)
            return false;
    } catch(const Exception &e) {
        debugException(e);
        DEBUG("Failed to get remote digest %s", url.c_str());
        return false;
    }

    vector<unsigned char> digest;
    if(r.content.size() == 32)
        digest.assign(r.content.cbegin(), r.content.cend());
    else
    {
        r.content.erase(r.content.find_last_not_of(" \n\r\t") + 1);
        if(r.content.size() != 64)
            return false;
        digest = File::hexToBin(r.content);
    }

    Digest sha(URI_RSA_SHA256);
    array<unsigned char, 10240> buf{};
    ifstream is(path, ifstream::binary);
    while(is)
    {
        is.read((char*)buf.data(), streamsize(buf.size()));
        if(is.gcount() > 0)
            sha.update(buf.data(), size_t(is.gcount()));
    }

    if(!digest.empty() && digest != sha.result())
        THROW("TSL %s remote digest does not match local. TSL might be outdated", territory().data());
    return true;
}
