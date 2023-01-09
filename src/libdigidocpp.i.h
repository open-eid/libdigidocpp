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

#pragma once

#include "Container.h"
#include "XmlConf.h"
#include "crypto/X509Cert.h"
#include "util/File.h"

#include <map>
#include <optional>

namespace digidoc {

class SWIGEXPORT DigiDocConf: public digidoc::XmlConfCurrent
{
public:
    DigiDocConf(std::string _cache)
        : digidoc::XmlConfCurrent({}, _cache.empty() ? std::string() : util::File::path(_cache, "conf.xsd"))
        , cache(std::move(_cache))
        , _logFile(cache.empty() ? std::string() : cache + "/digidocpp.log") {}

    static DigiDocConf* instance() { return dynamic_cast<DigiDocConf*>(Conf::instance()); };

    int logLevel() const final { return _logLevel.value_or(digidoc::XmlConfCurrent::logLevel()); }
    std::string logFile() const final { return _logFile.value_or(digidoc::XmlConfCurrent::logFile()); }
    std::string ocsp(const std::string &issuer) const final
    {
        if(!OCSPUrls)
            return digidoc::XmlConfCurrent::ocsp(issuer);
        auto pos = OCSPUrls.value().find(issuer);
        return pos == OCSPUrls.value().cend() ? std::string() : pos->second;
    }
    std::string PKCS12Cert() const final
    {
        return cache.empty() ? digidoc::XmlConfCurrent::PKCS12Cert() :
            cache + "/" + digidoc::util::File::fileName(digidoc::XmlConfCurrent::PKCS12Cert());
    }
    std::set<std::string> OCSPTMProfiles() const final { return TMProfiles.value_or(digidoc::XmlConfCurrent::OCSPTMProfiles()); }
    std::string TSLCache() const final { return cache.empty() ? digidoc::XmlConfCurrent::TSLCache() : cache; }
    std::vector<X509Cert> TSLCerts() const final { return tslCerts.value_or(digidoc::XmlConfCurrent::TSLCerts()); }
    std::string TSLUrl() const final { return tslUrl.value_or(digidoc::XmlConfCurrent::TSLUrl()); }
    X509Cert verifyServiceCert() const final {
        if(!serviceCerts)
            return digidoc::XmlConfCurrent::verifyServiceCert();
        return serviceCerts->empty() ? X509Cert() : serviceCerts->front();
    }
    std::vector<X509Cert> verifyServiceCerts() const final { return serviceCerts.value_or(digidoc::XmlConfCurrent::verifyServiceCerts()); }
    std::string verifyServiceUri() const final { return serviceUrl.value_or(digidoc::XmlConfCurrent::verifyServiceUri()); }
    std::string xsdPath() const final { return cache.empty() ? digidoc::XmlConfCurrent::xsdPath() : cache; }

    void setLogLevel(int level) { _logLevel = level; }
    void setLogFile(std::string file) { _logFile = std::move(file); }
    void setTSLCert(const std::vector<unsigned char> &cert)
    {
        if(cert.empty()) tslCerts.emplace();
        else tslCerts = { X509Cert(cert, X509Cert::Der) };
    }
    void addTSLCert(const std::vector<unsigned char> &cert)
    {
        if(!tslCerts)
            setTSLCert(cert);
        else if(!cert.empty())
            tslCerts->emplace_back(cert, X509Cert::Der);
    }
    void setTSLUrl(std::string url) { tslUrl = std::move(url); }
    void setOCSPUrls(std::map<std::string,std::string> urls) { OCSPUrls = std::move(urls); }
    void setOCSPTMProfiles(const std::vector<std::string> &_TMProfiles)
    {
        TMProfiles = {_TMProfiles.cbegin(), _TMProfiles.cend()};
    }
    void setVerifyServiceCert(const std::vector<unsigned char> &cert)
    {
        if(cert.empty()) serviceCerts.emplace();
        else serviceCerts = { X509Cert(cert, X509Cert::Der) };
    }
    void addVerifyServiceCert(const std::vector<unsigned char> &cert)
    {
        if(!serviceCerts)
            setVerifyServiceCert(cert);
        else if(!cert.empty())
            serviceCerts->emplace_back(cert, X509Cert::Der);
    }

private:
    DISABLE_COPY(DigiDocConf);

    std::string cache;
    std::optional<int> _logLevel;
    std::optional<std::string> _logFile, serviceUrl, tslUrl;
    std::optional<std::vector<X509Cert>> tslCerts, serviceCerts;
    std::optional<std::set<std::string>> TMProfiles;
    std::optional<std::map<std::string,std::string>> OCSPUrls;
};

static void initializeLib(const std::string &appName, const std::string &path)
{
    if(!Conf::instance())
        Conf::init(new DigiDocConf(path));
    initialize(appName);
}

static void initializeLib(const std::string &appName, const std::string &userAgent, const std::string &path)
{
    if(!Conf::instance())
        Conf::init(new DigiDocConf(path));
    initialize(appName, userAgent);
}

}
