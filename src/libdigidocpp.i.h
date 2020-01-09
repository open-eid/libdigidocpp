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

namespace digidoc {

class SWIGEXPORT DigiDocConf: public digidoc::XmlConfCurrent
{
public:
    DigiDocConf(std::string _cache)
        : digidoc::XmlConfCurrent(std::string(), _cache.empty() ? std::string() : util::File::path(_cache, "conf.xsd"))
        , cache(std::move(_cache)) {}

    static DigiDocConf* instance() { return dynamic_cast<DigiDocConf*>(Conf::instance()); };

    int logLevel() const override { return 4; }
    std::string logFile() const override { return cache.empty() ? digidoc::XmlConfCurrent::logFile() : cache + "/digidocpp.log"; }
    std::string ocsp(const std::string &issuer) const override
    {
        auto pos = OCSPUrls.find(issuer);
        return pos == OCSPUrls.end() ? std::string() : pos->second;
    }
    std::string PKCS12Cert() const override
    {
        return cache.empty() ? digidoc::XmlConfCurrent::PKCS12Cert() :
            cache + "/" + digidoc::util::File::fileName(digidoc::XmlConfCurrent::PKCS12Cert());
    }
    std::set<std::string> OCSPTMProfiles() const override { return TMProfiles.empty() ? digidoc::XmlConfCurrent::OCSPTMProfiles() : TMProfiles; }
    std::string TSLCache() const override { return cache.empty() ? digidoc::XmlConfCurrent::TSLCache() : cache; }
    std::vector<X509Cert> TSLCerts() const override { return tslCerts.empty() ? digidoc::XmlConfCurrent::TSLCerts() : tslCerts; };
    std::string TSLUrl() const override { return tslUrl.empty() ? digidoc::XmlConfCurrent::TSLUrl() : tslUrl; }
    X509Cert verifyServiceCert() const override { return !serviceCert ? digidoc::XmlConfCurrent::verifyServiceCert() : serviceCert; }
    std::string verifyServiceUri() const override { return serviceUrl.empty() ? digidoc::XmlConfCurrent::verifyServiceUri() : serviceUrl; }
    std::string xsdPath() const override { return cache.empty() ? digidoc::XmlConfCurrent::xsdPath() : cache; }

    void setTSLCert(const std::vector<unsigned char> &cert)
    {
        if(cert.empty()) tslCerts.clear();
        else tslCerts = { X509Cert(cert, X509Cert::Der) };
    }
    void addTSLCert(const std::vector<unsigned char> &cert)
    {
        if(!cert.empty())
            tslCerts.push_back(X509Cert(cert, X509Cert::Der));
    }
    void setTSLUrl(std::string url) { tslUrl = std::move(url); }
    void setOCSPUrls(std::map<std::string,std::string> urls) { OCSPUrls = urls; }
    void setOCSPTMProfiles(const std::vector<std::string> &_TMProfiles)
    {
        for(const std::string &profile: _TMProfiles)
            TMProfiles.emplace(profile);
        if(_TMProfiles.empty())
            TMProfiles.clear();
    }
    void setVerifyServiceCert(const std::vector<unsigned char> &cert) { serviceCert = X509Cert(cert.data(), cert.size(), X509Cert::Der); }
    void setVerifyServiceUri(std::string url) { serviceUrl = std::move(url); }

private:
    std::string cache, tslUrl, serviceUrl;
    std::vector<X509Cert> tslCerts;
    std::set<std::string> TMProfiles;
    std::map<std::string,std::string> OCSPUrls;
    X509Cert serviceCert;
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
