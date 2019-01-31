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
    std::string PKCS12Cert() const override
    {
        return cache.empty() ? digidoc::XmlConfCurrent::PKCS12Cert() :
            cache + "/" + digidoc::util::File::fileName(digidoc::XmlConfCurrent::PKCS12Cert());
    }
    std::set<std::string> OCSPTMProfiles() const override { return TMProfiles.empty() ? digidoc::XmlConfCurrent::OCSPTMProfiles() : TMProfiles; }
    std::string TSLCache() const override { return cache.empty() ? digidoc::XmlConfCurrent::TSLCache() : cache; }
    std::vector<X509Cert> TSLCerts() const override { return tslCerts.empty() ? digidoc::XmlConfCurrent::TSLCerts() : tslCerts; };
    std::string TSLUrl() const override { return tslUrl.empty() ? digidoc::XmlConfCurrent::TSLUrl() : tslUrl; }
    std::string xsdPath() const override { return cache.empty() ? digidoc::XmlConfCurrent::xsdPath() : cache; }

    void setTSLCert(const std::vector<unsigned char> &tslCert)
    {
        if(tslCert.empty()) tslCerts.clear();
        else tslCerts = { X509Cert(tslCert, X509Cert::Der) };
    }
    void setTSLUrl(std::string _tslUrl) { tslUrl = std::move(_tslUrl); }
    void setOCSPTMProfiles(const std::vector<std::string> &_TMProfiles)
    {
        for(const std::string &profile: _TMProfiles)
            TMProfiles.emplace(profile);
        if(_TMProfiles.empty())
            TMProfiles.clear();
    }

private:
    std::string cache, tslUrl;
    std::vector<X509Cert> tslCerts;
    std::set<std::string> TMProfiles;
};

static void initializeLib(const std::string &appName, const std::string &path)
{
    if(!Conf::instance())
        Conf::init(new DigiDocConf(path));
    initialize(appName);
}

}
