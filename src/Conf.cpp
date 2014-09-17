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

#include "Conf.h"

#include "log.h"
#include "SignatureBES.h"
#include "crypto/Digest.h"
#include "crypto/X509Cert.h"
#include "util/File.h"

#include <map>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
namespace digidoc { vector<unsigned char> tslcert(); }

Conf* Conf::INSTANCE = nullptr;

Conf::Conf()
{
}

Conf::~Conf()
{
}

Conf* Conf::instance()
{
	return INSTANCE;
}

/**
 * Init global Conf with conf
 * @param conf implementation to use
 **/
void Conf::init(Conf *conf)
{
    delete INSTANCE;
    INSTANCE = conf;
}

bool Conf::bdoc1Supported() const
{
    return false;
}

string Conf::defaultPolicyId() const
{
    return SignatureBES::policylist.cbegin()->first;
}

string Conf::libdigidocConf() const
{
#ifdef _WIN32
    return File::dllPath("digidoc.dll") + "digidoc.ini";
#else
    return "";
#endif
}

int Conf::logLevel() const {
#ifdef NDEBUG
    return Log::InfoType;
#else
    return Log::DebugType;
#endif
}
string Conf::logFile() const { return ""; }
string Conf::digestUri() const { return URI_SHA256; }

string Conf::xsdPath() const
{
    string path = "schema";
#ifdef __APPLE__
    path.insert(0, File::frameworkResourcesPath("ee.ria.digidocpp"));
#endif
    return path;
}

string Conf::PKCS11Driver() const { return PKCS11_MODULE; }

string Conf::ocsp(const string &issuer) const
{
    static const map<string,string> ocsplist = [](){
        map<string,string> list;
        //Estonia Live
        list.insert(make_pair("ESTEID-SK 2007", "http://ocsp.sk.ee"));
        list.insert(make_pair("ESTEID-SK 2011", "http://ocsp.sk.ee"));
        list.insert(make_pair("KLASS3-SK 2010", "http://ocsp.sk.ee"));
        //Estonia Test
        list.insert(make_pair("TEST of ESTEID-SK 2007", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        list.insert(make_pair("TEST of ESTEID-SK 2011", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        list.insert(make_pair("TEST of KLASS3-SK 2010", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        //Finland Test
        list.insert(make_pair("VRK CA for Test Purposes", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        list.insert(make_pair("VRK CA for Test Purposes - G2", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        //Latvia Test - disabled, issuer name is identical with live certificates
        //list.insert(make_pair("E-ME SI (CA1)", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        //Lithuania Test
        list.insert(make_pair("Nacionalinis sertifikavimo centras (IssuingCA A)", "http://www.openxades.org/cgi-bin/ocsp.cgi"));
        return list;
    }();
    auto pos = ocsplist.find(issuer);
    return pos == ocsplist.end() ? "http://ocsp.sk.ee/_proxy" : pos->second;
}

string Conf::certsPath() const { return ""; }
string Conf::proxyHost() const { return ""; }
string Conf::proxyPort() const { return ""; }
string Conf::proxyUser() const { return ""; }
string Conf::proxyPass() const { return ""; }
string Conf::PKCS12Cert() const
{
#ifdef __APPLE__
    string path = File::frameworkResourcesPath("ee.ria.digidocpp");
#elif defined(_WIN32) && defined(_DEBUG)
    string path = File::dllPath("digidocppd.dll");
#elif defined(_WIN32)
    string path = File::dllPath("digidocpp.dll");
#else
    string path = DIGIDOCPP_CONFIG_DIR "/";
#endif
    return path + "37242.p12";
}
string Conf::PKCS12Pass() const { return "\x30\x75\x35\x61\x52\x55\x6b\x41"; }
bool Conf::PKCS12Disable() const { return false; }

ConfV2::ConfV2() {}
ConfV2::~ConfV2() {}
ConfV2* ConfV2::instance() { return dynamic_cast<ConfV2*>(Conf::instance()); }

string ConfV2::TSUrl() const { return TSA_URL; }



bool ConfV2::TSLAutoUpdate() const { return true; }
string ConfV2::TSLCache() const
{
#ifdef _WIN32
    string cachePath = File::env("APPDATA");
    return cachePath += "\\digidocpp\\tsl\\";
#else
    string cachePath = File::env("HOME");
    return cachePath += "/.digidocpp/tsl/";
#endif
}
X509Cert ConfV2::TSLCert() const { return X509Cert(tslcert(), X509Cert::Pem); }
string ConfV2::TSLUrl() const { return TSL_URL; }
