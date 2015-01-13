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
namespace digidoc
{
    vector<unsigned char> tslcert1();
    vector<unsigned char> tslcert2();
}

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
    return string();
#endif
}

int Conf::logLevel() const {
#ifdef NDEBUG
    return Log::InfoType;
#else
    return Log::DebugType;
#endif
}
string Conf::logFile() const { return string(); }
string Conf::digestUri() const { return URI_SHA256; }

string Conf::xsdPath() const
{
    string path = "schema";
#if defined(__APPLE__)
    path.insert(0, File::frameworkResourcesPath("ee.ria.digidocpp"));
#elif defined(_WIN32) && defined(_DEBUG)
    path.insert(0, File::dllPath("digidocppd.dll"));
#elif defined(_WIN32)
    path.insert(0, File::dllPath("digidocpp.dll"));
#else
    path.insert(0, DIGIDOCPP_CONFIG_DIR "/");
#endif
    return path;
}

string Conf::PKCS11Driver() const { return PKCS11_MODULE; }

string Conf::ocsp(const string &issuer) const
{
    static const map<string,string> ocsplist = {
        //Estonia Live
        {"ESTEID-SK 2007", "http://ocsp.sk.ee"},
        {"ESTEID-SK 2011", "http://ocsp.sk.ee"},
        {"EID-SK 2011", "http://ocsp.sk.ee"},
        {"KLASS3-SK 2010", "http://ocsp.sk.ee"},
        //Estonia Test
        {"TEST of ESTEID-SK 2007", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
        {"TEST of ESTEID-SK 2011", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
        {"TEST of KLASS3-SK 2010", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
        //Finland Test
        {"VRK CA for Test Purposes", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
        {"VRK CA for Test Purposes - G2", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
        //Latvia Test - disabled, issuer name is identical with live certificates
        //{"E-ME SI (CA1)", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
        //Lithuania Test
        {"Nacionalinis sertifikavimo centras (IssuingCA A)", "http://www.openxades.org/cgi-bin/ocsp.cgi"},
    };
    auto pos = ocsplist.find(issuer);
    return pos == ocsplist.end() ? "http://ocsp.sk.ee/_proxy" : pos->second;
}

string Conf::certsPath() const { return string(); }
string Conf::proxyHost() const { return string(); }
string Conf::proxyPort() const { return string(); }
string Conf::proxyUser() const { return string(); }
string Conf::proxyPass() const { return string(); }
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
    return path + "73411.p12";
}
string Conf::PKCS12Pass() const { return "\x32\x30\x4d\x38\x58\x33\x37\x6c"; }
bool Conf::PKCS12Disable() const { return false; }


ConfV2::ConfV2() {}
ConfV2::~ConfV2() {}
ConfV2* ConfV2::instance() { return dynamic_cast<ConfV2*>(Conf::instance()); }
string ConfV2::TSUrl() const { return TSA_URL; }
bool ConfV2::TSLAutoUpdate() const { return true; }
string ConfV2::TSLCache() const
{
#ifdef _WIN32
    return File::env("APPDATA") + "\\digidocpp\\tsl\\";
#else
    return File::env("HOME") + "/.digidocpp/tsl/";
#endif
}
X509Cert ConfV2::TSLCert() const { return X509Cert(tslcert1(), X509Cert::Pem); }
string ConfV2::TSLUrl() const { return TSL_URL; }


ConfV3::ConfV3() {}
ConfV3::~ConfV3() {}
ConfV3* ConfV3::instance() { return dynamic_cast<ConfV3*>(Conf::instance()); }
bool ConfV3::TSLAllowExpired() const { return false; }
vector<X509Cert> ConfV3::TSLCerts() const
{
    return {
        X509Cert(tslcert1(), X509Cert::Pem),
        X509Cert(tslcert2(), X509Cert::Pem)
    };
}
bool ConfV3::TSLOnlineDigest() const { return true; }
int ConfV3::TSLTimeOut() const { return 10; }
