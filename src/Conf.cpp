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

#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509Cert.h"
#include "log.h"
#include "tslcerts.h"
#include "util/File.h"

#include <map>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

Conf* Conf::INSTANCE = nullptr;

/**
 * @class digidoc::Conf
 * @brief Configuration class which can reimplemented and virtual methods overloaded.
 *
 * @see @ref parameters
 */
/**
 * Configuration parameters
 */
Conf::Conf() = default;

Conf::~Conf() = default;

/**
 * Return global instance object
 */
Conf* Conf::instance() { return INSTANCE; }

/**
 * Init global Conf with conf
 */
void Conf::init(Conf *conf)
{
    delete INSTANCE;
    INSTANCE = conf;
}

/**
 * Returns libdigidoc library configuration file's (digidoc.ini) file location
 */
string Conf::libdigidocConf() const
{
#ifdef _WIN32
    return File::dllPath("digidoc.dll") + "digidoc.ini";
#else
    return {};
#endif
}

/**
 * Returns log level.
 * 0 = Error
 * 1 = Warn
 * 2 = Info
 * 3 = Debug
 */
int Conf::logLevel() const {
#ifdef NDEBUG
    return Log::InfoType;
#else
    return Log::DebugType;
#endif
}

/**
 * Gets log file location. Default log goes to standard out stream
 */
string Conf::logFile() const { return {}; }

/**
 * Return default digest type as URI
 */
string Conf::digestUri() const { return URI_SHA256; }

/**
 * Gets XSD schema files path
 */
string Conf::xsdPath() const { return File::confPath() + "schema"; }

/**
 * Returns PKCS11 driver file path
 */
string Conf::PKCS11Driver() const { return PKCS11_MODULE; }

/**
 * Return OCSP request URL
 * @param issuer OCSP issuer.
 */
string Conf::ocsp(const string &issuer) const
{
    static const map<string,string> ocsplist = {
        //Estonia Live
        {"ESTEID-SK 2011", "http://ocsp.sk.ee"},
        {"ESTEID-SK 2015", "http://ocsp.sk.ee"},
        {"EID-SK 2011", "http://ocsp.sk.ee"},
        {"EID-SK 2016", "http://ocsp.sk.ee"},
        {"KLASS3-SK 2010", "http://ocsp.sk.ee"},
        {"KLASS3-SK 2016", "http://ocsp.sk.ee"},
        //Estonia Test
        {"TEST of ESTEID-SK 2011", "http://demo.sk.ee/ocsp"},
        {"TEST of ESTEID-SK 2015", "http://demo.sk.ee/ocsp"},
        {"TEST of EID-SK 2011", "http://demo.sk.ee/ocsp"},
        {"TEST of EID-SK 2016", "http://demo.sk.ee/ocsp"},
        {"TEST of KLASS3-SK 2010", "http://demo.sk.ee/ocsp"},
        {"TEST of KLASS3-SK 2016", "http://demo.sk.ee/ocsp"},
        //Finland Test
        {"VRK CA for Test Purposes - G2", "http://demo.sk.ee/ocsp"},
        //Latvia Test - disabled, issuer name is identical with live certificates
        //{"E-ME SI (CA1)", "http://demo.sk.ee/ocsp"},
        //Lithuania Test
        {"Nacionalinis sertifikavimo centras (IssuingCA A)", "http://demo.sk.ee/ocsp"},
    };
    auto pos = ocsplist.find(issuer);
    return pos == ocsplist.end() ? string() : pos->second;
}

/**
 * Gets Certificate store location.
 * @deprecated unused
 */
string Conf::certsPath() const { return {}; }

/**
 * Gets proxy host address.
 */
string Conf::proxyHost() const { return {}; }

/**
 * Gets proxy port number.
 */
string Conf::proxyPort() const { return {}; }

/**
 * Gets proxy user name.
 */
string Conf::proxyUser() const { return {}; }

/**
 * Gets proxy login password.
 */
string Conf::proxyPass() const { return {}; }

/**
 * Gets PKCS12 certificate file location.
 *
 * Used for signing OCSP request
 */
string Conf::PKCS12Cert() const { return File::confPath() + "798.p12"; }

/**
 * Gets PKCS12 password.
 * @see digidoc::Conf::PKCS12Cert
 */
string Conf::PKCS12Pass() const { return "\x61\x50\x51\x31\x31\x74\x69\x34"; }

/**
 * Gets PKCS12 usage.
 * @see digidoc::Conf::PKCS12Cert
 */
bool Conf::PKCS12Disable() const { return false; }

/**
 * Returns default time-stamp server URL
 */
string Conf::TSUrl() const { return TSA_URL; }

/**
 * Download new TSL list when it is expired or invalid
 */
bool Conf::TSLAutoUpdate() const { return true; }

/**
 * TSL cache path in local file system
 */
string Conf::TSLCache() const
{
#ifdef _WIN32
    return File::env("APPDATA") + "\\digidocpp\\tsl\\";
#else
    return File::env("HOME") + "/.digidocpp/tsl/";
#endif
}

/**
 * TSL master list's (LOTL) URL
 */
string Conf::TSLUrl() const { return TSL_URL; }

/**
 * Allow expired TSL lists
 */
bool Conf::TSLAllowExpired() const { return false; }

/**
 * TSL master list's (LOTL) signing certificates
 */
vector<X509Cert> Conf::TSLCerts() const { return tslcerts; }

/**
 * Compare local TSL digest with digest published online to check for newer version
 */
bool Conf::TSLOnlineDigest() const { return true; }

/**
 * Gets TSL downloading connection's current timeout value
 */
int Conf::TSLTimeOut() const { return 10; }

/**
 * Redirect SSL traffic over proxy server
 * Default: false
 */
bool Conf::proxyForceSSL() const { return false; }

/**
 * Tunnel SSL traffic over proxy server
 * Default: false
 */
bool Conf::proxyTunnelSSL() const { return true; }

/**
 * Gets signature digest URI
 */
string Conf::signatureDigestUri() const { return digestUri(); }

/**
 * Gets verify service URI
 */
string Conf::verifyServiceUri() const { return SIVA_URL; }



/**
 * @class digidoc::ConfV2
 * @brief Verison 2 of configuration class to add additonial parameters.
 *
 * Conf contains virtual members and is not leaf class we need create
 * subclasses to keep binary compatibility
 * https://techbase.kde.org/Policies/Binary_Compatibility_Issues_With_C++#Adding_new_virtual_functions_to_leaf_classes
 * @see digidoc::Conf
 * @see @ref parameters
 */
/**
 * Version 2 config with new parameters
 */
ConfV2::ConfV2() = default;

ConfV2::~ConfV2() = default;

/**
 * Return global instance object
 */
ConfV2* ConfV2::instance() { return dynamic_cast<ConfV2*>(Conf::instance()); }

/**
 * Gets verify service Cert
 */
X509Cert ConfV2::verifyServiceCert() const { return X509Cert(); }



/**
 * @class digidoc::ConfV3
 * @brief Verison 3 of configuration class to add additonial parameters.
 *
 * Conf contains virtual members and is not leaf class we need create
 * subclasses to keep binary compatibility
 * https://techbase.kde.org/Policies/Binary_Compatibility_Issues_With_C++#Adding_new_virtual_functions_to_leaf_classes
 * @see digidoc::ConfV2
 * @see @ref parameters
 */
/**
 * Version 3 config with new parameters
 */
ConfV3::ConfV3() = default;

ConfV3::~ConfV3() = default;

/**
 * Return global instance object
 */
ConfV3* ConfV3::instance() { return dynamic_cast<ConfV3*>(Conf::instance()); }

/**
 * Gets verify service Cert
 */
set<string> ConfV3::OCSPTMProfiles() const { return { "1.3.6.1.4.1.10015.4.1.2" }; }
