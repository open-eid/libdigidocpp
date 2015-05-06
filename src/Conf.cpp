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
    vector<unsigned char> tslcert3();
}

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
Conf::Conf()
{
}

Conf::~Conf()
{
}

/**
 * Return global instance object
 */
Conf* Conf::instance()
{
	return INSTANCE;
}

/**
 * Init global Conf with conf
 */
void Conf::init(Conf *conf)
{
    delete INSTANCE;
    INSTANCE = conf;
}

/**
 * Returns if BDOC 1 is supported
 */
bool Conf::bdoc1Supported() const
{
    return false;
}

/**
 * Returns BDOC 2.1 Signature Policy Identifier
 */
string Conf::defaultPolicyId() const
{
    return SignatureBES::policylist.cbegin()->first;
}

/**
 * Returns libdigidoc library configuration file's (digidoc.ini) file location
 */
string Conf::libdigidocConf() const
{
#ifdef _WIN32
    return File::dllPath("digidoc.dll") + "digidoc.ini";
#else
    return string();
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
string Conf::logFile() const { return string(); }

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

/**
 * Gets Certificate store location.
 * @deprecated unused
 */
string Conf::certsPath() const { return string(); }

/**
 * Gets proxy host address.
 */
string Conf::proxyHost() const { return string(); }

/**
 * Gets proxy port number.
 */
string Conf::proxyPort() const { return string(); }

/**
 * Gets proxy user name.
 */
string Conf::proxyUser() const { return string(); }

/**
 * Gets proxy login password.
 */
string Conf::proxyPass() const { return string(); }

/**
 * Gets PKCS12 certificate file location.
 *
 * Used for signing OCSP request
 */
string Conf::PKCS12Cert() const { return File::confPath() + "73411.p12"; }

/**
 * Gets PKCS12 password.
 * @see digidoc::Conf::PKCS12Cert
 */
string Conf::PKCS12Pass() const { return "\x32\x30\x4d\x38\x58\x33\x37\x6c"; }

/**
 * Gets PKCS12 usage.
 * @see digidoc::Conf::PKCS12Cert
 */
bool Conf::PKCS12Disable() const { return false; }


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
ConfV2::ConfV2() {}
ConfV2::~ConfV2() {}

/**
 * Return global instance object
 */
ConfV2* ConfV2::instance() { return dynamic_cast<ConfV2*>(Conf::instance()); }

/**
 * Returns default time-stamp server URL
 */
string ConfV2::TSUrl() const { return TSA_URL; }

/**
 * Download new TSL list when it is expired or invalid
 */
bool ConfV2::TSLAutoUpdate() const { return true; }

/**
 * TSL cache path in local file system
 */
string ConfV2::TSLCache() const
{
#ifdef _WIN32
    return File::env("APPDATA") + "\\digidocpp\\tsl\\";
#else
    return File::env("HOME") + "/.digidocpp/tsl/";
#endif
}

/**
 * TSL master list's (LOTL) signing certificate
 * @deprecated digidoc::ConfV3::TSLCerts
 */
X509Cert ConfV2::TSLCert() const { return X509Cert(tslcert1(), X509Cert::Pem); }

/**
 * TSL master list's (LOTL) URL
 */
string ConfV2::TSLUrl() const { return TSL_URL; }


/**
 * @class digidoc::ConfV3
 * @brief Verison 3 of configuration class to add additonial parameters.
 * @see digidoc::ConfV2
 * @see @ref parameters
 */
/**
 * Version 3 config with new parameters
 */
ConfV3::ConfV3() {}
ConfV3::~ConfV3() {}

/**
 * Return global instance object
 */
ConfV3* ConfV3::instance() { return dynamic_cast<ConfV3*>(Conf::instance()); }

/**
 * Allow expired TSL lists
 */
bool ConfV3::TSLAllowExpired() const { return false; }

/**
 * TSL master list's (LOTL) signing certificates
 */
vector<X509Cert> ConfV3::TSLCerts() const
{
    return {
        X509Cert(tslcert1(), X509Cert::Pem),
        X509Cert(tslcert2(), X509Cert::Pem),
        X509Cert(tslcert3(), X509Cert::Pem),
    };
}

/**
 * Compare local TSL digest with digest published online to check for newer version
 */
bool ConfV3::TSLOnlineDigest() const { return true; }

/**
 * Gets TSL downloading connection's current timeout value
 */
int ConfV3::TSLTimeOut() const { return 10; }



/**
 * @class digidoc::ConfV4
 * @brief Verison 4 of configuration class to add additonial parameters.
 * @see digidoc::ConfV3
 * @see @ref parameters
 */
/**
 * Version 4 config with new parameters
 */
ConfV4::ConfV4() {}
ConfV4::~ConfV4() {}

/**
 * Return global instance object
 */
ConfV4* ConfV4::instance() { return dynamic_cast<ConfV4*>(Conf::instance()); }

/**
 * Redirect SSL traffic over proxy server
 * Default: false
 */
bool ConfV4::proxyForceSSL() const { return false; }

/**
 * Tunnel SSL traffic over proxy server
 * Default: false
 */
bool ConfV4::proxyTunnelSSL() const { return false; }

/**
 * Gets signature digest URI
 */
string ConfV4::signatureDigestUri() const { return digestUri(); }
