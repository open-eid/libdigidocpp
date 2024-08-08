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

#include "XmlConf.h"

#include "XMLDocument.h"
#include "crypto/X509Cert.h"
#include "util/File.h"

#include <map>
#include <optional>

using namespace std;
using namespace digidoc;
using namespace digidoc::util;

namespace digidoc
{

template <class A>
class XmlConfParam: public optional<A>
{
public:
    constexpr XmlConfParam(std::string_view _name, A &&def = {}) noexcept
        : name(_name), defaultValue(std::move(def))
    {}

    template <class V>
    constexpr void setValue(V other)
    {
        if(defaultValue == other)
            optional<A>::reset();
        else
            optional<A>::emplace(std::forward<V>(other));
    }

    const string_view name;
    const A defaultValue;
    bool locked = false;
};

class XmlConf::Private
{
public:
    Private(Conf *self, const string &path, string schema);

    auto loadDoc(const string &path) const;
    void init(const string &path, bool global);
    template <class A>
    void setUserConf(XmlConfParam<A> &param, A value);

    XmlConfParam<int> logLevel;
    XmlConfParam<string> logFile;
    XmlConfParam<string> digestUri;
    XmlConfParam<string> signatureDigestUri;
    XmlConfParam<string> PKCS11Driver;
    XmlConfParam<bool> proxyForceSSL;
    XmlConfParam<bool> proxyTunnelSSL;
    XmlConfParam<string> proxyHost;
    XmlConfParam<string> proxyPort;
    XmlConfParam<string> proxyUser;
    XmlConfParam<string> proxyPass;
    XmlConfParam<string> TSUrl;
    XmlConfParam<bool> TSLAutoUpdate;
    XmlConfParam<string> TSLCache;
    XmlConfParam<bool> TSLOnlineDigest;
    XmlConfParam<int> TSLTimeOut;
    XmlConfParam<string> verifyServiceUri;
    map<string,string> ocsp;
    set<string> ocspTMProfiles;

    string SCHEMA_LOC;
    static const string USER_CONF_LOC;
};
}

const string XmlConf::Private::USER_CONF_LOC = File::path(File::digidocppPath(), "digidocpp.conf");

XmlConf::Private::Private(Conf *self, const string &path, string schema)
    : logLevel{"log.level", self->Conf::logLevel()}
    , logFile{"log.file", self->Conf::logFile()}
    , digestUri{"signer.digestUri", self->Conf::digestUri()}
    , signatureDigestUri{"signer.signatureDigestUri", self->Conf::digestUri()}
    , PKCS11Driver{"pkcs11.driver.path", self->Conf::PKCS11Driver()}
    , proxyForceSSL{"proxy.forceSSL", self->Conf::proxyForceSSL()}
    , proxyTunnelSSL{"proxy.tunnelSSL", self->Conf::proxyTunnelSSL()}
    , proxyHost{"proxy.host", self->Conf::proxyHost()}
    , proxyPort{"proxy.port", self->Conf::proxyPort()}
    , proxyUser{"proxy.user", self->Conf::proxyUser()}
    , proxyPass{"proxy.pass", self->Conf::proxyPass()}
    , TSUrl{"ts.url", self->Conf::TSUrl()}
    , TSLAutoUpdate{"tsl.autoupdate", self->Conf::TSLAutoUpdate()}
    , TSLCache{"tsl.cache", self->Conf::TSLCache()}
    , TSLOnlineDigest{"tsl.onlineDigest", self->Conf::TSLOnlineDigest()}
    , TSLTimeOut{"tsl.timeOut", self->Conf::TSLTimeOut()}
    , verifyServiceUri{"verify.serivceUri", self->Conf::verifyServiceUri()}
    , SCHEMA_LOC(std::move(schema))
{
    if(path.empty())
    {
        init(File::path(File::confPath(), "digidocpp.conf"), true);
        init(USER_CONF_LOC, false);
    }
    else
        init(path, true);
}

auto XmlConf::Private::loadDoc(const string &path) const
{
    LIBXML_TEST_VERSION
    auto doc = XMLDocument(path, {"configuration"});
    if(!doc)
    {
        WARN("Failed to parse configuration: %s", path.c_str());
        return doc;
    }
    try {
        doc.validateSchema(SCHEMA_LOC);
    } catch(const Exception & /*e*/) {
        WARN("Failed to validate configuration: %s (%s)", path.c_str(), SCHEMA_LOC.c_str());
        doc.reset();
    }
    return doc;
}

/**
 * Load and parse xml from path. Initialize XmlConf member variables from xml.
 * @param path to use for initializing conf
 */
void XmlConf::Private::init(const string& path, bool global)
{
    DEBUG("XmlConfPrivate::init(%s, %u)", path.c_str(), global);
    if(File::fileSize(path) == 0)
        return;

    auto doc = loadDoc(path);
    if(!doc)
        return;
    for(XMLNode elem: doc)
    {
        if(elem.name() == "ocsp")
        {
            ocsp.emplace(elem["issuer"], elem);
            continue;
        }
        auto paramName = elem["name"];
        string_view value = elem;
        optional<bool> lock;
        if(auto val = elem["lock"]; !val.empty())
            lock = val == "true";
        auto setValue = [&](auto &param) {
            if(paramName != param.name)
                return false;
            if(global && lock.has_value()) param.locked = lock.value();
            if(global || !param.locked)
            {
                using type = typename remove_reference_t<decltype(param)>::value_type;
                if constexpr(is_same_v<type,bool>)
                    param.setValue(value == "true");
                else if constexpr(is_integral_v<type>)
                    param.setValue(atoi(value.data()));
                else
                    param.setValue(value);
            }
            return true;
        };
        if(setValue(logLevel) ||
            setValue(logFile) ||
            setValue(digestUri) ||
            setValue(signatureDigestUri) ||
            setValue(PKCS11Driver) ||
            setValue(proxyForceSSL) ||
            setValue(proxyTunnelSSL) ||
            setValue(proxyHost) ||
            setValue(proxyPort) ||
            setValue(proxyUser) ||
            setValue(proxyPass) ||
            setValue(TSUrl) ||
            setValue(TSLAutoUpdate) ||
            setValue(TSLCache) ||
            setValue(TSLOnlineDigest) ||
            setValue(TSLTimeOut) ||
            setValue(verifyServiceUri))
            continue;
        if(paramName == "ocsp.tm.profile" && global)
            ocspTMProfiles.emplace(value);
    }
}

/**
 * Sets any parameter in a user configuration file. Also creates a configuration file if it is missing.
 *
 * @param param name of parameter that needs to be changed or created.
 * @param defined default value
 * @param value value for changing or adding to a given parameter. If value is an empty string, the walue for a given parameter will be erased.
 * @throws Exception exception is thrown if reading, writing or creating of a user configuration file fails.
 */
template<class A>
void XmlConf::Private::setUserConf(XmlConfParam<A> &param, A value)
{
    if(param.locked)
        return;
    param.setValue(std::forward<A>(value));

    auto doc = loadDoc(USER_CONF_LOC);
    if(!doc)
    {
        doc = XMLDocument::create("configuration");
        doc.setProperty("noNamespaceSchemaLocation", SCHEMA_LOC,
            doc.addNS("http://www.w3.org/2001/XMLSchema-instance", "xsi"));
    }

    // Remove old entries
    for(auto i = doc.begin(); i != doc.end();)
    {
        if(XMLNode n{*i}; n.name() == "param" && n["name"] == param.name)
            i = XMLNode::erase(i);
        else
            ++i;
    }

    if(param.has_value())
    {
        XMLNode p = doc+"param";
        p.setProperty("name", param.name);
        if constexpr(is_same_v<A,bool>)
            p = param.value() ? "true" : "false";
        else if constexpr(is_integral_v<A>)
            p = to_string(param.value());
        else
            p = param.value();
    }

    File::createDirectory(File::directory(USER_CONF_LOC));
    if(!doc.save(USER_CONF_LOC))
        ERR("Failed to save configuration: %s (%s)", USER_CONF_LOC.c_str(), SCHEMA_LOC.c_str());
}


/**
 * @typedef digidoc::XmlConfCurrent
 * Reference to latest XmlConfV5 class
 */

/**
 * @class digidoc::XmlConf
 * @brief XML Configuration class
 * @deprecated Use digidoc::XmlConfV5
 * @see digidoc::Conf
 */
XmlConf::XmlConf(const string &path, const string &schema)
    : d(make_unique<XmlConf::Private>(this, path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
{}
XmlConf::~XmlConf() = default;

/**
 * @copydoc digidoc::Conf::instance()
 */
XmlConf* XmlConf::instance() { return dynamic_cast<XmlConf*>(Conf::instance()); }

/**
 * @class digidoc::XmlConfV2
 * @brief Version 2 of XML Configuration class
 * @deprecated Use digidoc::XmlConfV5
 * @see digidoc::ConfV2
 */
XmlConfV2::XmlConfV2(const string &path, const string &schema)
    : d(make_unique<XmlConf::Private>(this, path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
{}
XmlConfV2::~XmlConfV2() = default;

/**
 * @copydoc digidoc::Conf::instance()
 */
XmlConfV2* XmlConfV2::instance() { return dynamic_cast<XmlConfV2*>(Conf::instance()); }

/**
 * @class digidoc::XmlConfV3
 * @brief Version 3 of XML Configuration class
 * @deprecated Use digidoc::XmlConfV5
 * @see digidoc::ConfV3
 */
XmlConfV3::XmlConfV3(const string &path, const string &schema)
    : d(make_unique<XmlConf::Private>(this, path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
{}
XmlConfV3::~XmlConfV3() = default;

/**
 * @copydoc digidoc::Conf::instance()
 */
XmlConfV3* XmlConfV3::instance() { return dynamic_cast<XmlConfV3*>(Conf::instance()); }

/**
 * @class digidoc::XmlConfV4
 * @brief Version 4 of XML Configuration class
 * @deprecated Use digidoc::XmlConfV5
 * @see digidoc::ConfV4
 */
/**
 * Initialize xml conf from path
 */
XmlConfV4::XmlConfV4(const string &path, const string &schema)
    : d(make_unique<XmlConf::Private>(this, path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
{}
XmlConfV4::~XmlConfV4() = default;

/**
 * @copydoc digidoc::Conf::instance()
 */
XmlConfV4* XmlConfV4::instance() { return dynamic_cast<XmlConfV4*>(Conf::instance()); }

/**
 * @class digidoc::XmlConfV5
 * @brief Version 5 of XML Configuration class
 * @see digidoc::ConfV5
 */
/**
 * Initialize xml conf from path
 */
XmlConfV5::XmlConfV5(const string &path, const string &schema)
    : d(make_unique<XmlConf::Private>(this, path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
{}
XmlConfV5::~XmlConfV5() = default;

/**
 * @copydoc digidoc::Conf::instance()
 */
XmlConfV5* XmlConfV5::instance() { return dynamic_cast<XmlConfV5*>(Conf::instance()); }



#define GET1EX(TYPE, PROP, VALUE) \
TYPE XmlConf::PROP() const { return VALUE; } \
TYPE XmlConfV2::PROP() const { return VALUE; } \
TYPE XmlConfV3::PROP() const { return VALUE; } \
TYPE XmlConfV4::PROP() const { return VALUE; } \
TYPE XmlConfV5::PROP() const { return VALUE; }

#define GET1(TYPE, PROP) \
GET1EX(TYPE, PROP, d->PROP.value_or(d->PROP.defaultValue))

#define SET1EX(TYPE, SET, VALUE) \
void XmlConf::SET(TYPE value) { VALUE; } \
void XmlConfV2::SET(TYPE value) { VALUE; } \
void XmlConfV3::SET(TYPE value) { VALUE; } \
void XmlConfV4::SET(TYPE value) { VALUE; } \
void XmlConfV5::SET(TYPE value) { VALUE; }

#define SET1(TYPE, SET, PROP) \
SET1EX(TYPE, SET, d->setUserConf(d->PROP, value))

#define SET1CONSTEX(TYPE, SET, VALUE) \
void XmlConf::SET(const TYPE &value) { VALUE; } \
void XmlConfV2::SET(const TYPE &value) { VALUE; } \
void XmlConfV3::SET(const TYPE &value) { VALUE; } \
void XmlConfV4::SET(const TYPE &value) { VALUE; } \
void XmlConfV5::SET(const TYPE &value) { VALUE; }

#define SET1CONST(TYPE, SET, PROP) \
SET1CONSTEX(TYPE, SET, d->setUserConf(d->PROP, value))

GET1(int, logLevel)
GET1(string, logFile)
GET1(string, PKCS11Driver)
GET1(string, proxyHost)
GET1(string, proxyPort)
GET1(string, proxyUser)
GET1(string, proxyPass)
GET1(bool, proxyForceSSL)
GET1(bool, proxyTunnelSSL)
GET1EX(string, PKCS12Cert, Conf::PKCS12Cert())
GET1EX(string, PKCS12Pass, Conf::PKCS12Cert())
GET1EX(bool, PKCS12Disable, Conf::PKCS12Disable())
GET1(string, TSUrl)
GET1(bool, TSLAutoUpdate)
GET1(string, TSLCache)
GET1(string, digestUri)
GET1(string, signatureDigestUri)
GET1(bool, TSLOnlineDigest)
GET1(int, TSLTimeOut)
GET1(string, verifyServiceUri)

string XmlConf::ocsp(const string &issuer) const
{
    auto i = d->ocsp.find(issuer);
    return i != d->ocsp.end() ? i->second : Conf::ocsp(issuer);
}

string XmlConfV2::ocsp(const string &issuer) const
{
    auto i = d->ocsp.find(issuer);
    return i != d->ocsp.end() ? i->second : Conf::ocsp(issuer);
}

string XmlConfV3::ocsp(const string &issuer) const
{
    auto i = d->ocsp.find(issuer);
    return i != d->ocsp.end() ? i->second : Conf::ocsp(issuer);
}

string XmlConfV4::ocsp(const string &issuer) const
{
    auto i = d->ocsp.find(issuer);
    return i != d->ocsp.end() ? i->second : Conf::ocsp(issuer);
}

string XmlConfV5::ocsp(const string &issuer) const
{
    auto i = d->ocsp.find(issuer);
    return i != d->ocsp.end() ? i->second : Conf::ocsp(issuer);
}

/**
 * @fn void digidoc::XmlConf::setTSLOnlineDigest(bool enable)
 * Enables/Disables online digest check
 * @throws Exception exception is thrown if saving a TSL online digest into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setTSLOnlineDigest(bool enable)
 * @copydoc digidoc::XmlConf::setTSLOnlineDigest(bool enable)
 */
/**
 * @fn void digidoc::XmlConfV3::setTSLOnlineDigest(bool enable)
 * @copydoc digidoc::XmlConf::setTSLOnlineDigest(bool enable)
 */
/**
 * @fn void digidoc::XmlConfV4::setTSLOnlineDigest(bool enable)
 * @copydoc digidoc::XmlConf::setTSLOnlineDigest(bool enable)
 */
/**
 * @fn void digidoc::XmlConfV5::setTSLOnlineDigest(bool enable)
 * @copydoc digidoc::XmlConf::setTSLOnlineDigest(bool enable)
 */
SET1(bool, setTSLOnlineDigest, TSLOnlineDigest)

/**
 * @fn void digidoc::XmlConf::setTSLTimeOut(int timeOut)
 * Sets TSL connection timeout
 * @param timeOut Time out in seconds
 * @throws Exception exception is thrown if saving a TSL timeout into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setTSLTimeOut(int timeOut)
 * @copydoc digidoc::XmlConf::setTSLTimeOut(int timeOut)
 */
/**
 * @fn void digidoc::XmlConfV3::setTSLTimeOut(int timeOut)
 * @copydoc digidoc::XmlConf::setTSLTimeOut(int timeOut)
 */
/**
 * @fn void digidoc::XmlConfV4::setTSLTimeOut(int timeOut)
 * @copydoc digidoc::XmlConf::setTSLTimeOut(int timeOut)
 */
/**
 * @fn void digidoc::XmlConfV5::setTSLTimeOut(int timeOut)
 * @copydoc digidoc::XmlConf::setTSLTimeOut(int timeOut)
 */
SET1(int, setTSLTimeOut, TSLTimeOut)

/**
 * @fn void digidoc::XmlConf::setProxyHost(const std::string &host)
 * Sets a Proxy host address. Also adds or replaces proxy host data in the user configuration file.
 *
 * @param host proxy host address.
 * @throws Exception exception is thrown if saving a proxy host address into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyHost(const std::string &host)
 * @copydoc digidoc::XmlConf::setProxyHost(const std::string &host)
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyHost(const std::string &host)
 * @copydoc digidoc::XmlConf::setProxyHost(const std::string &host)
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyHost(const std::string &host)
 * @copydoc digidoc::XmlConf::setProxyHost(const std::string &host)
 */
/**
 * @fn void digidoc::XmlConfV5::setProxyHost(const std::string &host)
 * @copydoc digidoc::XmlConf::setProxyHost(const std::string &host)
 */
SET1CONST(string, setProxyHost, proxyHost)

/**
 * @fn void digidoc::XmlConf::setProxyPort(const std::string &port)
 * Sets a Proxy port number. Also adds or replaces proxy port data in the user configuration file.
 *
 * @param port proxy port number.
 * @throws Exception exception is thrown if saving a proxy port number into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyPort(const std::string &port)
 * @copydoc digidoc::XmlConf::setProxyPort(const std::string &port)
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyPort(const std::string &port)
 * @copydoc digidoc::XmlConf::setProxyPort(const std::string &port)
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyPort(const std::string &port)
 * @copydoc digidoc::XmlConf::setProxyPort(const std::string &port)
 */
/**
 * @fn void digidoc::XmlConfV5::setProxyPort(const std::string &port)
 * @copydoc digidoc::XmlConf::setProxyPort(const std::string &port)
 */
SET1CONST(string, setProxyPort, proxyPort)

/**
 * @fn void digidoc::XmlConf::setProxyUser(const std::string &user)
 * Sets a Proxy user name. Also adds or replaces proxy user name in the user configuration file.
 *
 * @param user proxy user name.
 * @throws Exception exception is thrown if saving a proxy user name into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyUser(const std::string &user)
 * @copydoc digidoc::XmlConf::setProxyUser(const std::string &user)
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyUser(const std::string &user)
 * @copydoc digidoc::XmlConf::setProxyUser(const std::string &user)
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyUser(const std::string &user)
 * @copydoc digidoc::XmlConf::setProxyUser(const std::string &user)
 */
/**
 * @fn void digidoc::XmlConfV5::setProxyUser(const std::string &user)
 * @copydoc digidoc::XmlConf::setProxyUser(const std::string &user)
 */
SET1CONST(string, setProxyUser, proxyUser)

/**
 * @fn void digidoc::XmlConf::setProxyPass(const std::string &pass)
 * Sets a Proxy password. Also adds or replaces proxy password in the user configuration file.
 *
 * @param pass proxy password.
 * @throws Exception exception is thrown if saving a proxy password into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyPass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setProxyPass(const std::string &pass)
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyPass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setProxyPass(const std::string &pass)
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyPass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setProxyPass(const std::string &pass)
 */
/**
 * @fn void digidoc::XmlConfV5::setProxyPass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setProxyPass(const std::string &pass)
 */
SET1CONST(string, setProxyPass, proxyPass)

/**
 * @fn void digidoc::XmlConf::setPKCS12Cert(const std::string &cert)
 * Sets a PKCS#12 certficate path. Also adds or replaces PKCS#12 certificate path in the user configuration file.
 * By default the PKCS#12 certificate file should be located at default path, given by getUserConfDir() function.
 *
 * @param cert PKCS#12 certificate location path.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate path into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setPKCS12Cert(const std::string &cert)
 * @copydoc digidoc::XmlConf::setPKCS12Cert(const std::string &cert)
 */
/**
 * @fn void digidoc::XmlConfV3::setPKCS12Cert(const std::string &cert)
 * @copydoc digidoc::XmlConf::setPKCS12Cert(const std::string &cert)
 */
/**
 * @fn void digidoc::XmlConfV4::setPKCS12Cert(const std::string &cert)
 * @copydoc digidoc::XmlConf::setPKCS12Cert(const std::string &cert)
 */
/**
 * @fn void digidoc::XmlConfV5::setPKCS12Cert(const std::string &cert)
 * @copydoc digidoc::XmlConf::setPKCS12Cert(const std::string &cert)
 */
SET1CONSTEX(string, setPKCS12Cert, {})

/**
 * @fn void digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 * Sets a PKCS#12 certificate password. Also adds or replaces PKCS#12 certificate password in the user configuration file.
 *
 * @param pass PKCS#12 certificate password.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate password into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setPKCS12Pass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 */
/**
 * @fn void digidoc::XmlConfV3::setPKCS12Pass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 */
/**
 * @fn void digidoc::XmlConfV4::setPKCS12Pass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 */
/**
 * @fn void digidoc::XmlConfV5::setPKCS12Pass(const std::string &pass)
 * @copydoc digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 */
SET1CONSTEX(string, setPKCS12Pass, {})

/**
 * @fn void digidoc::XmlConf::setTSUrl(const std::string &url)
 * Sets a TSA service URL. Also adds or replaces TSA service URL in the user configuration file.
 *
 * @param url Target URL to connect TSA service.
 * @throws Exception exception is thrown if saving a TS service URL into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setTSUrl(const std::string &url)
 * @copydoc digidoc::XmlConf::setTSUrl(const std::string &url)
 */
/**
 * @fn void digidoc::XmlConfV3::setTSUrl(const std::string &url)
 * @copydoc digidoc::XmlConf::setTSUrl(const std::string &url)
 */
/**
 * @fn void digidoc::XmlConfV4::setTSUrl(const std::string &url)
 * @copydoc digidoc::XmlConf::setTSUrl(const std::string &url)
 */
/**
 * @fn void digidoc::XmlConfV5::setTSUrl(const std::string &url)
 * @copydoc digidoc::XmlConf::setTSUrl(const std::string &url)
 */
SET1CONST(string, setTSUrl, TSUrl)

/**
 * @fn void digidoc::XmlConf::setVerifyServiceUri(const std::string &url)
 * Sets a Verify service URL. Also adds or replaces Verify service URL in the user configuration file.
 *
 * @param url Target URL to connect Verify service.
 * @throws Exception exception is thrown if saving a Verify service URL into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setVerifyServiceUri(const std::string &url)
 * @copydoc digidoc::XmlConf::setVerifyServiceUri(const std::string &url)
 */
/**
 * @fn void digidoc::XmlConfV3::setVerifyServiceUri(const std::string &url)
 * @copydoc digidoc::XmlConf::setVerifyServiceUri(const std::string &url)
 */
/**
 * @fn void digidoc::XmlConfV4::setVerifyServiceUri(const std::string &url)
 * @copydoc digidoc::XmlConf::setVerifyServiceUri(const std::string &url)
 */
/**
 * @fn void digidoc::XmlConfV5::setVerifyServiceUri(const std::string &url)
 * @copydoc digidoc::XmlConf::setVerifyServiceUri(const std::string &url)
 */
SET1CONST(string, setVerifyServiceUri, verifyServiceUri)

/**
 * @fn void digidoc::XmlConf::setPKCS12Disable(bool disable)
 * Sets a PKCS#12 certificate usage. Also adds or replaces PKCS#12 certificate usage in the user configuration file.
 *
 * @param disable PKCS#12 certificate usage.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate usage into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setPKCS12Disable(bool disable)
 * @copydoc digidoc::XmlConf::setPKCS12Disable(bool disable)
 */
/**
 * @fn void digidoc::XmlConfV3::setPKCS12Disable(bool disable)
 * @copydoc digidoc::XmlConf::setPKCS12Disable(bool disable)
 */
/**
 * @fn void digidoc::XmlConfV4::setPKCS12Disable(bool disable)
 * @copydoc digidoc::XmlConf::setPKCS12Disable(bool disable)
 */
/**
 * @fn void digidoc::XmlConfV5::setPKCS12Disable(bool disable)
 * @copydoc digidoc::XmlConf::setPKCS12Disable(bool disable)
 */
SET1EX(bool, setPKCS12Disable, {})

/**
 * @fn void digidoc::XmlConf::setProxyTunnelSSL(bool enable)
 *
 * Enables SSL proxy connections
 * @throws Exception exception is thrown if saving into a user configuration file fails.
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyTunnelSSL(bool enable)
 * @copydoc digidoc::XmlConf::setProxyTunnelSSL(bool enable)
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyTunnelSSL(bool enable)
 * @copydoc digidoc::XmlConf::setProxyTunnelSSL(bool enable)
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyTunnelSSL(bool enable)
 * @copydoc digidoc::XmlConf::setProxyTunnelSSL(bool enable)
 */
/**
 * @fn void digidoc::XmlConfV5::setProxyTunnelSSL(bool enable)
 * @copydoc digidoc::XmlConf::setProxyTunnelSSL(bool enable)
 */
SET1(bool, setProxyTunnelSSL, proxyTunnelSSL)


X509Cert XmlConfV2::verifyServiceCert() const
{
    return ConfV2::verifyServiceCert();
}

X509Cert XmlConfV3::verifyServiceCert() const
{
    return ConfV3::verifyServiceCert();
}

X509Cert XmlConfV4::verifyServiceCert() const
{
    return ConfV4::verifyServiceCert();
}

X509Cert XmlConfV5::verifyServiceCert() const
{
    return ConfV5::verifyServiceCert();
}

set<string> XmlConfV3::OCSPTMProfiles() const
{
    return d->ocspTMProfiles.empty() ? ConfV3::OCSPTMProfiles() : d->ocspTMProfiles;
}

set<string> XmlConfV4::OCSPTMProfiles() const
{
    return d->ocspTMProfiles.empty() ? ConfV3::OCSPTMProfiles() : d->ocspTMProfiles;
}

set<string> XmlConfV5::OCSPTMProfiles() const
{
    return d->ocspTMProfiles.empty() ? ConfV3::OCSPTMProfiles() : d->ocspTMProfiles;
}

vector<X509Cert> XmlConfV4::verifyServiceCerts() const
{
    return ConfV4::verifyServiceCerts();
}

vector<X509Cert> XmlConfV5::verifyServiceCerts() const
{
    return ConfV5::verifyServiceCerts();
}

vector<X509Cert> XmlConfV5::TSCerts() const
{
    return ConfV5::TSCerts();
}
