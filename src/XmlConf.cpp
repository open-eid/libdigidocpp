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

#include "crypto/X509Cert.h"
#include "util/File.h"
#include "util/log.h"
#include "xml/conf.hxx"

#include <fstream>

using namespace std;
using namespace digidoc::util;
using namespace xercesc;
using namespace xml_schema;

namespace digidoc
{

template <class A>
class XmlConfParam: public unique_ptr<A>
{
public:
    XmlConfParam(string _name, A def = {}): name(std::move(_name)), _def(std::move(def)) {}

    void setValue(const string &val, const Param::LockOptional &lock, bool global)
    {
        if(global && lock.present()) locked = lock.get();
        if(global || !locked)
        {
            if constexpr(is_same<A,bool>::value)
                operator =(val == "true");
            else if constexpr(is_integral<A>::value)
                operator =(stoi(val));
            else
                operator =(val);
        }
    }

    XmlConfParam &operator=(const A &other)
    {
        unique_ptr<A>::reset(_def != other ? new A(other) : nullptr);
        return *this;
    }

    operator A() const
    {
        return value(_def);
    }

    A value(const A &def) const
    {
        return unique_ptr<A>::get() ? *unique_ptr<A>::get(): def;
    }

    const string name;
    A _def;
    bool locked = false;
};

class XmlConf::Private
{
public:
    Private(const string &path = {}, string schema = {});

    void init(const string &path, bool global);
    unique_ptr<Configuration> read(const string &path) const;
    template <class A>
    void setUserConf(XmlConfParam<A> &param, const A &defined, const A &value);
    static string to_string(bool val) { return val ? "true" : "false"; }
    static string to_string(const string &val) { return val; }


    XmlConfParam<int> logLevel{"log.level", 3};
    XmlConfParam<string> logFile{"log.file"};
    XmlConfParam<string> digestUri{"signer.digestUri"};
    XmlConfParam<string> signatureDigestUri{"signer.signatureDigestUri"};
    XmlConfParam<string> PKCS11Driver{"pkcs11.driver.path"};
    XmlConfParam<bool> proxyForceSSL{"proxy.forceSSL", false};
    XmlConfParam<bool> proxyTunnelSSL{"proxy.tunnelSSL", true};
    XmlConfParam<string> proxyHost{"proxy.host"};
    XmlConfParam<string> proxyPort{"proxy.port"};
    XmlConfParam<string> proxyUser{"proxy.user"};
    XmlConfParam<string> proxyPass{"proxy.pass"};
    XmlConfParam<string> PKCS12Cert{"pkcs12.cert"};
    XmlConfParam<string> PKCS12Pass{"pkcs12.pass"};
    XmlConfParam<bool> PKCS12Disable{"pkcs12.disable", false};
    XmlConfParam<string> TSUrl{"ts.url"};
    XmlConfParam<bool> TSLAutoUpdate{"tsl.autoupdate", true};
    XmlConfParam<string> TSLCache{"tsl.cache"};
    XmlConfParam<bool> TSLOnlineDigest{"tsl.onlineDigest", true};
    XmlConfParam<int> TSLTimeOut{"tsl.timeOut", 10};
    XmlConfParam<string> verifyServiceUri{"verify.serivceUri"};
    map<string,string> ocsp;
    std::set<std::string> ocspTMProfiles;

    string SCHEMA_LOC;
    string USER_CONF_LOC;
};
}

using namespace digidoc;

XmlConf::Private::Private(const string &path, string schema)
    : SCHEMA_LOC(std::move(schema))
{
    try {
        if(!XMLPlatformUtils::fgMemoryManager)
            XMLPlatformUtils::Initialize();
    }
    catch (const XMLException &e) {
        try {
            string result = xsd::cxx::xml::transcode<char>(e.getMessage());
            THROW("Error during initialisation of Xerces: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Error during initialisation of Xerces");
        }
    }

    USER_CONF_LOC = File::path(File::digidocppPath(), "digidocpp.conf");
    if(path.empty())
    {
        init(File::confPath() + "/digidocpp.conf", true);
        init(USER_CONF_LOC, false);
    }
    else
        init(path, true);
}

/**
 * Load and parse xml from path. Initialize XmlConf member variables from xml.
 * @param path to use for initializing conf
 */
void XmlConf::Private::init(const string& path, bool global)
{
    DEBUG("XmlConfPrivate::init(%s, %u)", path.c_str(), global);
    try
    {
        unique_ptr<Configuration> conf = read(path);
        for(const Configuration::ParamType &p: conf->param())
        {
            if(p.name() == logLevel.name)
                logLevel.setValue(p, p.lock(), global);
            else if(p.name() == logFile.name)
                logFile.setValue(p, p.lock(), global);
            else if(p.name() == digestUri.name)
                digestUri.setValue(p, p.lock(), global);
            else if(p.name() == signatureDigestUri.name)
                signatureDigestUri.setValue(p, p.lock(), global);
            else if(p.name() == PKCS11Driver.name)
                PKCS11Driver.setValue(p, p.lock(), global);
            else if(p.name() == proxyForceSSL.name)
                proxyForceSSL.setValue(p, p.lock(), global);
            else if(p.name() == proxyTunnelSSL.name)
                proxyTunnelSSL.setValue(p, p.lock(), global);
            else if(p.name() == proxyHost.name)
                proxyHost.setValue(p, p.lock(), global);
            else if(p.name() == proxyPort.name)
                proxyPort.setValue(p, p.lock(), global);
            else if(p.name() == proxyUser.name)
                proxyUser.setValue(p, p.lock(), global);
            else if(p.name() == proxyPass.name)
                proxyPass.setValue(p, p.lock(), global);
            else if(p.name() == PKCS12Cert.name)
            {
                string file = File::isRelative(p) ? File::confPath() + p : string(p);
                PKCS12Cert.setValue(file, p.lock(), global);
            }
            else if(p.name() == PKCS12Pass.name)
                PKCS12Pass.setValue(p, p.lock(), global);
            else if(p.name() == PKCS12Disable.name)
                PKCS12Disable.setValue(p, p.lock(), global);
            else if(p.name() == TSUrl.name)
                TSUrl.setValue(p, p.lock(), global);
            else if(p.name() == TSLAutoUpdate.name)
                TSLAutoUpdate.setValue(p, p.lock(), global);
            else if(p.name() == TSLCache.name)
                TSLCache.setValue(p, p.lock(), global);
            else if(p.name() == TSLOnlineDigest.name)
                TSLOnlineDigest.setValue(p, p.lock(), global);
            else if(p.name() == TSLTimeOut.name)
                TSLTimeOut.setValue(p, p.lock(), global);
            else if(p.name() == verifyServiceUri.name)
                verifyServiceUri.setValue(p, p.lock(), global);
            else if(p.name() == "ocsp.tm.profile" && global)
                ocspTMProfiles.emplace(p);
            else
                WARN("Unknown configuration parameter %s", p.name().c_str());
        }

        for(const Configuration::OcspType &o: conf->ocsp())
            ocsp[o.issuer()] = o;
    }
    catch(const Exception &e)
    {
        WARN("Failed to parse configuration: %s %d %s", path.c_str(), global, e.msg().c_str());
    }
    catch(const xml_schema::Exception &e)
    {
        WARN("Failed to parse configuration: %s %d %s", path.c_str(), global, e.what());
    }
}

/**
 * Parses xml configuration given path
 * @param path to parse xml config
 * @return returns parsed xml configuration
 */
unique_ptr<Configuration> XmlConf::Private::read(const string &path) const
{
    try
    {
        if(File::fileExists(path))
        {
            Properties props;
            props.no_namespace_schema_location(SCHEMA_LOC);
            return configuration(path, Flags::dont_initialize, props);
        }
    }
    catch(const xml_schema::Exception& e)
    {
        THROW("Failed to parse configuration: %s (%s) - %s",
            path.c_str(), SCHEMA_LOC.c_str(), e.what());
    }
    catch(const xsd::cxx::xml::properties<char>::argument & /* e */)
    {
        THROW("Failed to parse configuration: %s (%s)",
            path.c_str(), SCHEMA_LOC.c_str());
    }
    catch(const xsd::cxx::xml::invalid_utf8_string & /* e */)
    {
        THROW("Failed to parse configuration: %s (%s)",
            path.c_str(), SCHEMA_LOC.c_str());
    }
    catch(const xsd::cxx::xml::invalid_utf16_string & /* e */)
    {
        THROW("Failed to parse configuration: %s (%s)",
            path.c_str(), SCHEMA_LOC.c_str());
    }
    return make_unique<Configuration>();
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
void XmlConf::Private::setUserConf(XmlConfParam<A> &param, const A &defined, const A &value)
{
    if(param.locked)
        return;
    param = value;
    unique_ptr<Configuration> conf = read(USER_CONF_LOC);
    try
    {
        Configuration::ParamSequence &paramSeq = conf->param();
        for(Configuration::ParamSequence::iterator it = paramSeq.begin(); it != paramSeq.end(); ++it)
        {
            if(param.name == it->name())
            {
                paramSeq.erase(it);
                break;
            }
        }
        if(defined != value) //if it's a new parameter
            paramSeq.push_back({to_string(value), param.name});
    }
    catch (const xml_schema::Exception& e)
    {
        THROW("(in set %s) Failed to parse configuration: %s", param.name.c_str(), e.what());
    }

    File::createDirectory(File::directory(USER_CONF_LOC));
    ofstream ofs(File::encodeName(USER_CONF_LOC));
    if (ofs.fail())
        THROW("Failed to open configuration: %s", USER_CONF_LOC.c_str());
    NamespaceInfomap map;
    map[{}].name = {};
    map[{}].schema = SCHEMA_LOC;
    configuration(ofs, *conf, map, "UTF-8", Flags::dont_initialize);
}


/**
 * @typedef digidoc::XmlConfCurrent
 * @see digidoc::XmlConfV5
 */

/**
 * @class digidoc::XmlConf
 * @brief XML Configuration class
 * @deprecated Use digidoc::XmlConfV5
 * @see digidoc::Conf
 */
XmlConf::XmlConf(const string &path, const string &schema)
    : d(make_unique<XmlConf::Private>(path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
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
    : d(make_unique<XmlConf::Private>(path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
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
    : d(make_unique<XmlConf::Private>(path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
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
    : d(make_unique<XmlConf::Private>(path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
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
    : d(make_unique<XmlConf::Private>(path, schema.empty() ? File::path(xsdPath(), "conf.xsd") : schema))
{}
XmlConfV5::~XmlConfV5() = default;

/**
 * @copydoc digidoc::Conf::instance()
 */
XmlConfV5* XmlConfV5::instance() { return dynamic_cast<XmlConfV5*>(Conf::instance()); }



#define GET1(TYPE, PROP) \
TYPE XmlConf::PROP() const { return d->PROP.value(Conf::PROP()); } \
TYPE XmlConfV2::PROP() const { return d->PROP.value(Conf::PROP()); } \
TYPE XmlConfV3::PROP() const { return d->PROP.value(Conf::PROP()); } \
TYPE XmlConfV4::PROP() const { return d->PROP.value(Conf::PROP()); } \
TYPE XmlConfV5::PROP() const { return d->PROP.value(Conf::PROP()); }

#define SET1(TYPE, SET, PROP) \
void XmlConf::SET(TYPE PROP) \
{ d->setUserConf<TYPE>(d->PROP, Conf::PROP(), PROP); } \
void XmlConfV2::SET(TYPE PROP) \
{ d->setUserConf<TYPE>(d->PROP, ConfV2::PROP(), PROP); } \
void XmlConfV3::SET(TYPE PROP) \
{ d->setUserConf<TYPE>(d->PROP, ConfV3::PROP(), PROP); } \
void XmlConfV4::SET(TYPE PROP) \
{ d->setUserConf<TYPE>(d->PROP, ConfV4::PROP(), PROP); } \
void XmlConfV5::SET(TYPE PROP) \
{ d->setUserConf<TYPE>(d->PROP, ConfV5::PROP(), PROP); }

#define SET1CONST(TYPE, SET, PROP) \
void XmlConf::SET(const TYPE &(PROP)) \
{ d->setUserConf<TYPE>(d->PROP, Conf::PROP(), PROP); } \
void XmlConfV2::SET(const TYPE &(PROP)) \
{ d->setUserConf<TYPE>(d->PROP, ConfV2::PROP(), PROP); } \
void XmlConfV3::SET(const TYPE &(PROP)) \
{ d->setUserConf<TYPE>(d->PROP, ConfV3::PROP(), PROP); } \
void XmlConfV4::SET(const TYPE &(PROP)) \
{ d->setUserConf<TYPE>(d->PROP, ConfV4::PROP(), PROP); } \
void XmlConfV5::SET(const TYPE &(PROP)) \
{ d->setUserConf<TYPE>(d->PROP, ConfV5::PROP(), PROP); }

GET1(int, logLevel)
GET1(string, logFile)
GET1(string, PKCS11Driver)
GET1(string, proxyHost)
GET1(string, proxyPort)
GET1(string, proxyUser)
GET1(string, proxyPass)
GET1(bool, proxyForceSSL)
GET1(bool, proxyTunnelSSL)
GET1(string, PKCS12Cert)
GET1(string, PKCS12Pass)
GET1(bool, PKCS12Disable)
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
SET1CONST(string, setPKCS12Cert, PKCS12Cert)

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
SET1CONST(string, setPKCS12Pass, PKCS12Pass)

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
SET1(bool, setPKCS12Disable, PKCS12Disable)

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
