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

#include "log.h"
#include "crypto/X509Cert.h"
#include "util/File.h"
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
    XmlConfParam(const string &_name, A def = A()): name(_name), _def(def), locked(false) {}

    void setValue(const A &val, bool lock, bool global)
    {
        if(global) locked = lock;
        if(global || !locked) operator =(val);
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

    string name;
    A _def;
    bool locked;
};

class XmlConfPrivate
{
public:
    XmlConfPrivate(const string &path = "", const string &schema = "");

    void init(const string &path, bool global);
    unique_ptr<Configuration> read(const string &path);
    void setUserConf(const string &paramName, const string &defined, const string &value);

    XmlConfParam<int> logLevel;
    XmlConfParam<string> logFile;
    XmlConfParam<string> digestUri;
    XmlConfParam<string> signatureDigestUri;
    XmlConfParam<string> PKCS11Driver;
    XmlConfParam<string> proxyHost;
    XmlConfParam<string> proxyPort;
    XmlConfParam<string> proxyUser;
    XmlConfParam<string> proxyPass;
    XmlConfParam<string> PKCS12Cert;
    XmlConfParam<string> PKCS12Pass;
    XmlConfParam<bool> PKCS12Disable;
    XmlConfParam<string> TSUrl;
    XmlConfParam<bool> TSLAutoUpdate;
    XmlConfParam<string> TSLCache;
    XmlConfParam<bool> TSLOnlineDigest;
    XmlConfParam<int> TSLTimeOut;
    map<string,string> ocsp;

    string SCHEMA_LOC;
    string USER_CONF_LOC;
};
}

using namespace digidoc;

XmlConfPrivate::XmlConfPrivate(const string &path, const string &schema)
    : logLevel("log.level")
    , logFile("log.file")
    , digestUri("signer.digestUri")
    , signatureDigestUri("signer.signatureDigestUri")
    , PKCS11Driver("pkcs11.driver.path")
    , proxyHost("proxy.host")
    , proxyPort("proxy.port")
    , proxyUser("proxy.user")
    , proxyPass("proxy.pass")
    , PKCS12Cert("pkcs12.cert")
    , PKCS12Pass("pkcs12.pass")
    , PKCS12Disable("pkcs12.disable")
    , TSUrl("ts.url")
    , TSLAutoUpdate("tsl.autoupdate", true)
    , TSLCache("tsl.cache")
    , TSLOnlineDigest("tsl.onlineDigest", true)
    , TSLTimeOut("tsl.timeOut", 10)
    , SCHEMA_LOC(schema)
{
    try {
        XMLPlatformUtils::Initialize();
    }
    catch (const XMLException &e) {
        char *msg = XMLString::transcode(e.getMessage());
        string result = msg;
        XMLString::release(&msg);
        THROW("Error during initialisation of Xerces: %s", result.c_str());
    }

#ifdef _WIN32
    USER_CONF_LOC = File::env("APPDATA");
    if (!USER_CONF_LOC.empty())
        USER_CONF_LOC += "\\digidocpp\\digidocpp.conf";
#else
    USER_CONF_LOC = File::env("HOME");
    if (!USER_CONF_LOC.empty())
        USER_CONF_LOC += "/.digidocpp/digidocpp.conf";
#endif

    if(path.empty())
    {
        try
        {
            init(File::confPath() + "digidocpp.conf", true);
        }
        catch(const Exception &e)
        {
            WARN("Failed to read global configuration '%s' file", e.msg().c_str());
        }

        try
        {
            if(File::fileExists(USER_CONF_LOC))
                init(USER_CONF_LOC, false);
        }
        catch(const Exception &e)
        {
            WARN("Failed to read user home configuration '%s' file", e.msg().c_str());
        }
    }
    else
    {
        try
        {
            init(path, true);
        }
        catch(const Exception &e)
        {
            WARN("Failed to read global configuration '%s' file: %s", e.msg().c_str(), path.c_str());
        }
    }
}

/**
 * Load and parse xml from path. Initialize XmlConf member variables from xml.
 * @param path to use for initializing conf
 */
void XmlConfPrivate::init(const string& path, bool global)
{
    DEBUG("XmlConfPrivate::init(%s)", path.c_str());
    unique_ptr<Configuration> conf = read(path);
    try
    {
        for(const Configuration::ParamType &p: conf->param())
        {
            if(p.name() == logLevel.name)
                logLevel.setValue(atoi(string(p).c_str()), p.lock(), global);
            else if(p.name() == logFile.name)
                logFile.setValue(p, p.lock(), global);
            else if(p.name() == digestUri.name)
                digestUri.setValue(p, p.lock(), global);
            else if(p.name() == signatureDigestUri.name)
                signatureDigestUri.setValue(p, p.lock(), global);
            else if(p.name() == PKCS11Driver.name)
                PKCS11Driver.setValue(p, p.lock(), global);
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
                string path = File::isRelative(p) ? File::confPath() + p : string(p);
                PKCS12Cert.setValue(path, p.lock(), global);
            }
            else if(p.name() == PKCS12Pass.name)
                PKCS12Pass.setValue(p, p.lock(), global);
            else if(p.name() == PKCS12Disable.name)
                PKCS12Disable.setValue(p == "true", p.lock(), global);
            else if(p.name() == TSUrl.name)
                TSUrl.setValue(p, p.lock(), global);
            else if(p.name() == TSLAutoUpdate.name)
                TSLAutoUpdate.setValue(p == "true", p.lock(), global);
            else if(p.name() == TSLCache.name)
                TSLCache.setValue(p, p.lock(), global);
            else if(p.name() == TSLOnlineDigest.name)
                TSLOnlineDigest.setValue(p == "true", p.lock(), global);
            else if(p.name() == TSLTimeOut.name)
                TSLTimeOut.setValue(stoi(p), p.lock(), global);
            else
                WARN("Unknown configuration parameter %s", p.name().c_str());
        }

        for(const Configuration::OcspType &o: conf->ocsp())
            ocsp[o.issuer()] = o;
    }
    catch(const xml_schema::Exception& e)
    {
        THROW("Failed to parse configuration: %s", e.what());
    }
}

/**
 * Parses xml configuration given path
 * @param path to parse xml config
 * @return returns parsed xml configuration
 */
unique_ptr<Configuration> XmlConfPrivate::read(const string &path)
{
    try
    {
        Properties props;
        props.no_namespace_schema_location(SCHEMA_LOC);
        return configuration(path, Flags::dont_initialize, props);
    }
    catch(const xml_schema::Exception& e)
    {
        THROW("Failed to parse configuration: %s (%s) - %s",
            path.c_str(), SCHEMA_LOC.c_str(), e.what());
    }
    return unique_ptr<Configuration>(new Configuration);
}

/**
 * Sets any parameter in a user configuration file. Also creates a configuration file if it is missing.
 *
 * @param paramName name of parameter that needs to be changed or created.
 * @param value value for changing or adding to a given parameter. If value is an empty string, the walue for a given parameter will be erased.
 * @throws Exception exception is thrown if reading, writing or creating of a user configuration file fails.
 */
void XmlConfPrivate::setUserConf(const string &paramName, const string &defined, const string &value)
{
    unique_ptr<Configuration> conf(new Configuration);
    if(File::fileExists(USER_CONF_LOC))
        conf = read(USER_CONF_LOC);
    try
    {
        Configuration::ParamSequence &paramSeq = conf->param();
        for(Configuration::ParamSequence::iterator it = paramSeq.begin(); it != paramSeq.end(); ++it)
        {
            if(paramName == it->name())
            {
                paramSeq.erase(it);
                break;
            }
        }
        if(defined != value && value.size()) //if it's a new parameter
            paramSeq.push_back(Param(value, paramName));
    }
    catch (const xml_schema::Exception& e)
    {
        THROW("(in set %s) Failed to parse configuration: %s", paramName.c_str(), e.what());
    }

    string path = File::directory(USER_CONF_LOC);
    if (!File::directoryExists(path))
        File::createDirectory(path);
    ofstream ofs(File::encodeName(USER_CONF_LOC).c_str());
    if (ofs.fail())
        THROW("Failed to open configuration: %s", USER_CONF_LOC.c_str());
    NamespaceInfomap map;
    map[""].name = "";
    map[""].schema = SCHEMA_LOC;
    configuration(ofs, *conf, map, "UTF-8", Flags::dont_initialize);
}


/**
 * @class digidoc::XmlConf
 * @brief XML Configuration class
 * @deprecated See digidoc::XmlConfV4
 * @see digidoc::Conf
 */
/**
 * @class digidoc::XmlConfV2
 * @brief Version 2 of XML Configuration class
 * @deprecated See digidoc::XmlConfV4
 * @see digidoc::ConfV2
 */
/**
 * @class digidoc::XmlConfV3
 * @brief Version 3 of XML Configuration class
 * @deprecated See digidoc::XmlConfV4
 * @see digidoc::ConfV3
 */
/**
 * @class digidoc::XmlConfV4
 * @brief Version 4 of XML Configuration class
 * @see digidoc::ConfV4
 */
/**
 * @deprecated See digidoc::XmlConfV4::XmlConfV4
 */
XmlConf::XmlConf(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}
/**
 * @deprecated See digidoc::XmlConfV4::XmlConfV4
 */
XmlConfV2::XmlConfV2(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}
/**
 * @deprecated See digidoc::XmlConfV4::XmlConfV4
 */
XmlConfV3::XmlConfV3(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}
/**
 * Initialize xml conf from path
 */
XmlConfV4::XmlConfV4(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}

XmlConf::~XmlConf() { delete d; }
XmlConfV2::~XmlConfV2() { delete d; }
XmlConfV3::~XmlConfV3() { delete d; }
XmlConfV4::~XmlConfV4() { delete d; }

#define GET1(TYPE, PROP) \
TYPE XmlConf::PROP() const { return d->PROP.value(Conf::PROP()); } \
TYPE XmlConfV2::PROP() const { return d->PROP.value(ConfV2::PROP()); } \
TYPE XmlConfV3::PROP() const { return d->PROP.value(ConfV3::PROP()); } \
TYPE XmlConfV4::PROP() const { return d->PROP.value(ConfV4::PROP()); }

#define GET2(TYPE, PROP) \
TYPE XmlConfV2::PROP() const { return d->PROP.value(ConfV2::PROP()); } \
TYPE XmlConfV3::PROP() const { return d->PROP.value(ConfV3::PROP()); } \
TYPE XmlConfV4::PROP() const { return d->PROP.value(ConfV4::PROP()); }

#define GET3(TYPE, PROP) \
TYPE XmlConfV3::PROP() const { return d->PROP.value(ConfV3::PROP()); } \
TYPE XmlConfV4::PROP() const { return d->PROP.value(ConfV4::PROP()); }

#define GET1_R(TYPE, PROP) \
TYPE XmlConf::PROP() const { return Conf::PROP(); } \
TYPE XmlConfV2::PROP() const { return ConfV2::PROP(); } \
TYPE XmlConfV3::PROP() const { return ConfV3::PROP(); } \
TYPE XmlConfV4::PROP() const { return ConfV4::PROP(); }

#define GET2_R(TYPE, PROP) \
TYPE XmlConfV2::PROP() const { return ConfV2::PROP(); } \
TYPE XmlConfV3::PROP() const { return ConfV3::PROP(); } \
TYPE XmlConfV4::PROP() const { return ConfV4::PROP(); }

#define SET1(TYPE, SET, PROP) \
void XmlConf::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, Conf::PROP(), d->PROP = PROP); } \
void XmlConfV2::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, ConfV2::PROP(), d->PROP = PROP); } \
void XmlConfV3::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, ConfV3::PROP(), d->PROP = PROP); } \
void XmlConfV4::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, ConfV4::PROP(), d->PROP = PROP); }

GET1(int, logLevel)
GET1(string, logFile)
GET1(string, PKCS11Driver)
GET1(string, proxyHost)
GET1(string, proxyPort)
GET1(string, proxyUser)
GET1(string, proxyPass)
GET1(string, PKCS12Cert)
GET1(string, PKCS12Pass)
GET1(bool, PKCS12Disable)
GET2(string, TSUrl)
GET2(bool, TSLAutoUpdate)
GET2(string, TSLCache)
GET1_R(string, xsdPath)
GET1_R(string, certsPath)
GET2_R(X509Cert, TSLCert)
GET2_R(string, TSLUrl)
GET3(bool,TSLOnlineDigest)
GET3(int,TSLTimeOut)

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


/**
 * @deprecated See digidoc::XmlConfV4::setTSLOnlineDigest
 */
void XmlConfV3::setTSLOnlineDigest( bool enable )
{
    if( !d->TSLOnlineDigest.locked )
        d->setUserConf(d->TSLOnlineDigest.name, ConfV3::TSLOnlineDigest() ? "true" : "false", (d->TSLOnlineDigest = enable) ? "true" : "false");
}
/**
 * Enables/Disables online digest check
 * @throws Exception exception is thrown if saving a TSL online digest into a user configuration file fails.
 */
void XmlConfV4::setTSLOnlineDigest( bool enable )
{
    if( !d->TSLOnlineDigest.locked )
        d->setUserConf(d->TSLOnlineDigest.name, ConfV3::TSLOnlineDigest() ? "true" : "false", (d->TSLOnlineDigest = enable) ? "true" : "false");
}

/**
 * @deprecated See digidoc::XmlConfV4::setTSLTimeOut
 */
void XmlConfV3::setTSLTimeOut( int timeOut )
{
    if( !d->TSLTimeOut.locked )
        d->setUserConf(d->TSLTimeOut.name, to_string(ConfV3::TSLTimeOut()), to_string(timeOut));
}
/**
 * Sets TSL connection timeout
 * @param timeOut Time out in seconds
 * @throws Exception exception is thrown if saving a TSL timeout into a user configuration file fails.
 */
void XmlConfV4::setTSLTimeOut( int timeOut )
{
    if( !d->TSLTimeOut.locked )
        d->setUserConf(d->TSLTimeOut.name, to_string(ConfV3::TSLTimeOut()), to_string(timeOut));
}

string XmlConfV4::digestUri() const
{
    return d->digestUri.value(ConfV4::digestUri());
}

string XmlConfV4::signatureDigestUri() const
{
    return d->signatureDigestUri.value(ConfV4::signatureDigestUri());
}

/**
 * @fn void digidoc::XmlConf::setProxyHost(const std::string &host)
 * @deprecated See digidoc::XmlConfV4::setProxyHost
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyHost(const std::string &host)
 * @deprecated See digidoc::XmlConfV4::setProxyHost
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyHost(const std::string &host)
 * @deprecated See digidoc::XmlConfV4::setProxyHost
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyHost(const std::string &host)
 * Sets a Proxy host address. Also adds or replaces proxy host data in the user configuration file.
 *
 * @param host proxy host address.
 * @throws Exception exception is thrown if saving a proxy host address into a user configuration file fails.
 */
SET1(string, setProxyHost, proxyHost)

/**
 * @fn void digidoc::XmlConf::setProxyPort(const std::string &port)
 * @deprecated See digidoc::XmlConfV4::setProxyPort
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyPort(const std::string &port)
 * @deprecated See digidoc::XmlConfV4::setProxyPort
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyPort(const std::string &port)
 * @deprecated See digidoc::XmlConfV4::setProxyPort
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyPort(const std::string &port)
 * Sets a Proxy port number. Also adds or replaces proxy port data in the user configuration file.
 *
 * @param port proxy port number.
 * @throws Exception exception is thrown if saving a proxy port number into a user configuration file fails.
 */
SET1(string, setProxyPort, proxyPort)

/**
 * @fn void digidoc::XmlConf::setProxyUser(const std::string &user)
 * @deprecated See digidoc::XmlConfV4::setProxyUser
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyUser(const std::string &user)
 * @deprecated See digidoc::XmlConfV4::setProxyUser
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyUser(const std::string &user)
 * @deprecated See digidoc::XmlConfV4::setProxyUser
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyUser(const std::string &user)
 * Sets a Proxy user name. Also adds or replaces proxy user name in the user configuration file.
 *
 * @param user proxy user name.
 * @throws Exception exception is thrown if saving a proxy user name into a user configuration file fails.
 */
SET1(string, setProxyUser, proxyUser)

/**
 * @fn void digidoc::XmlConf::setProxyPass(const std::string &pass)
 * @deprecated See digidoc::XmlConfV4::setProxyPass
 */
/**
 * @fn void digidoc::XmlConfV2::setProxyPass(const std::string &pass)
 * @deprecated See digidoc::XmlConfV4::setProxyPass
 */
/**
 * @fn void digidoc::XmlConfV3::setProxyPass(const std::string &pass)
 * @deprecated See digidoc::XmlConfV4::setProxyPass
 */
/**
 * @fn void digidoc::XmlConfV4::setProxyPass(const std::string &pass)
 * Sets a Proxy password. Also adds or replaces proxy password in the user configuration file.
 *
 * @param pass proxy password.
 * @throws Exception exception is thrown if saving a proxy password into a user configuration file fails.
 */
SET1(string, setProxyPass, proxyPass)

/**
 * @fn void digidoc::XmlConf::setPKCS12Cert(const std::string &cert)
 * @deprecated See digidoc::XmlConfV4::setPKCS12Cert
 */
/**
 * @fn void digidoc::XmlConfV2::setPKCS12Cert(const std::string &cert)
 * @deprecated See digidoc::XmlConfV4::setPKCS12Cert
 */
/**
 * @fn void digidoc::XmlConfV3::setPKCS12Cert(const std::string &cert)
 * @deprecated See digidoc::XmlConfV4::setPKCS12Cert
 */
/**
 * @fn void digidoc::XmlConfV4::setPKCS12Cert(const std::string &cert)
 * Sets a PKCS#12 certficate path. Also adds or replaces PKCS#12 certificate path in the user configuration file.
 * By default the PKCS#12 certificate file should be located at default path, given by getUserConfDir() function.
 *
 * @param cert PKCS#12 certificate location path.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate path into a user configuration file fails.
 */
SET1(string, setPKCS12Cert, PKCS12Cert)

/**
 * @fn void digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 * @deprecated See digidoc::XmlConfV4::setPKCS12Pass
 */
/**
 * @fn void digidoc::XmlConfV2::setPKCS12Pass(const std::string &pass)
 * @deprecated See digidoc::XmlConfV4::setPKCS12Pass
 */
/**
 * @fn void digidoc::XmlConfV3::setPKCS12Pass(const std::string &pass)
 * @deprecated See digidoc::XmlConfV4::setPKCS12Pass
 */
/**
 * @fn void digidoc::XmlConfV4::setPKCS12Pass(const std::string &pass)
 * Sets a PKCS#12 certificate password. Also adds or replaces PKCS#12 certificate password in the user configuration file.
 *
 * @param pass PKCS#12 certificate password.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate password into a user configuration file fails.
 */
SET1(string, setPKCS12Pass, PKCS12Pass)

/**
 * @deprecated See digidoc::XmlConfV4::setPKCS12Disable
 */
void XmlConf::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
/**
 * @deprecated See digidoc::XmlConfV4::setPKCS12Disable
 */
void XmlConfV2::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
/**
 * @deprecated See digidoc::XmlConfV4::setPKCS12Disable
 */
void XmlConfV3::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
/**
 * Sets a PKCS#12 certificate usage. Also adds or replaces PKCS#12 certificate usage in the user configuration file.
 *
 * @param disable PKCS#12 certificate usage.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate usage into a user configuration file fails.
 */
void XmlConfV4::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
