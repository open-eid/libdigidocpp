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

#define GET1(TYPE, PROP) \
TYPE XmlConf::PROP() const { return d->PROP.value(Conf::PROP()); } \
TYPE XmlConfV2::PROP() const { return d->PROP.value(ConfV2::PROP()); } \
TYPE XmlConfV3::PROP() const { return d->PROP.value(ConfV3::PROP()); }

#define GET2(TYPE, PROP) \
TYPE XmlConfV2::PROP() const { return d->PROP.value(ConfV2::PROP()); } \
TYPE XmlConfV3::PROP() const { return d->PROP.value(ConfV3::PROP()); }

#define GET1_R(TYPE, PROP) \
TYPE XmlConf::PROP() const { return Conf::PROP(); } \
TYPE XmlConfV2::PROP() const { return ConfV2::PROP(); } \
TYPE XmlConfV3::PROP() const { return ConfV3::PROP(); }

#define GET2_R(TYPE, PROP) \
TYPE XmlConfV2::PROP() const { return ConfV2::PROP(); } \
TYPE XmlConfV3::PROP() const { return ConfV3::PROP(); }

#define SET1(TYPE, SET, PROP) \
void XmlConf::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, Conf::PROP(), d->PROP = PROP); } \
void XmlConfV2::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, ConfV2::PROP(), d->PROP = PROP); } \
void XmlConfV3::SET( const TYPE &PROP ) \
{ if( !d->PROP.locked ) d->setUserConf(d->PROP.name, ConfV3::PROP(), d->PROP = PROP); }

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
    map<string,string> ocsp;

    string SCHEMA_LOC;
    string USER_CONF_LOC;
};
}

using namespace digidoc;

XmlConfPrivate::XmlConfPrivate(const string &path, const string &schema)
    : logLevel("log.level")
    , logFile("log.file")
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
#if defined(_WIN32) && defined(_DEBUG)
            string path = File::dllPath("digidocppd.dll");
#elif defined(_WIN32)
            string path = File::dllPath("digidocpp.dll");
#elif defined(FRAMEWORK)
            string path = File::frameworkResourcesPath("ee.ria.digidocpp");
#else
            string path = DIGIDOCPP_CONFIG_DIR;
#endif
            init(File::path(path, "/digidocpp.conf"), true);
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
                PKCS12Cert.setValue(p, p.lock(), global);
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
 * @throws IOException exception is thrown if reading, writing or creating of a user configuration file fails.
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
 * Initialize xml conf from path
 * @param path to use for initializing conf
 * @return
 */
XmlConf::XmlConf(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}
XmlConfV2::XmlConfV2(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}
XmlConfV3::XmlConfV3(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}

XmlConf::~XmlConf() { delete d; }
XmlConfV2::~XmlConfV2() { delete d; }
XmlConfV3::~XmlConfV3() { delete d; }

/**
 * Gets log level.
 * @return log level.
 */
GET1(int, logLevel)

/**
 * Gets log file location.
 * @return log path location.
 */
GET1(string, logFile)

/**
 * Gets Manifest schema file location.
 * @return Manifest schema full path location.
 */
GET1_R(string, xsdPath)

/**
 * Gets PKCS11 driver file path.
 * @return PKCS11 driver file location.
 */
GET1(string, PKCS11Driver)

/**
 * Gets OCSP data by issuer.
 * @param issuer OCSP issuer.
 * @return returns OCSP data structure, containing issuer, url and certificate location.
 */
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

/**
 * Gets Certificate store location.
 * @return Certificate store full path location.
 */
GET1_R(string, certsPath)

/**
 * Gets proxy host address.
 * @return proxy host address.
 */
GET1(string, proxyHost)

/**
 * Gets proxy port number.
 * @return proxy port.
 */
GET1(string, proxyPort)

/**
 * Gets proxy user name.
 * @return proxy user name.
 */
GET1(string, proxyUser)

/**
 * Gets proxy login password.
 * @return proxy password.
 */
GET1(string, proxyPass)

/**
 * Gets PKCS12 certificate file location.
 * @return PKCS12 certificate full path location.
 */
GET1(string, PKCS12Cert)

/**
 * Gets PKCS12 password.
 * @return PKCS12 password.
 */
GET1(string, PKCS12Pass)

/**
 * Gets PKCS12 usage.
 * @return PKCS12 usage.
 */
GET1(bool, PKCS12Disable)

GET2(string, TSUrl)
GET2(bool, TSLAutoUpdate)
GET2(string, TSLCache)
GET2_R(X509Cert, TSLCert)
GET2_R(string, TSLUrl)

bool XmlConfV3::TSLOnlineDigest() const
{
    return d->TSLOnlineDigest.value(ConfV3::TSLOnlineDigest());
}

void XmlConfV3::setTSLOnlineDigest( bool enable )
{
    if( !d->TSLOnlineDigest.locked )
        d->setUserConf(d->TSLOnlineDigest.name, ConfV3::TSLOnlineDigest() ? "true" : "false", (d->TSLOnlineDigest = enable) ? "true" : "false");
}

/**
 * Sets a Proxy host address. Also adds or replaces proxy host data in the user configuration file.
 *
 * @param host proxy host address.
 * @throws IOException exception is thrown if saving a proxy host address into a user configuration file fails.
 */
SET1(string, setProxyHost, proxyHost)

/**
 * Sets a Proxy port number. Also adds or replaces proxy port data in the user configuration file.
 *
 * @param port proxy port number.
 * @throws IOException exception is thrown if saving a proxy port number into a user configuration file fails.
 */
SET1(string, setProxyPort, proxyPort)

/**
 * Sets a Proxy user name. Also adds or replaces proxy user name in the user configuration file.
 *
 * @param user proxy user name.
 * @throws IOException exception is thrown if saving a proxy user name into a user configuration file fails.
 */
SET1(string, setProxyUser, proxyUser)

/**
 * Sets a Proxy password. Also adds or replaces proxy password in the user configuration file.
 *
 * @param pass proxy password.
 * @throws IOException exception is thrown if saving a proxy password into a user configuration file fails.
 */
SET1(string, setProxyPass, proxyPass)

/**
 * Sets a PKCS#12 certficate path. Also adds or replaces PKCS#12 certificate path in the user configuration file.
 * By default the PKCS#12 certificate file should be located at default path, given by getUserConfDir() function.
 *
 * @param cert PKCS#12 certificate location path.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate path into a user configuration file fails.
 */
SET1(string, setPKCS12Cert, PKCS12Cert)

/**
 * Sets a PKCS#12 certificate password. Also adds or replaces PKCS#12 certificate password in the user configuration file.
 *
 * @param pass PKCS#12 certificate password.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate password into a user configuration file fails.
 */
SET1(string, setPKCS12Pass, PKCS12Pass)

/**
 * Sets a PKCS#12 certificate usage. Also adds or replaces PKCS#12 certificate usage in the user configuration file.
 *
 * @param pass PKCS#12 certificate usage.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate usage into a user configuration file fails.
 */
void XmlConf::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
void XmlConfV2::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
void XmlConfV3::setPKCS12Disable( bool disable )
{
    if( !d->PKCS12Disable.locked )
        d->setUserConf(d->PKCS12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->PKCS12Disable = disable) ? "true" : "false");
}
