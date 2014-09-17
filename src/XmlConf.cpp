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
        return unique_ptr<A>::get() ? *unique_ptr<A>::get() : _def;
    }
    A value(const A &def)
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
    struct OCSP { string issuer, url; };
    XmlConfPrivate(const string &path = "", const string &schema = "");

    void init(const string &path, bool global);
    unique_ptr<Configuration> read(const string &path);
    void setUserConf(const string &paramName, const string &defined, const string &value);

    XmlConfParam<int> logLevel;
    XmlConfParam<string> logFile;
    XmlConfParam<string> pkcs11DriverPath;
    XmlConfParam<string> xsdPath;
    XmlConfParam<string> proxyHost;
    XmlConfParam<string> proxyPort;
    XmlConfParam<string> proxyUser;
    XmlConfParam<string> proxyPass;
    XmlConfParam<string> pkcs12Cert;
    XmlConfParam<string> pkcs12Pass;
    XmlConfParam<bool> pkcs12Disable;
    XmlConfParam<string> tsurl;
    XmlConfParam<bool> tslautoupdate;
    XmlConfParam<string> tslcache;
    vector<OCSP> ocsp;

    string SCHEMA_LOC;
    string DEFAULT_CONF_LOC;
    string USER_CONF_LOC;
};
}

using namespace digidoc;

XmlConfPrivate::XmlConfPrivate(const string &path, const string &schema)
    : logLevel("log.level")
    , logFile("log.file")
    , pkcs11DriverPath("pkcs11.driver.path")
    , xsdPath("xsd.path")
    , proxyHost("proxy.host")
    , proxyPort("proxy.port")
    , proxyUser("proxy.user")
    , proxyPass("proxy.pass")
    , pkcs12Cert("pkcs12.cert")
    , pkcs12Pass("pkcs12.pass")
    , pkcs12Disable("pkcs12.disable")
    , tsurl("ts.url")
    , tslautoupdate("tsl.autoupdate", true)
    , tslcache("tsl.cache")
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

#ifdef _WIN32
#ifdef _DEBUG
    DEFAULT_CONF_LOC = File::dllPath("digidocppd.dll");
#else
    DEFAULT_CONF_LOC = File::dllPath("digidocpp.dll");
#endif
    if(!File::directoryExists(DEFAULT_CONF_LOC + "schema"))
        DEFAULT_CONF_LOC = File::cwd();
#elif defined(FRAMEWORK)
    DEFAULT_CONF_LOC = File::frameworkResourcesPath("ee.ria.digidocpp");
#else
    DEFAULT_CONF_LOC = DIGIDOCPP_CONFIG_DIR;
#endif
    SCHEMA_LOC = schema.empty() ? File::path(DEFAULT_CONF_LOC, "schema/conf.xsd") : schema;

    if(path.empty())
    {
        try
        {
            init(DEFAULT_CONF_LOC + "/digidocpp.conf", true);
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
        const Configuration::ParamSequence &paramSeq = conf->param();
        for( Configuration::ParamSequence::const_iterator i = paramSeq.begin(); i != paramSeq.end(); ++i)
        {
            if(i->name() == logLevel.name)
                logLevel.setValue(atoi(string(*i).c_str()), i->lock(), global);
            else if(i->name() == logFile.name)
                logFile.setValue(*i, i->lock(), global);
            else if(i->name() == xsdPath.name)
                xsdPath.setValue(*i, i->lock(), global);
            else if(i->name() == pkcs11DriverPath.name)
                pkcs11DriverPath.setValue(*i, i->lock(), global);
            else if(i->name() == proxyHost.name)
                proxyHost.setValue(*i, i->lock(), global);
            else if(i->name() == proxyPort.name)
                proxyPort.setValue(*i, i->lock(), global);
            else if(i->name() == proxyUser.name)
                proxyUser.setValue(*i, i->lock(), global);
            else if(i->name() == proxyPass.name)
                proxyPass.setValue(*i, i->lock(), global);
            else if(i->name() == pkcs12Cert.name)
                pkcs12Cert.setValue(*i, i->lock(), global);
            else if(i->name() == pkcs12Pass.name)
                pkcs12Pass.setValue(*i, i->lock(), global);
            else if(i->name() == pkcs12Disable.name)
                pkcs12Disable.setValue(*i == "true", i->lock(), global);
            else if(i->name() == tsurl.name)
                tsurl.setValue(*i, i->lock(), global);
            else if(i->name() == tslautoupdate.name)
                tslautoupdate.setValue(*i == "true", i->lock(), global);
            else if(i->name() == tslcache.name)
                tslcache.setValue(*i, i->lock(), global);
            else
                WARN("Unknown configuration parameter %s", i->name().c_str());
        }

        Configuration::OcspSequence ocspSeq = conf->ocsp();
        for(Configuration::OcspSequence::const_iterator it = ocspSeq.begin(); it != ocspSeq.end(); ++it)
        {
            OCSP o = { it->issuer(), *it };
            ocsp.push_back(o);
        }
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
        return unique_ptr<Configuration>(configuration(path, Flags::dont_initialize, props).release());
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
    : d(new XmlConfPrivate(path, schema))
{
}

XmlConf::~XmlConf()
{
    delete d;
}

/**
 * Gets log level.
 * @return log level.
 */
int XmlConf::logLevel() const
{
    return d->logLevel.value(Conf::logLevel());
}

/**
 * Gets log file location.
 * @return log path location.
 */
string XmlConf::logFile() const
{
    return d->logFile.value(Conf::logFile());
}

/**
 * Gets Manifest schema file location.
 * @return Manifest schema full path location.
 */
string XmlConf::xsdPath() const
{
    string path = d->xsdPath.value(Conf::xsdPath());
    return File::isRelative(path) ? d->DEFAULT_CONF_LOC + "/" + path : path;
}

/**
 * Gets PKCS11 driver file path.
 * @return PKCS11 driver file location.
 */
string XmlConf::PKCS11Driver() const
{
    return d->pkcs11DriverPath.value(Conf::PKCS11Driver());
}

/**
 * Gets OCSP data by issuer.
 * @param issuer OCSP issuer.
 * @return returns OCSP data structure, containing issuer, url and certificate location.
 */
string XmlConf::ocsp(const string &issuer) const
{
    for(vector<XmlConfPrivate::OCSP>::const_iterator i = d->ocsp.begin(); i != d->ocsp.end(); ++i)
    {
        if(i->issuer == issuer)
            return i->url;
    }
    return Conf::ocsp(issuer);
}

/**
 * Gets Certificate store location.
 * @return Certificate store full path location.
 */
string XmlConf::certsPath() const
{
    return Conf::certsPath();
}

/**
 * Gets proxy host address.
 * @return proxy host address.
 */
string XmlConf::proxyHost() const
{
    return d->proxyHost.value(Conf::proxyHost());
}

/**
 * Gets proxy port number.
 * @return proxy port.
 */
string XmlConf::proxyPort() const
{
    return d->proxyPort.value(Conf::proxyPort());
}

/**
 * Gets proxy user name.
 * @return proxy user name.
 */
string XmlConf::proxyUser() const
{
    return d->proxyUser.value(Conf::proxyUser());
}

/**
 * Gets proxy login password.
 * @return proxy password.
 */
string XmlConf::proxyPass() const
{
    return d->proxyPass.value(Conf::proxyPass());
}

/**
 * Gets PKCS12 certificate file location.
 * @return PKCS12 certificate full path location.
 */
string XmlConf::PKCS12Cert() const
{
    return d->pkcs12Cert.value(Conf::PKCS12Cert());
}

/**
 * Gets PKCS12 password.
 * @return PKCS12 password.
 */
string XmlConf::PKCS12Pass() const
{
    return d->pkcs12Pass.value(Conf::PKCS12Pass());
}

/**
 * Gets PKCS12 usage.
 * @return PKCS12 usage.
 */
bool XmlConf::PKCS12Disable() const
{
    return d->pkcs12Disable.value(Conf::PKCS12Disable());
}

/**
 * Sets a Proxy host address. Also adds or replaces proxy host data in the user configuration file.
 *
 * @param host proxy host address.
 * @throws IOException exception is thrown if saving a proxy host address into a user configuration file fails.
 */
void XmlConf::setProxyHost( const string &host )
{
    if( !d->proxyHost.locked )
        d->setUserConf(d->proxyHost.name, Conf::proxyHost(), d->proxyHost = host);
}

/**
 * Sets a Proxy port number. Also adds or replaces proxy port data in the user configuration file.
 *
 * @param port proxy port number.
 * @throws IOException exception is thrown if saving a proxy port number into a user configuration file fails.
 */
void XmlConf::setProxyPort( const string &port )
{
    if( !d->proxyPort.locked )
        d->setUserConf(d->proxyPort.name, Conf::proxyPort(), d->proxyPort = port);
}

/**
 * Sets a Proxy user name. Also adds or replaces proxy user name in the user configuration file.
 *
 * @param user proxy user name.
 * @throws IOException exception is thrown if saving a proxy user name into a user configuration file fails.
 */
void XmlConf::setProxyUser( const string &user )
{
    if( !d->proxyUser.locked )
        d->setUserConf(d->proxyUser.name, Conf::proxyUser(), d->proxyUser = user);
}

/**
 * Sets a Proxy password. Also adds or replaces proxy password in the user configuration file.
 *
 * @param pass proxy password.
 * @throws IOException exception is thrown if saving a proxy password into a user configuration file fails.
 */
void XmlConf::setProxyPass( const string &pass )
{
    if( !d->proxyPass.locked )
        d->setUserConf(d->proxyPass.name, Conf::proxyPass(), d->proxyPass = pass);
}

/**
 * Sets a PKCS#12 certficate path. Also adds or replaces PKCS#12 certificate path in the user configuration file.
 * By default the PKCS#12 certificate file should be located at default path, given by getUserConfDir() function.
 *
 * @param cert PKCS#12 certificate location path.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate path into a user configuration file fails.
 */
void XmlConf::setPKCS12Cert( const string &cert )
{
    if( !d->pkcs12Cert.locked )
        d->setUserConf(d->pkcs12Cert.name, Conf::PKCS12Cert(), d->pkcs12Cert = cert);
}

/**
 * Sets a PKCS#12 certificate password. Also adds or replaces PKCS#12 certificate password in the user configuration file.
 *
 * @param pass PKCS#12 certificate password.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate password into a user configuration file fails.
 */
void XmlConf::setPKCS12Pass( const string &pass )
{
    if( !d->pkcs12Pass.locked )
        d->setUserConf(d->pkcs12Pass.name, Conf::PKCS12Pass(), d->pkcs12Pass = pass);
}

/**
 * Sets a PKCS#12 certificate usage. Also adds or replaces PKCS#12 certificate usage in the user configuration file.
 *
 * @param pass PKCS#12 certificate usage.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate usage into a user configuration file fails.
 */
void XmlConf::setPKCS12Disable( bool disable )
{
    if( !d->pkcs12Disable.locked )
        d->setUserConf(d->pkcs12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->pkcs12Disable = disable) ? "true" : "false");
}

/**
 * Initialize xml conf from path
 * @param path to use for initializing conf
 * @return
 */
XmlConfV2::XmlConfV2(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema))
{
}

XmlConfV2::~XmlConfV2()
{
    delete d;
}

/**
 * Gets log level.
 * @return log level.
 */
int XmlConfV2::logLevel() const
{
    return d->logLevel.value(Conf::logLevel());
}

/**
 * Gets log file location.
 * @return log path location.
 */
string XmlConfV2::logFile() const
{
    return d->logFile.value(Conf::logFile());
}

/**
 * Gets Manifest schema file location.
 * @return Manifest schema full path location.
 */
string XmlConfV2::xsdPath() const
{
    string path = d->xsdPath.value(Conf::xsdPath());
    return File::isRelative(path) ? d->DEFAULT_CONF_LOC + "/" + path : path;
}

/**
 * Gets PKCS11 driver file path.
 * @return PKCS11 driver file location.
 */
string XmlConfV2::PKCS11Driver() const
{
    return d->pkcs11DriverPath.value(Conf::PKCS11Driver());
}

/**
 * Gets OCSP data by issuer.
 * @param issuer OCSP issuer.
 * @return returns OCSP data structure, containing issuer, url and certificate location.
 */
string XmlConfV2::ocsp(const string &issuer) const
{
    for(vector<XmlConfPrivate::OCSP>::const_iterator i = d->ocsp.begin(); i != d->ocsp.end(); ++i)
    {
        if(i->issuer == issuer)
            return i->url;
    }
    return Conf::ocsp(issuer);
}

/**
 * Gets Certificate store location.
 * @return Certificate store full path location.
 */
string XmlConfV2::certsPath() const
{
    return Conf::certsPath();
}

/**
 * Gets proxy host address.
 * @return proxy host address.
 */
string XmlConfV2::proxyHost() const
{
    return d->proxyHost.value(Conf::proxyHost());
}

/**
 * Gets proxy port number.
 * @return proxy port.
 */
string XmlConfV2::proxyPort() const
{
    return d->proxyPort.value(Conf::proxyPort());
}

/**
 * Gets proxy user name.
 * @return proxy user name.
 */
string XmlConfV2::proxyUser() const
{
    return d->proxyUser.value(Conf::proxyUser());
}

/**
 * Gets proxy login password.
 * @return proxy password.
 */
string XmlConfV2::proxyPass() const
{
    return d->proxyPass.value(Conf::proxyPass());
}

/**
 * Gets PKCS12 certificate file location.
 * @return PKCS12 certificate full path location.
 */
string XmlConfV2::PKCS12Cert() const
{
    return d->pkcs12Cert.value(Conf::PKCS12Cert());
}

/**
 * Gets PKCS12 password.
 * @return PKCS12 password.
 */
string XmlConfV2::PKCS12Pass() const
{
    return d->pkcs12Pass.value(Conf::PKCS12Pass());
}

/**
 * Gets PKCS12 usage.
 * @return PKCS12 usage.
 */
bool XmlConfV2::PKCS12Disable() const
{
    return d->pkcs12Disable.value(Conf::PKCS12Disable());
}

string XmlConfV2::TSUrl() const
{
    return d->tsurl.value(ConfV2::TSUrl());
}

bool XmlConfV2::TSLAutoUpdate() const
{
    return d->tslautoupdate.value(ConfV2::TSLAutoUpdate());
}

string XmlConfV2::TSLCache() const
{
    return d->tslcache.value(ConfV2::TSLCache());
}

X509Cert XmlConfV2::TSLCert() const
{
    return ConfV2::TSLCert();
}

string XmlConfV2::TSLUrl() const
{
    return ConfV2::TSLUrl();
}

/**
 * Sets a Proxy host address. Also adds or replaces proxy host data in the user configuration file.
 *
 * @param host proxy host address.
 * @throws IOException exception is thrown if saving a proxy host address into a user configuration file fails.
 */
void XmlConfV2::setProxyHost( const string &host )
{
    if( !d->proxyHost.locked )
        d->setUserConf(d->proxyHost.name, Conf::proxyHost(), d->proxyHost = host);
}

/**
 * Sets a Proxy port number. Also adds or replaces proxy port data in the user configuration file.
 *
 * @param port proxy port number.
 * @throws IOException exception is thrown if saving a proxy port number into a user configuration file fails.
 */
void XmlConfV2::setProxyPort( const string &port )
{
    if( !d->proxyPort.locked )
        d->setUserConf(d->proxyPort.name, Conf::proxyPort(), d->proxyPort = port);
}

/**
 * Sets a Proxy user name. Also adds or replaces proxy user name in the user configuration file.
 *
 * @param user proxy user name.
 * @throws IOException exception is thrown if saving a proxy user name into a user configuration file fails.
 */
void XmlConfV2::setProxyUser( const string &user )
{
    if( !d->proxyUser.locked )
        d->setUserConf(d->proxyUser.name, Conf::proxyUser(), d->proxyUser = user);
}

/**
 * Sets a Proxy password. Also adds or replaces proxy password in the user configuration file.
 *
 * @param pass proxy password.
 * @throws IOException exception is thrown if saving a proxy password into a user configuration file fails.
 */
void XmlConfV2::setProxyPass( const string &pass )
{
    if( !d->proxyPass.locked )
        d->setUserConf(d->proxyPass.name, Conf::proxyPass(), d->proxyPass = pass);
}

/**
 * Sets a PKCS#12 certficate path. Also adds or replaces PKCS#12 certificate path in the user configuration file.
 * By default the PKCS#12 certificate file should be located at default path, given by getUserConfDir() function.
 *
 * @param cert PKCS#12 certificate location path.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate path into a user configuration file fails.
 */
void XmlConfV2::setPKCS12Cert( const string &cert )
{
    if( !d->pkcs12Cert.locked )
        d->setUserConf(d->pkcs12Cert.name, Conf::PKCS12Cert(), d->pkcs12Cert = cert);
}

/**
 * Sets a PKCS#12 certificate password. Also adds or replaces PKCS#12 certificate password in the user configuration file.
 *
 * @param pass PKCS#12 certificate password.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate password into a user configuration file fails.
 */
void XmlConfV2::setPKCS12Pass( const string &pass )
{
    if( !d->pkcs12Pass.locked )
        d->setUserConf(d->pkcs12Pass.name, Conf::PKCS12Pass(), d->pkcs12Pass = pass);
}

/**
 * Sets a PKCS#12 certificate usage. Also adds or replaces PKCS#12 certificate usage in the user configuration file.
 *
 * @param pass PKCS#12 certificate usage.
 * @throws IOException exception is thrown if saving a PKCS#12 certificate usage into a user configuration file fails.
 */
void XmlConfV2::setPKCS12Disable( bool disable )
{
    if( !d->pkcs12Disable.locked )
        d->setUserConf(d->pkcs12Disable.name, Conf::PKCS12Disable() ? "true" : "false", (d->pkcs12Disable = disable) ? "true" : "false");
}
