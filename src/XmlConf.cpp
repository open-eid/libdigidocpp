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

#ifdef ANDROID
template <typename T>
static string to_string(T value)
{
    ostringstream os;
    os << value;
    return os.str();
}

static int stoi(const string &value)
{
    int result = 0;
    stringstream ss(value);
    ss >> result;
    return result;
}
#endif

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
    template <class A>
    void setUserConf(XmlConfParam<A> &param, const A &defined, const A &value);
    string tostring(bool val) const { return val ? "true" : "false"; }
    string tostring(int val) const { return to_string(val); }
    string tostring(const string &val) const { return val; }


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
    XmlConfParam<string> PKCS12Cert;
    XmlConfParam<string> PKCS12Pass;
    XmlConfParam<bool> PKCS12Disable;
    XmlConfParam<string> TSUrl;
    XmlConfParam<bool> TSLAutoUpdate;
    XmlConfParam<string> TSLCache;
    XmlConfParam<bool> TSLOnlineDigest;
    XmlConfParam<int> TSLTimeOut;
    XmlConfParam<string> verifyServiceUri;
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
    , proxyForceSSL("proxy.forceSSL", false)
    , proxyTunnelSSL("proxy.tunnelSSL", true)
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
    , verifyServiceUri("verify.serivceUri")
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
void XmlConfPrivate::init(const string& path, bool global)
{
    DEBUG("XmlConfPrivate::init(%s, %u)", path.c_str(), global);
    try
    {
        unique_ptr<Configuration> conf = read(path);
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
            else if(p.name() == proxyForceSSL.name)
                proxyForceSSL.setValue(p == "true", p.lock(), global);
            else if(p.name() == proxyTunnelSSL.name)
                proxyTunnelSSL.setValue(p == "true", p.lock(), global);
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
            else if(p.name() == verifyServiceUri.name)
                verifyServiceUri.setValue(p, p.lock(), global);
            else
                WARN("Unknown configuration parameter %s", p.name().c_str());
        }

        for(const Configuration::OcspType &o: conf->ocsp())
            ocsp[o.issuer()] = o;
    }
    catch(const Exception &e)
    {
        WARN("Failed to parse configuration: %s %s %u", path.c_str(), global, e.msg().c_str());
    }
    catch(const xml_schema::Exception &e)
    {
        WARN("Failed to parse configuration: %s %s %u", path.c_str(), global, e.what());
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
    return unique_ptr<Configuration>(new Configuration);
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
void XmlConfPrivate::setUserConf(XmlConfParam<A> &param, const A &defined, const A &value)
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
            paramSeq.push_back(Param(tostring(value), param.name));
    }
    catch (const xml_schema::Exception& e)
    {
        THROW("(in set %s) Failed to parse configuration: %s", param.name.c_str(), e.what());
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
 * @see digidoc::Conf
 */
XmlConf::XmlConf(const string &path, const string &schema)
    : d(new XmlConfPrivate(path, schema.empty() ? File::path(Conf::xsdPath(), "conf.xsd") : schema))
{}
XmlConf::~XmlConf() { delete d; }

#define GET1(TYPE, PROP) \
TYPE XmlConf::PROP() const { return d->PROP.value(Conf::PROP()); }

#define SET1(TYPE, SET, PROP) \
void XmlConf::SET(TYPE PROP) \
{ d->setUserConf<TYPE>(d->PROP, Conf::PROP(), PROP); }

#define SET1CONST(TYPE, SET, PROP) \
void XmlConf::SET(const TYPE &PROP) \
{ d->setUserConf<TYPE>(d->PROP, Conf::PROP(), PROP); }

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

/**
 * @fn void digidoc::XmlConf::setTSLOnlineDigest( bool enable )
 * Enables/Disables online digest check
 * @throws Exception exception is thrown if saving a TSL online digest into a user configuration file fails.
 */
SET1(bool, setTSLOnlineDigest, TSLOnlineDigest)

/**
 * @fn void digidoc::XmlConf::setTSLTimeOut( int timeOut )
 * Sets TSL connection timeout
 * @param timeOut Time out in seconds
 * @throws Exception exception is thrown if saving a TSL timeout into a user configuration file fails.
 */
SET1(int, setTSLTimeOut, TSLTimeOut)

/**
 * @fn void digidoc::XmlConf::setProxyHost(const std::string &host)
 * Sets a Proxy host address. Also adds or replaces proxy host data in the user configuration file.
 *
 * @param host proxy host address.
 * @throws Exception exception is thrown if saving a proxy host address into a user configuration file fails.
 */
SET1CONST(string, setProxyHost, proxyHost)

/**
 * @fn void digidoc::XmlConf::setProxyPort(const std::string &port)
 * Sets a Proxy port number. Also adds or replaces proxy port data in the user configuration file.
 *
 * @param port proxy port number.
 * @throws Exception exception is thrown if saving a proxy port number into a user configuration file fails.
 */
SET1CONST(string, setProxyPort, proxyPort)

/**
 * @fn void digidoc::XmlConf::setProxyUser(const std::string &user)
 * Sets a Proxy user name. Also adds or replaces proxy user name in the user configuration file.
 *
 * @param user proxy user name.
 * @throws Exception exception is thrown if saving a proxy user name into a user configuration file fails.
 */
SET1CONST(string, setProxyUser, proxyUser)

/**
 * @fn void digidoc::XmlConf::setProxyPass(const std::string &pass)
 * Sets a Proxy password. Also adds or replaces proxy password in the user configuration file.
 *
 * @param pass proxy password.
 * @throws Exception exception is thrown if saving a proxy password into a user configuration file fails.
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
SET1CONST(string, setPKCS12Cert, PKCS12Cert)

/**
 * @fn void digidoc::XmlConf::setPKCS12Pass(const std::string &pass)
 * Sets a PKCS#12 certificate password. Also adds or replaces PKCS#12 certificate password in the user configuration file.
 *
 * @param pass PKCS#12 certificate password.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate password into a user configuration file fails.
 */
SET1CONST(string, setPKCS12Pass, PKCS12Pass)

/**
 * @fn void digidoc::XmlConf::setPKCS12Disable( bool disable )
 * Sets a PKCS#12 certificate usage. Also adds or replaces PKCS#12 certificate usage in the user configuration file.
 *
 * @param disable PKCS#12 certificate usage.
 * @throws Exception exception is thrown if saving a PKCS#12 certificate usage into a user configuration file fails.
 */
SET1(bool, setPKCS12Disable, PKCS12Disable)

/**
 * Enables SSL proxy connections
 * @throws Exception exception is thrown if saving into a user configuration file fails.
 */
void XmlConf::setProxyTunnelSSL(bool enable)
{
    d->setUserConf<bool>(d->proxyTunnelSSL, Conf::proxyTunnelSSL(), enable);
}
