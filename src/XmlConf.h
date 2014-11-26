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

#pragma once

#include "Conf.h"

namespace digidoc
{

class XmlConfPrivate;
class DEPRECATED_DIGIDOC EXP_DIGIDOC XmlConf: public Conf
{
public:
    XmlConf(const std::string &path = "", const std::string &schema = "");
    virtual ~XmlConf();

    virtual int logLevel() const;
    virtual std::string logFile() const;
    virtual std::string xsdPath() const;
    virtual std::string PKCS11Driver() const;
    virtual std::string ocsp(const std::string &issuer) const;
    DEPRECATED_DIGIDOC virtual std::string certsPath() const;
    virtual std::string proxyHost() const;
    virtual std::string proxyPort() const;
    virtual std::string proxyUser() const;
    virtual std::string proxyPass() const;
    virtual std::string PKCS12Cert() const;
    virtual std::string PKCS12Pass() const;
    virtual bool PKCS12Disable() const;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setPKCS12Cert( const std::string &cert );
    virtual void setPKCS12Pass( const std::string &pass );
    virtual void setPKCS12Disable( bool disable );

private:
    DISABLE_COPY(XmlConf);

    XmlConfPrivate *d;
};

class DEPRECATED_DIGIDOC EXP_DIGIDOC XmlConfV2: public ConfV2
{
public:
    explicit XmlConfV2(const std::string &path = "", const std::string &schema = "");
    virtual ~XmlConfV2();

    virtual int logLevel() const;
    virtual std::string logFile() const;
    virtual std::string xsdPath() const;
    virtual std::string PKCS11Driver() const;
    virtual std::string ocsp(const std::string &issuer) const;
    DEPRECATED_DIGIDOC virtual std::string certsPath() const;
    virtual std::string proxyHost() const;
    virtual std::string proxyPort() const;
    virtual std::string proxyUser() const;
    virtual std::string proxyPass() const;
    virtual std::string PKCS12Cert() const;
    virtual std::string PKCS12Pass() const;
    virtual bool PKCS12Disable() const;
    virtual std::string TSUrl() const;
    virtual bool TSLAutoUpdate() const;
    virtual std::string TSLCache() const;
    virtual X509Cert TSLCert() const;
    virtual std::string TSLUrl() const;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setPKCS12Cert( const std::string &cert );
    virtual void setPKCS12Pass( const std::string &pass );
    virtual void setPKCS12Disable( bool disable );

private:
    DISABLE_COPY(XmlConfV2);

    XmlConfPrivate *d;
};

class EXP_DIGIDOC XmlConfV3: public ConfV3
{
public:
    explicit XmlConfV3(const std::string &path = "", const std::string &schema = "");
    virtual ~XmlConfV3();

    virtual int logLevel() const;
    virtual std::string logFile() const;
    virtual std::string xsdPath() const;
    virtual std::string PKCS11Driver() const;
    virtual std::string ocsp(const std::string &issuer) const;
    DEPRECATED_DIGIDOC virtual std::string certsPath() const;
    virtual std::string proxyHost() const;
    virtual std::string proxyPort() const;
    virtual std::string proxyUser() const;
    virtual std::string proxyPass() const;
    virtual std::string PKCS12Cert() const;
    virtual std::string PKCS12Pass() const;
    virtual bool PKCS12Disable() const;
    virtual std::string TSUrl() const;
    virtual bool TSLAutoUpdate() const;
    virtual std::string TSLCache() const;
    virtual X509Cert TSLCert() const;
    virtual bool TSLOnlineDigest() const;
    virtual int TSLTimeOut() const;
    virtual std::string TSLUrl() const;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setPKCS12Cert( const std::string &cert );
    virtual void setPKCS12Pass( const std::string &pass );
    virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

private:
    DISABLE_COPY(XmlConfV3);

    XmlConfPrivate *d;
};

}
