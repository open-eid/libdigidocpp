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

class EXP_DIGIDOC XmlConf: public Conf
{
public:
    explicit XmlConf(const std::string &path = "", const std::string &schema = "");
    ~XmlConf() override;

    int logLevel() const override;
    std::string logFile() const override;
    std::string PKCS11Driver() const override;

    std::string proxyHost() const override;
    std::string proxyPort() const override;
    std::string proxyUser() const override;
    std::string proxyPass() const override;
    bool proxyForceSSL() const override;
    bool proxyTunnelSSL() const override;

    std::string digestUri() const override;
    std::string signatureDigestUri() const override;
    std::string ocsp(const std::string &issuer) const override;
    std::string TSUrl() const override;
    std::string verifyServiceUri() const override;

    std::string PKCS12Cert() const override;
    std::string PKCS12Pass() const override;
    bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    virtual void setPKCS12Cert( const std::string &cert );
    virtual void setPKCS12Pass( const std::string &pass );
    virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

private:
    DISABLE_COPY(XmlConf);

    class Private;
    Private *d;
    friend class XmlConfV2;
    friend class XmlConfV3;
};

class EXP_DIGIDOC XmlConfV2: public ConfV2
{
public:
    explicit XmlConfV2(const std::string &path = "", const std::string &schema = "");
    ~XmlConfV2() override;

    int logLevel() const override;
    std::string logFile() const override;
    std::string PKCS11Driver() const override;

    std::string proxyHost() const override;
    std::string proxyPort() const override;
    std::string proxyUser() const override;
    std::string proxyPass() const override;
    bool proxyForceSSL() const override;
    bool proxyTunnelSSL() const override;

    std::string digestUri() const override;
    std::string signatureDigestUri() const override;
    std::string ocsp(const std::string &issuer) const override;
    std::string TSUrl() const override;
    X509Cert verifyServiceCert() const override;
    std::string verifyServiceUri() const override;

    std::string PKCS12Cert() const override;
    std::string PKCS12Pass() const override;
    bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    virtual void setPKCS12Cert( const std::string &cert );
    virtual void setPKCS12Pass( const std::string &pass );
    virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

private:
    DISABLE_COPY(XmlConfV2);

    XmlConf::Private *d;
};

class EXP_DIGIDOC XmlConfV3: public ConfV3
{
public:
    explicit XmlConfV3(const std::string &path = {}, const std::string &schema = {});
    ~XmlConfV3() override;

    int logLevel() const override;
    std::string logFile() const override;
    std::string PKCS11Driver() const override;

    std::string proxyHost() const override;
    std::string proxyPort() const override;
    std::string proxyUser() const override;
    std::string proxyPass() const override;
    bool proxyForceSSL() const override;
    bool proxyTunnelSSL() const override;

    std::string digestUri() const override;
    std::string signatureDigestUri() const override;
    std::string ocsp(const std::string &issuer) const override;
    std::set<std::string> OCSPTMProfiles() const override;
    std::string TSUrl() const override;
    X509Cert verifyServiceCert() const override;
    std::string verifyServiceUri() const override;

    std::string PKCS12Cert() const override;
    std::string PKCS12Pass() const override;
    bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    virtual void setPKCS12Cert( const std::string &cert );
    virtual void setPKCS12Pass( const std::string &pass );
    virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

private:
    DISABLE_COPY(XmlConfV3);

    XmlConf::Private *d;
};

using XmlConfCurrent = XmlConfV3;
}
