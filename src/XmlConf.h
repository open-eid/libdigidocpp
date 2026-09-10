// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Conf.h"

#include <memory>

namespace digidoc
{

class DIGIDOCPP_EXPORT XmlConf: public Conf
{
public:
    explicit XmlConf(const std::string &path = "", const std::string &schema = "");
    ~XmlConf() override;
    static XmlConf* instance();

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

    DIGIDOCPP_DEPRECATED std::string PKCS12Cert() const override;
    DIGIDOCPP_DEPRECATED std::string PKCS12Pass() const override;
    DIGIDOCPP_DEPRECATED bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Cert( const std::string &cert );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Pass( const std::string &pass );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

    virtual void setTSUrl(const std::string &url);
    virtual void setVerifyServiceUri(const std::string &url);

private:
    DISABLE_COPY(XmlConf);

    class Private;
    std::unique_ptr<Private> d;
    friend class XmlConfV2;
    friend class XmlConfV3;
    friend class XmlConfV4;
    friend class XmlConfV5;
};

class DIGIDOCPP_EXPORT XmlConfV2: public ConfV2
{
public:
    explicit XmlConfV2(const std::string &path = "", const std::string &schema = "");
    ~XmlConfV2() override;
    static XmlConfV2* instance();

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

    DIGIDOCPP_DEPRECATED std::string PKCS12Cert() const override;
    DIGIDOCPP_DEPRECATED std::string PKCS12Pass() const override;
    DIGIDOCPP_DEPRECATED bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Cert( const std::string &cert );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Pass( const std::string &pass );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

    virtual void setTSUrl(const std::string &url);
    virtual void setVerifyServiceUri(const std::string &url);

private:
    DISABLE_COPY(XmlConfV2);

    std::unique_ptr<XmlConf::Private> d;
};

class DIGIDOCPP_EXPORT XmlConfV3: public ConfV3
{
public:
    explicit XmlConfV3(const std::string &path = {}, const std::string &schema = {});
    ~XmlConfV3() override;
    static XmlConfV3* instance();

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

    DIGIDOCPP_DEPRECATED std::string PKCS12Cert() const override;
    DIGIDOCPP_DEPRECATED std::string PKCS12Pass() const override;
    DIGIDOCPP_DEPRECATED bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Cert( const std::string &cert );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Pass( const std::string &pass );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

    virtual void setTSUrl(const std::string &url);
    virtual void setVerifyServiceUri(const std::string &url);

private:
    DISABLE_COPY(XmlConfV3);

    std::unique_ptr<XmlConf::Private> d;
};

class DIGIDOCPP_EXPORT XmlConfV4: public ConfV4
{
public:
    explicit XmlConfV4(const std::string &path = {}, const std::string &schema = {});
    ~XmlConfV4() override;
    static XmlConfV4* instance();

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
    std::vector<X509Cert> verifyServiceCerts() const override;
    std::string verifyServiceUri() const override;

    DIGIDOCPP_DEPRECATED std::string PKCS12Cert() const override;
    DIGIDOCPP_DEPRECATED std::string PKCS12Pass() const override;
    DIGIDOCPP_DEPRECATED bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Cert( const std::string &cert );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Pass( const std::string &pass );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

    virtual void setTSUrl(const std::string &url);
    virtual void setVerifyServiceUri(const std::string &url);

private:
    DISABLE_COPY(XmlConfV4);

    std::unique_ptr<XmlConf::Private> d;
};

class DIGIDOCPP_EXPORT XmlConfV5: public ConfV5
{
public:
    explicit XmlConfV5(const std::string &path = {}, const std::string &schema = {});
    ~XmlConfV5() override;
    static XmlConfV5* instance();

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
    std::vector<X509Cert> TSCerts() const override;
    std::string TSUrl() const override;
    X509Cert verifyServiceCert() const override;
    std::vector<X509Cert> verifyServiceCerts() const override;
    std::string verifyServiceUri() const override;

    DIGIDOCPP_DEPRECATED std::string PKCS12Cert() const override;
    DIGIDOCPP_DEPRECATED std::string PKCS12Pass() const override;
    DIGIDOCPP_DEPRECATED bool PKCS12Disable() const override;

    bool TSLAutoUpdate() const override;
    std::string TSLCache() const override;
    bool TSLOnlineDigest() const override;
    int TSLTimeOut() const override;

    virtual void setProxyHost( const std::string &host );
    virtual void setProxyPort( const std::string &port );
    virtual void setProxyUser( const std::string &user );
    virtual void setProxyPass( const std::string &pass );
    virtual void setProxyTunnelSSL( bool enable );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Cert( const std::string &cert );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Pass( const std::string &pass );
    DIGIDOCPP_DEPRECATED virtual void setPKCS12Disable( bool disable );

    virtual void setTSLOnlineDigest( bool enable );
    virtual void setTSLTimeOut( int timeOut );

    virtual void setTSUrl(const std::string &url);
    virtual void setVerifyServiceUri(const std::string &url);

private:
    DISABLE_COPY(XmlConfV5);

    std::unique_ptr<XmlConf::Private> d;
};

using XmlConfCurrent = XmlConfV5;
}
