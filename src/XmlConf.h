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
class EXP_DIGIDOC XmlConf: public Conf
{
public:
    explicit XmlConf(const std::string &path = "", const std::string &schema = "");
    virtual ~XmlConf();

    virtual int logLevel() const override;
    virtual std::string logFile() const override;
    virtual std::string PKCS11Driver() const override;

    virtual std::string proxyHost() const override;
    virtual std::string proxyPort() const override;
    virtual std::string proxyUser() const override;
    virtual std::string proxyPass() const override;
    virtual bool proxyForceSSL() const override;
    virtual bool proxyTunnelSSL() const override;

    virtual std::string digestUri() const override;
    virtual std::string signatureDigestUri() const override;
    virtual std::string ocsp(const std::string &issuer) const override;
    virtual std::string TSUrl() const override;

    virtual std::string PKCS12Cert() const override;
    virtual std::string PKCS12Pass() const override;
    virtual bool PKCS12Disable() const override;

    virtual bool TSLAutoUpdate() const override;
    virtual std::string TSLCache() const override;
    virtual bool TSLOnlineDigest() const override;
    virtual int TSLTimeOut() const override;

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

    XmlConfPrivate *d;
};
}
