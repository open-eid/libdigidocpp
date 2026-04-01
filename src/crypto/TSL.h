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

#include "X509Cert.h"

#include "XMLDocument.h"

#include <map>
#include <optional>

namespace digidoc
{
struct XMLNode;
class Exception;

class TSL: private XMLDocument
{
public:
    struct Qualifier { std::vector<std::string> qualifiers; std::vector<std::vector<std::string>> policySet; std::vector<std::map<X509Cert::KeyUsage,bool>> keyUsage; std::string assert_; };
    using Qualifiers = std::optional<std::vector<Qualifier>>;
    struct Service { std::vector<X509Cert> certs; std::map<std::string,Qualifiers> validity; std::string type, additional, name; };
    struct Pointer { std::string territory, location; std::vector<X509Cert> certs; };

    TSL(std::string file = {});
    bool isExpired() const;
    void validate() const;
    void validate(const std::vector<X509Cert> &certs, int recursion = 0) const;

    std::string_view type() const noexcept;
    std::string_view operatorName() const noexcept;
    std::string_view territory() const noexcept;
    unsigned long long sequenceNumber() const;
    std::string_view issueDate() const noexcept;
    std::string_view nextUpdate() const noexcept;
    std::string_view url() const noexcept;

    std::vector<Pointer> pointers() const;
    std::vector<Service> services() const;

    static bool activate(std::string_view territory);
    static std::vector<Service> parse(const std::string &url, const std::vector<X509Cert> &certs,
        const std::string &cache, std::string_view territory);

private:
    std::vector<std::string> pivotURLs() const;
    X509Cert signingCert() const;
    std::vector<X509Cert> signingCerts() const;
    bool validateETag(const std::string &url);
    bool validateRemoteDigest(const std::string &url);

    static std::string fetch(const std::string &url, const std::string &path);
    static void debugException(const Exception &e);
    static TSL parseTSL(const std::string &url, const std::vector<X509Cert> &certs,
        const std::string &cache, std::string_view territory) ;
    static bool parseInfo(XMLNode info, Service &s);
    static std::vector<X509Cert> serviceDigitalIdentity(XMLNode other, std::string_view ctx);
    static std::vector<X509Cert> serviceDigitalIdentities(XMLNode other, std::string_view ctx);
    static std::string_view toString(XMLNode obj, std::string_view lang = "en") noexcept;

    XMLNode schemeInformation;
    std::string path;
};
}
