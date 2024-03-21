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

#include <map>
#include <optional>

namespace digidoc
{
class Exception;
namespace tsl { class TrustStatusListType; class InternationalNamesType; class OtherTSLPointerType; }

class TSL
{
public:
    struct Qualifier { std::vector<std::string> qualifiers; std::vector<std::vector<std::string>> policySet; std::vector<std::map<X509Cert::KeyUsage,bool>> keyUsage; std::string assert_; };
    using Qualifiers = std::optional<std::vector<Qualifier>>;
    struct Service { std::vector<X509Cert> certs; std::map<time_t,Qualifiers> validity; std::string type, additional, name; };
    struct Pointer { std::string territory, location; std::vector<X509Cert> certs; };

    TSL(std::string file = {});
    bool isExpired() const;
    void validate(const X509Cert &cert) const;
    void validate(const std::vector<X509Cert> &certs, int recursion = 0) const;

    std::string_view type() const;
    std::string_view operatorName() const;
    std::string territory() const;
    unsigned long long sequenceNumber() const;
    std::string issueDate() const;
    std::string nextUpdate() const;
    std::string url() const;

    std::vector<Pointer> pointers() const;
    std::vector<Service> services() const;

    static bool activate(const std::string &territory);
    static std::vector<Service> parse();

private:
    std::vector<std::string> pivotURLs() const;
    X509Cert signingCert() const;
    std::vector<X509Cert> signingCerts() const;
    bool validateETag(const std::string &url);
    bool validateRemoteDigest(const std::string &url);

    static std::string fetch(const std::string &url, const std::string &path);
    static void debugException(const Exception &e);
    static std::vector<Service> parse(const std::string &url, const std::vector<X509Cert> &certs,
        const std::string &cache, const std::string &territory);
    static TSL parseTSL(const std::string &url, const std::vector<X509Cert> &certs,
        const std::string &cache, const std::string &territory);
    template<class Info>
    static bool parseInfo(const Info &info, Service &s);
    static std::vector<X509Cert> serviceDigitalIdentities(const tsl::OtherTSLPointerType &other,
        std::string_view region);
    static std::string_view toString(const tsl::InternationalNamesType &obj, std::string_view lang = "en");

    std::shared_ptr<tsl::TrustStatusListType> tsl;
    std::string path;
};
}
