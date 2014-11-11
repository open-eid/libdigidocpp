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

#include <set>

namespace digidoc
{
namespace tsl { class TrustStatusListType; class InternationalNamesType; }
class TSL
{
public:
    TSL(const std::string &file, const std::string &url);
    ~TSL();
    void validateRemoteDigest();
    void validate(const std::vector<X509Cert> &certs);

    std::string type() const;
    std::string operatorName() const;
    std::string territory() const;
    std::string issueDate() const;
    std::string nextUpdate() const;

    std::string path, url;
    struct Pointer { std::string territory, location; std::vector<X509Cert> certs; };
    std::vector<Pointer> pointer;
    std::vector<X509Cert> certs() const;

    static std::vector<X509Cert> parse();

private:
    static std::vector<X509Cert> parse(const std::string &url, const std::vector<X509Cert> &certs,
        const std::string &cache, const std::string &territory);

    static const std::set<std::string> SCHEMES_URI;
    static const std::set<std::string> GENERIC_URI;
    static const std::set<std::string> SERVICETYPE;
    static const std::set<std::string> SERVICESTATUS;

    std::string toString(const tsl::InternationalNamesType &obj, const std::string &lang = "en") const;
    std::shared_ptr<tsl::TrustStatusListType> tsl;
};
}
