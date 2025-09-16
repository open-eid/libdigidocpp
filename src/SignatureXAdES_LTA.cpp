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

#include "SignatureXAdES_LTA.h"

#include "ASiC_E.h"
#include "DataFile_p.h"
#include "crypto/Digest.h"
#include "crypto/Signer.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "util/File.h"

#include <algorithm>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

namespace digidoc
{
constexpr XMLName ArchiveTimeStamp {"ArchiveTimeStamp", XADESv141_NS};
}

void SignatureXAdES_LTA::calcArchiveDigest(const Digest &digest, string_view canonicalizationMethod, XMLNode ts) const
{
    for(auto ref = signature/"SignedInfo"/"Reference"; ref; ref++)
    {
        auto uri = ref["URI"];
        if(ref["Type"] == REF_TYPE)
        {
            auto sp = qualifyingProperties()/"SignedProperties";
            if(uri.front() != '#' || sp["Id"] != uri.substr(1))
                THROW("Invalid SignedProperties ID");
            signatures->c14n(digest, canonicalizationMethod, sp);
            continue;
        }

        string uriPath = File::fromUriPath(uri);
        if(uriPath.front() == '/')
            uriPath.erase(0);

        auto files = bdoc->dataFiles();
        auto file = find_if(files.cbegin(), files.cend(), [&uriPath](DataFile *file) {
            return file->fileName() == uriPath;
        });
        if(file == files.cend())
            THROW("Filed to find reference URI in container");

        static_cast<const DataFilePrivate*>(*file)->digest(digest);
    }

    for(const auto *name: {"SignedInfo", "SignatureValue", "KeyInfo"})
    {
        if(auto elem = signature/name)
            signatures->c14n(digest, canonicalizationMethod, elem);
        else
            DEBUG("Element %s not found", name);
    }

    for(auto elem: unsignedSignatureProperties())
    {
        if(elem == ts)
            break;
        signatures->c14n(digest, canonicalizationMethod, elem);
    }
    //ds:Object
}

void SignatureXAdES_LTA::extendSignatureProfile(Signer *signer)
{
    if(SignatureXAdES_LTA::profile().find(ASiC_E::ASIC_TS_PROFILE) == string::npos)
        SignatureXAdES_LT::extendSignatureProfile(signer);
    if(signer->profile() != ASiC_E::ASIC_TSA_PROFILE)
        return;

    int i = 0;
    for(auto ts = unsignedSignatureProperties()/ArchiveTimeStamp; ts; ts++, ++i);

    Digest calc;
    auto method = canonicalizationMethod();
    calcArchiveDigest(calc, method, {});

    TS tsa(calc, signer->userAgent());
    auto ts = unsignedSignatureProperties() + ArchiveTimeStamp;
    ts.setNS(ts.addNS(XADESv141_NS, "xades141"));
    ts.setProperty("Id", id() + "-A" + to_string(i));
    (ts + CanonicalizationMethod).setProperty("Algorithm", method);
    ts + EncapsulatedTimeStamp = tsa;
}

vector<TSAInfo> SignatureXAdES_LTA::ArchiveTimeStamps() const
{
    vector<TSAInfo> result;
    for(auto ts = unsignedSignatureProperties()/ArchiveTimeStamp; ts; ts++)
    {
        TS t(ts/EncapsulatedTimeStamp);
        result.push_back({t.cert(), util::date::to_string(t.time())});
    }
    return result;
}

void SignatureXAdES_LTA::validate(const string &policy) const
{
    Exception exception(EXCEPTION_PARAMS("Signature validation"));
    try {
        SignatureXAdES_LT::validate(policy);
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }

    if(profile().find(ASiC_E::ASIC_TSA_PROFILE) == string::npos)
    {
        if(!exception.causes().empty())
            throw exception;
        return;
    }

    try {
        for(auto ts = unsignedSignatureProperties()/ArchiveTimeStamp; ts; ts++)
        {
            verifyTS(ts, exception, [this, ts](const Digest &digest, string_view canonicalizationMethod) {
                calcArchiveDigest(digest, canonicalizationMethod, ts);
            });
        }
    } catch(const Exception &e) {
        exception.addCause(e);
    } catch(...) {
        EXCEPTION_ADD(exception, "Failed to validate signature");
    }
    if(!exception.causes().empty())
        throw exception;
}
