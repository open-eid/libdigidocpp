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

void SignatureXAdES_LTA::calcArchiveDigest(const Digest &digest, string_view canonicalizationMethod) const
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

    auto usp = unsignedSignatureProperties();
    for(const auto *name: {
        "SignatureTimeStamp",
        "CounterSignature",
        "CompleteCertificateRefs",
        "CompleteRevocationRefs",
        "AttributeCertificateRefs",
        "AttributeRevocationRefs",
        "CertificateValues",
        "RevocationValues",
        "SigAndRefsTimeStamp",
        "RefsOnlyTimeStamp" })
    {
        if(auto elem = usp/name)
            signatures->c14n(digest, canonicalizationMethod, elem);
        else
            DEBUG("Element %s not found", name);
    }

    if(auto elem = usp/XMLName{"TimeStampValidationData", XADESv141_NS})
        signatures->c14n(digest, canonicalizationMethod, elem);
    else
        DEBUG("Element TimeStampValidationData not found");
    //ds:Object
}

void SignatureXAdES_LTA::extendSignatureProfile(Signer *signer)
{
    SignatureXAdES_LT::extendSignatureProfile(signer);
    if(signer->profile() != ASiC_E::ASIC_TSA_PROFILE)
        return;
    Digest calc;
    auto method = canonicalizationMethod();
    calcArchiveDigest(calc, method);

    TS tsa(calc, signer->userAgent());
    auto ts = unsignedSignatureProperties() + ArchiveTimeStamp;
    ts.setNS(ts.addNS(XADESv141_NS, "xades141"));
    ts.setProperty("Id", id() + "-A0");
    (ts + CanonicalizationMethod).setProperty("Algorithm", method);
    ts + EncapsulatedTimeStamp = tsa;
}

TS SignatureXAdES_LTA::tsaFromBase64() const
{
    try {
        return {unsignedSignatureProperties()/ArchiveTimeStamp/EncapsulatedTimeStamp};
    } catch(const Exception &) {}
    return {};
}

X509Cert SignatureXAdES_LTA::ArchiveTimeStampCertificate() const
{
    return tsaFromBase64().cert();
}

string SignatureXAdES_LTA::ArchiveTimeStampTime() const
{
    return date::to_string(tsaFromBase64().time());
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
        auto ts = unsignedSignatureProperties()/ArchiveTimeStamp;
        if(!ts)
            THROW("Missing ArchiveTimeStamp element");
        verifyTS(ts, exception, [this](const Digest &digest, string_view canonicalizationMethod) {
            calcArchiveDigest(digest, canonicalizationMethod);
        });
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}
