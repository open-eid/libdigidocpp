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

#include "SignatureTST.h"

#include "ASiC_S.h"
#include "DataFile_p.h"
#include "crypto/Digest.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "util/log.h"

using namespace digidoc;
using namespace std;

SignatureTST::SignatureTST(std::unique_ptr<istream> is, ASiC_S *asicSDoc): asicSDoc(asicSDoc)
{
    is->seekg(0, istream::end);
    istream::pos_type pos = is->tellg();
    const auto size = pos < 0 ? 0 : (unsigned long)pos;
    is->clear();
    is->seekg(0, istream::beg);

    vector<unsigned char> buf(size, 0);
    is->read((char*)buf.data(), streamsize(buf.size()));

    timestampToken = make_unique<TS>(buf.data(), buf.size());
}

SignatureTST::~SignatureTST() = default;

X509Cert SignatureTST::TimeStampCertificate() const
{
    return timestampToken->cert();
}

string SignatureTST::TimeStampTime() const
{
    return util::date::to_string(timestampToken->time());
}

string SignatureTST::trustedSigningTime() const
{
    return TimeStampTime();
}

// DSig properties
string SignatureTST::id() const
{
    return timestampToken->serial();
}

string SignatureTST::claimedSigningTime() const
{
    return TimeStampTime();
}

X509Cert SignatureTST::signingCertificate() const
{
    return TimeStampCertificate();
}

string SignatureTST::signatureMethod() const
{
    return timestampToken->digestMethod();
}

void SignatureTST::validate() const
{
    Exception exception(EXCEPTION_PARAMS("Timestamp validation."));

    if(!timestampToken)
    {
        EXCEPTION_ADD(exception, "Failed to parse timestamp token.");
        throw exception;
    }
    try
    {
        const string digestMethod = timestampToken->digestMethod();
        Digest digest(digestMethod);
        auto dataFile = static_cast<const DataFilePrivate*>(asicSDoc->dataFiles().front());
        dataFile->calcDigest(&digest);
        timestampToken->verify(digest);

        if(digestMethod == URI_SHA1 &&
            !Exception::hasWarningIgnore(Exception::ReferenceDigestWeak))
        {
            Exception e(EXCEPTION_PARAMS("TimeStamp '%s' digest weak", digestMethod.c_str()));
            e.setCode(Exception::ReferenceDigestWeak);
            exception.addCause(e);
        }
    }
    catch (const Exception& e)
    {
        exception.addCause(e);
    }

    if(!exception.causes().empty())
        throw exception;
}

std::vector<unsigned char> SignatureTST::dataToSign() const
{
    THROW("Not implemented.");
}

void SignatureTST::setSignatureValue(const std::vector<unsigned char> & /*signatureValue*/)
{
    THROW("Not implemented.");
}

// Xades properties
string SignatureTST::profile() const
{
    return "TimeStampToken";
}
