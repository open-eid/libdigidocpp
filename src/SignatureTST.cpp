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

#include "Conf.h"
#include "DataFile_p.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/OCSP.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"

#include <xsec/dsig/DSIGConstants.hpp>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace digidoc::xades;
using namespace std;

SignatureTST::SignatureTST(istream &is, ASiCSDoc *asicSDoc): asicSDoc(asicSDoc)
{
    is.seekg(0, istream::end);
    istream::pos_type pos = is.tellg();
    const auto size = pos < 0 ? 0 : (unsigned long)pos;
    is.clear();
    is.seekg(0, istream::beg);

    vector<unsigned char> buf(size, 0);
    is.read((char*)&buf[0], buf.size());

    timestampToken = new TS(buf);
}

SignatureTST::~SignatureTST() {}

X509Cert SignatureTST::TimeStampCertificate() const
{
    return timestampToken->cert();
}

string SignatureTST::TimeStampTime() const
{
    return ASN1TimeToXSD(timestampToken->time());
}

string SignatureTST::trustedSigningTime() const
{
    return TimeStampTime();
}

// DSig properties
string SignatureTST::id() const
{
    return "";
}
string SignatureTST::claimedSigningTime() const
{
    return "";
}
X509Cert SignatureTST::signingCertificate() const
{
    return X509Cert();
}
string SignatureTST::signatureMethod() const
{
    return "";
}
void SignatureTST::validate() const
{
    // TODO
    // Digest digest(timestampToken->digestMethod());
    // auto dataFile = static_cast<const DataFilePrivate*>(asicSDoc->dataFiles().front());
    // dataFile->calcDigest(&digest);

    // timestampToken->verify(digest);
}
std::vector<unsigned char> SignatureTST::dataToSign() const
{
    THROW("Not implemented.");
}
void SignatureTST::setSignatureValue(const std::vector<unsigned char> &signatureValue)
{
    THROW("Not implemented.");
}
// Xades properties
string SignatureTST::profile() const
{
    return "";
}
string SignatureTST::city() const
{
    return "";
}
string SignatureTST::stateOrProvince() const
{
    return "";
}
string SignatureTST::postalCode() const
{
    return "";
}
string SignatureTST::countryName() const
{
    return "";
}

// Xades properties
string SignatureTST::streetAddress() const
{
    return "";
}
