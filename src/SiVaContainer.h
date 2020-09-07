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

#include "Container.h"
#include "Signature.h"
#include "crypto/X509Cert.h"

namespace digidoc
{
class SiVaContainer;
class Exception;

class SignatureSiVa: public Signature
{
public:
    std::string id() const override { return _id; }
    std::string claimedSigningTime() const override { return _signingTime; }
    std::string trustedSigningTime() const override { return _bestTime.empty() ? _signingTime : _bestTime; }
    X509Cert signingCertificate() const override { return _signingCertificate; }
    std::string signedBy() const override { return _signedBy; }
    std::string signatureMethod() const override { return _signatureMethod; }
    void validate() const override;
    void validate(const std::string &policy) const override;
    std::vector<unsigned char> dataToSign() const override;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue) override;

    // Xades properties
    std::string profile() const override { return _profile; }
    std::string city() const override { return _city; };
    std::string stateOrProvince() const override { return _stateOrProvince; };
    std::string postalCode() const override { return _postalCode; };
    std::string countryName() const override { return _country; };
    std::vector<std::string> signerRoles() const override { return _signerRoles; };

    //TM profile properties
    X509Cert OCSPCertificate() const override { return _ocspCertificate; };

    //TS profile properties
    X509Cert TimeStampCertificate() const override { return _tsCertificate; };

    //TSA profile properties
    X509Cert ArchiveTimeStampCertificate() const override { return _tsaCertificate; };

    // Other
    std::vector<unsigned char> messageImprint() const override { return  _messageImprint; };

private:
    SignatureSiVa() = default;
    DISABLE_COPY(SignatureSiVa);

    X509Cert _signingCertificate, _ocspCertificate, _tsCertificate, _tsaCertificate;
    std::string _id, _profile, _signedBy, _signatureMethod, _signingTime, _bestTime, _indication, _subIndication, _signatureLevel;
    std::string _city, _stateOrProvince, _postalCode, _country;
    std::vector<std::string> _signerRoles;
    std::vector<unsigned char> _messageImprint;
    std::vector<Exception> _exceptions;

    friend SiVaContainer;
};

class SiVaContainer: public Container
{
public:
    ~SiVaContainer() override;

    void save(const std::string &path = {}) override;
    std::string mediaType() const override;

    void addDataFile(const std::string &path, const std::string &mediaType) override;
    void addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType) override;
    std::vector<DataFile*> dataFiles() const override;
    void removeDataFile(unsigned int id) override;

    void addAdESSignature(std::istream &sigdata) override;
    Signature* prepareSignature(Signer *signer) override;
    std::vector<Signature*> signatures() const override;
    void removeSignature(unsigned int id) override;
    Signature* sign(Signer* signer) override;

    static std::unique_ptr<Container> createInternal(const std::string &path);
    static std::unique_ptr<Container> openInternal(const std::string &path);

private:
    SiVaContainer(const std::string &path, const std::string &ext, bool useHashCode);
    DISABLE_COPY(SiVaContainer);

    std::stringstream* parseDDoc(std::unique_ptr<std::istream> is, bool useHashCode);

    class Private;
    Private *d;
};

}
