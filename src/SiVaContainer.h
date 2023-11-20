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

class SignatureSiVa final: public Signature
{
public:
    std::string id() const final { return _id; }
    std::string claimedSigningTime() const final { return _signingTime; }
    std::string trustedSigningTime() const final { return _bestTime.empty() ? _signingTime : _bestTime; }
    X509Cert signingCertificate() const final { return _signingCertificate; }
    std::string signedBy() const final { return _signedBy; }
    std::string signatureMethod() const final { return _signatureMethod; }
    void validate() const final;
    void validate(const std::string &policy) const final;
    std::vector<unsigned char> dataToSign() const final;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue) final;

    // Xades properties
    std::string profile() const final { return _profile; }
    std::string city() const final { return _city; }
    std::string stateOrProvince() const final { return _stateOrProvince; }
    std::string postalCode() const final { return _postalCode; }
    std::string countryName() const final { return _country; }
    std::vector<std::string> signerRoles() const final { return _signerRoles; }

    //TM profile properties
    X509Cert OCSPCertificate() const final { return _ocspCertificate; }
    std::string OCSPProducedAt() const final { return _ocspTime; }

    //TS profile properties
    X509Cert TimeStampCertificate() const final { return _tsCertificate; }
    std::string TimeStampTime() const final { return _tsTime; }

    //TSA profile properties
    X509Cert ArchiveTimeStampCertificate() const final { return _tsaCertificate; }

    // Other
    std::vector<unsigned char> messageImprint() const final { return  _messageImprint; }

private:
    SignatureSiVa() = default;
    DISABLE_COPY(SignatureSiVa);

    X509Cert _signingCertificate, _ocspCertificate, _tsCertificate, _tsaCertificate;
    std::string _id, _profile, _signedBy, _signatureMethod, _signingTime, _indication, _subIndication, _signatureLevel;
    std::string _bestTime, _tsTime, _ocspTime;
    std::string _city, _stateOrProvince, _postalCode, _country;
    std::vector<std::string> _signerRoles;
    std::vector<unsigned char> _messageImprint;
    std::vector<Exception> _exceptions;

    friend SiVaContainer;
};

class SiVaContainer final: public Container
{
public:
    ~SiVaContainer() final;

    void save(const std::string &path = {}) final;
    std::string mediaType() const final;

    void addDataFile(const std::string &path, const std::string &mediaType) final;
    void addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType) final;
    std::vector<DataFile*> dataFiles() const final;
    void removeDataFile(unsigned int id) final;

    void addAdESSignature(std::istream &sigdata) final;
    Signature* prepareSignature(Signer *signer) final;
    std::vector<Signature*> signatures() const final;
    void removeSignature(unsigned int id) final;
    Signature* sign(Signer* signer) final;

    static std::unique_ptr<Container> createInternal(const std::string &path);
    static std::unique_ptr<Container> openInternal(const std::string &path, ContainerOpenCB *cb);

private:
    SiVaContainer(const std::string &path, ContainerOpenCB *cb, bool useHashCode);
    DISABLE_COPY(SiVaContainer);

    std::unique_ptr<std::istream> parseDDoc(bool useHashCode);

    class Private;
    std::unique_ptr<Private> d;
};

}
