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
#include "DataFile.h"
#include "Signature.h"
#include "crypto/X509Cert.h"

namespace digidoc
{

class RDocPrivate;

class DataFileRDOC: public DataFile
{
public:
    ~DataFileRDOC() {}

    std::string id() const override { return _id; }
    std::string fileName() const override { return _fileName; }
    unsigned long fileSize() const override { return _fileSize; }
    std::string mediaType() const override { return _mediaType; }

    std::vector<unsigned char> calcDigest(const std::string &method) const override;
    void saveAs(std::ostream &os) const override;
    void saveAs(const std::string& path) const override;

private:
    DataFileRDOC() {}
    DISABLE_COPY(DataFileRDOC);

    std::shared_ptr<std::istream> _is;
    std::string _id, _fileName, _mediaType;
    unsigned long _fileSize = 0;
    friend class RDoc;
};

class SignatureRDOC: public Signature
{
public:
    ~SignatureRDOC() {}

    std::string id() const override { return _id; }
    std::string claimedSigningTime() const override { return _signingTime; }
    std::string trustedSigningTime() const override;
    X509Cert signingCertificate() const override { return _signCert; }
    std::string signatureMethod() const override { return _signatureMethod; }
    void validate() const override;
    std::vector<unsigned char> dataToSign() const override;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue) override;

    // Xades properties
    std::string profile() const override { return _profile; }
    std::string city() const override { return std::string(); }
    std::string stateOrProvince() const override { return std::string(); }
    std::string streetAddress() const override { return std::string(); }
    std::string postalCode() const override { return std::string(); }
    std::string countryName() const override { return std::string(); }
    std::vector<std::string> signerRoles() const override { return std::vector<std::string>(); }

    //TS profile properties
    X509Cert TimeStampCertificate() const override { return _tsCert; }
    std::string TimeStampTime() const override { return _tsTime; }

    //TSA profile properties
    X509Cert ArchiveTimeStampCertificate() const override { return _aCert; }
    std::string ArchiveTimeStampTime() const override { return _aTime; }

private:
    SignatureRDOC() {}
    DISABLE_COPY(SignatureRDOC);

    std::string _id, _profile, _signatureMethod, _signingTime, _tsTime, _aTime, _result, _resultDetails;
    std::string _sID, _tID, _aID;
    X509Cert _signCert, _tsCert, _aCert;
    friend class RDocPrivate;
};

class RDoc: public Container
{
public:
    ~RDoc();

    void save(const std::string &path = "") override;
    std::string mediaType() const override;

    void addDataFile(const std::string &path, const std::string &mediaType) override;
    void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType) override;
    std::vector<DataFile*> dataFiles() const override;
    void removeDataFile(unsigned int id) override;

    void addAdESSignature(std::istream &sigdata) override;
    Signature* prepareSignature(Signer *signer) override;
    std::vector<Signature*> signatures() const override;
    void removeSignature(unsigned int id) override;
    Signature* sign(Signer* signer) override;

    static Container* createInternal(const std::string &path);
    static Container* openInternal(const std::string &path);

private:
    RDoc(const std::string &path);
    DISABLE_COPY(RDoc);

    RDocPrivate *d;
};

}
