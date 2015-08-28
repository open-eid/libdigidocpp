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

struct SignatureInfo_st;

namespace digidoc
{

class DDocPrivate;
class SignatureDDOCPrivate;

/**
 * DDoc Signature class
 */
class SignatureDDOC: public Signature
{
public:
    virtual ~SignatureDDOC();

    std::string id() const;
    std::string signingTime() const;
    X509Cert signingCertificate() const;
    std::string signatureMethod() const;
    void validate(Validate = ValidateFULL) const;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue);
    void notarize();

    // Xades properties
    std::string profile() const;
    std::string city() const;
    std::string stateOrProvince() const;
    std::string postalCode() const;
    std::string countryName() const;
    std::vector<std::string> signerRoles() const;

    std::vector<unsigned char> nonce() const;
    X509Cert OCSPCertificate() const;
    std::string producedAt() const;

private:
    SignatureDDOC(SignatureInfo_st *sig, DDocPrivate *doc);
    DISABLE_COPY(SignatureDDOC);

    DDocPrivate *d;
    SignatureInfo_st *s;

    friend class DDocPrivate;
};

/**
 * Implements the DDOC specification of the signed digital document container.
 * Container can contain several files and all these files can be signed using
 * signing certificates. Container can only be signed if it contains documents.
 * Documents can be added and removed from container only if the container is
 * not signed. To add or remove documents from signed container remove all the
 * signatures before modifying documents list in container.
 */
class DDoc: public Container
{
public:
    ~DDoc();

    void save(const std::string &path = "") override;
    std::string mediaType() const override;

    void addDataFile(const std::string &path, const std::string &mediaType) override;
    void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType) override;
    DataFileList dataFiles() const override;
    void removeDataFile(unsigned int id) override;

    void addRawSignature(std::istream &sigdata) override;
    SignatureList signatures() const override;
    void removeSignature(unsigned int id) override;
    Signature* sign(Signer* signer) override;

    static Container* createInternal(const std::string &path);
    static Container* openInternal(const std::string &path);

private:
    DDoc();
    DDoc(const std::string &path);
    void load(const std::string &path);
    DISABLE_COPY(DDoc);
    DDocPrivate *d;
};

}
