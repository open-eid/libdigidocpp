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
    ~SignatureDDOC() final;

    std::string id() const override;
    std::string claimedSigningTime() const override;
    X509Cert signingCertificate() const override;
    std::string signatureMethod() const override;
    std::string trustedSigningTime() const override;
    void validate() const override;
    std::vector<unsigned char> dataToSign() const override;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue) override;
    void extendSignatureProfile(const std::string &profile) override;

    // Xades properties
    std::string profile() const override;
    std::string city() const override;
    std::string stateOrProvince() const override;
    std::string postalCode() const override;
    std::string countryName() const override;
    std::vector<std::string> signerRoles() const override;

    std::vector<unsigned char> messageImprint() const override;
    X509Cert OCSPCertificate() const override;
    std::string OCSPProducedAt() const override;

private:
    SignatureDDOC(SignatureInfo_st *sig, DDocPrivate *doc);
    DISABLE_COPY(SignatureDDOC);

    DDocPrivate *d;
    SignatureInfo_st *s;

    friend class DDoc;
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
    ~DDoc() final;

    void save(const std::string &path = {}) override;
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
    DDoc();
    DDoc(const std::string &path);
    void load(const std::string &path);
    DISABLE_COPY(DDoc);
    DDocPrivate *d;
};

}
