// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Container.h"
#include "DataFile.h"
#include "Signature.h"
#include "crypto/X509Cert.h"

namespace digidoc
{

class PDF: public Container
{
public:
    ~PDF();
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
    PDF(const std::string &path);
    DISABLE_COPY(PDF);

    class Private;
    Private *d;
};

}
