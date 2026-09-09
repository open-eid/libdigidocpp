// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "ASiContainer.h"

namespace digidoc
{
    /**
    * Implements the ASiC-S specification of the timestamped digital document container.
    * The container contains a single data file and either XAdES signatures or
    * an RFC 3161 TimeStampToken. XAdES containers can be opened and validated,
    * but are read-only. Creating, timestamping, saving, validating, and adding
    * archive-manifest time-stamp layers are supported for TimeStampToken containers.
    */
    class ASiC_S : public ASiContainer
    {
    public:
        static constexpr std::string_view ASIC_TST_PROFILE = "TimeStampToken";

        void addAdESSignature(std::istream &sigdata) override;
        Signature* prepareSignature(Signer *signer) override;
        Signature* sign(Signer* signer) override;

        static std::unique_ptr<Container> createInternal(const std::string &path);
        static std::unique_ptr<Container> openInternal(const std::string &path, ContainerOpenCB *cb);

    private:
        ASiC_S(const std::string &path, bool create);
        DISABLE_COPY(ASiC_S);

        void addDataFileChecks(std::string_view path, const std::string &mediaType) override;
        void canSave() final;
        void save(const ZipSerialize &s) final;

        friend class SignatureTST;
    };
}
