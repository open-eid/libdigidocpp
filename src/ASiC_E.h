// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "ASiContainer.h"

namespace digidoc
{
    /**
     * Implements the BDOC specification of the signed digital document container.
     * Container can contain several files and all these files can be signed using
     * signing certificates. Container can only be signed if it contains documents.
     * Documents can be added and removed from container only if the container is
     * not signed. To add or remove documents from signed container remove all the
     * signatures before modifying documents list in container.
     */
    class ASiC_E final : public ASiContainer
    {
      public:
          static constexpr std::string_view ASIC_TM_PROFILE = "time-mark";
          static constexpr std::string_view ASIC_TS_PROFILE = "time-stamp";
          static constexpr std::string_view ASIC_TMA_PROFILE = "time-mark-archive";
          static constexpr std::string_view ASIC_TSA_PROFILE = "time-stamp-archive";

          ~ASiC_E() final;
          std::vector<DataFile*> metaFiles() const;

          void addAdESSignature(std::istream &data) final;
          Signature* prepareSignature(Signer *signer) final;
          Signature* sign(Signer* signer) final;

          static std::unique_ptr<Container> createInternal(const std::string &path);
          static std::unique_ptr<Container> openInternal(const std::string &path);

      private:
          ASiC_E(const std::string &path, bool create);
          DISABLE_COPY(ASiC_E);
          void canSave() final;
          void loadSignatures(XMLDocument &&doc, const std::string &file);
          void save(const ZipSerialize &s) final;

          class Private;
          std::unique_ptr<Private> d;
    };
}
