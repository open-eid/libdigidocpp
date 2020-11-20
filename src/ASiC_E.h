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

#include "ASiContainer.h"

namespace digidoc
{
    class ZipSerialize;

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
          static const std::string BES_PROFILE;
          static const std::string EPES_PROFILE;
          static const std::string ASIC_TM_PROFILE;
          static const std::string ASIC_TS_PROFILE;
          static const std::string ASIC_TMA_PROFILE;
          static const std::string ASIC_TSA_PROFILE;
          static const std::string MANIFEST_NAMESPACE;

          ~ASiC_E() final;
          void save(const std::string &path = {}) final;
          std::vector<DataFile*> metaFiles() const;

          void addAdESSignature(std::istream &sigdata) final;
          Signature* prepareSignature(Signer *signer) final;
          Signature* sign(Signer* signer) final;

          static std::unique_ptr<Container> createInternal(const std::string &path);
          static std::unique_ptr<Container> openInternal(const std::string &path);

      private:
          ASiC_E();
          ASiC_E(const std::string &path);
          DISABLE_COPY(ASiC_E);
          void createManifest(std::ostream &os);
          void parseManifestAndLoadFiles(const ZipSerialize &z);

          class Private;
          Private *d;
    };
}
