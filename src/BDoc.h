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

#include "ADoc.h"

namespace digidoc
{
    class BDocPrivate;
    class ZipSerialize;

    /**
     * Implements the BDOC specification of the signed digital document container.
     * Container can contain several files and all these files can be signed using
     * signing certificates. Container can only be signed if it contains documents.
     * Documents can be added and removed from container only if the container is
     * not signed. To add or remove documents from signed container remove all the
     * signatures before modifying documents list in container.
     *
     * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly
     * (see iconv --list for the list of supported encoding values for libiconv).
     *
     * @author Janari Põld
     */
    class BDoc: public ADoc
    {

      public:
          static const std::string ASIC_MIMETYPE;
          static const std::string BDOC_MIMETYPE;

          static const std::string BES_PROFILE;
          static const std::string EPES_PROFILE;
          static const std::string ASIC_TM_PROFILE;
          static const std::string ASIC_TS_PROFILE;
          static const std::string ASIC_TMA_PROFILE;
          static const std::string ASIC_TSA_PROFILE;

          BDoc();
          BDoc(const std::string &path);
          virtual ~BDoc();
          void save(const std::string &path = "");
          std::string mediaType() const;

          void addDataFile(const std::string &path, const std::string &mediaType);
          void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
          DataFileList dataFiles() const;
          void removeDataFile(unsigned int id);

          void addRawSignature(std::istream &sigdata);
          SignatureList signatures() const;
          void removeSignature(unsigned int id);
          Signature* sign(Signer* signer, const std::string &profile);

      private:
          DISABLE_COPY(BDoc);
          void createManifest(std::ostream &os);
          void readMimetype(std::istream &path);
          void parseManifestAndLoadFiles(const ZipSerialize &z, const std::vector<std::string> &list);

          BDocPrivate *d;
    };
}
