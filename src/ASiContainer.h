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
#include "util/ZipSerialize.h"

#include <set>

namespace digidoc
{
    class DataFilePrivate;
    /**
     * Base class for the ASiC (Associated Signature Container) documents.
     * Implements the operations and data structures common for more specific ASiC 
     * signature containers like ASiC-S and ASiC-E (e.g. Estonian BDoc).
     * See standards ETSI TS 102 918, ETSI TS 103 171, ETSI TS 103 174 for details.
     *
     * Contains methods for detecting the container type and manipulating the container's 
     * zip archive.
     */
    class ASiContainer: public Container
    {
      public:
          static const std::string_view ASICE_EXTENSION;
          static const std::string_view ASICE_EXTENSION_ABBR;
          static const std::string_view ASICS_EXTENSION;
          static const std::string_view ASICS_EXTENSION_ABBR;
          static const std::string_view BDOC_EXTENSION;

          static const std::string MIMETYPE_ASIC_E;
          static const std::string MIMETYPE_ASIC_S;
          static const std::string MIMETYPE_ADOC;

          ~ASiContainer() override;
          std::string mediaType() const override;

          void addDataFile(const std::string &path, const std::string &mediaType) override;
          void addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType) override;
          std::vector<DataFile*> dataFiles() const override;
          void removeDataFile(unsigned int id) override;
          void removeSignature(unsigned int id) override;
          std::vector<Signature*> signatures() const override;

          static std::string readMimetype(const ZipSerialize &z);

      protected:
          ASiContainer(const std::string &mimetype);

          void addDataFilePrivate(const std::string &fileName, const std::string &mediaType);
          Signature* addSignature(std::unique_ptr<Signature> &&signature);
          DataFilePrivate *dataFile(const std::string &path, const std::string &mediaType) const;
          ZipSerialize* load(const std::string &path, bool requireMimetype, const std::set<std::string> &supported);
          void deleteSignature(Signature* s);

          void zpath(const std::string &file);
          std::string zpath() const;
          ZipSerialize::Properties zproperty(const std::string &file) const;
          void zproperty(const std::string &file, ZipSerialize::Properties &&prop);

      private:
          DISABLE_COPY(ASiContainer);

          void addDataFileChecks(const std::string &path, const std::string &mediaType);

          class Private;
          std::unique_ptr<Private> d;
    };
}
