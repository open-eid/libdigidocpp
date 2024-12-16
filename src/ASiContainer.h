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
    struct XMLDocument;

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
          static constexpr std::string_view MIMETYPE_ASIC_E = "application/vnd.etsi.asic-e+zip";
          static constexpr std::string_view MIMETYPE_ASIC_S = "application/vnd.etsi.asic-s+zip";
          //https://signa.mitsoft.lt/static/signa-web/webResources/docs/ADOC_specification_approved20090907_EN.pdf
          static constexpr std::string_view MIMETYPE_ADOC = "application/vnd.lt.archyvai.adoc-2008";
          static constexpr std::string_view MANIFEST_NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
          static constexpr std::string_view ASIC_NS = "http://uri.etsi.org/02918/v1.2.1#";

          ~ASiContainer() override;
          std::string mediaType() const override;

          void addDataFile(const std::string &path, const std::string &mediaType) override;
          void addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType) override;
          std::vector<DataFile*> dataFiles() const override;
          void removeDataFile(unsigned int id) override;
          void removeSignature(unsigned int id) override;
          void save(const std::string &path) override;
          std::vector<Signature*> signatures() const override;

          static std::string readMimetype(const ZipSerialize &z);

      protected:
          ASiContainer(std::string_view mimetype);

          virtual void addDataFileChecks(const std::string &path, const std::string &mediaType);
          void addDataFilePrivate(std::unique_ptr<std::istream> is, std::string fileName, std::string mediaType);
          Signature* addSignature(std::unique_ptr<Signature> &&signature);
          virtual void canSave() = 0;
          XMLDocument createManifest() const;
          std::unique_ptr<std::iostream> dataStream(std::string_view path, const ZipSerialize &z) const;
          ZipSerialize load(const std::string &path, bool requireMimetype, const std::set<std::string_view> &supported);
          virtual void save(const ZipSerialize &s) = 0;
          void deleteSignature(Signature* s);

          void zpath(const std::string &file);
          std::string zpath() const;
          const ZipSerialize::Properties& zproperty(std::string_view file) const;

      private:
          DISABLE_COPY(ASiContainer);

          class Private;
          std::unique_ptr<Private> d;
    };
}
