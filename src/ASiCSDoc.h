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

namespace digidoc
{
    class ASiCSDocPrivate;
    class ZipSerialize;

    /**
    * Implements the ASiC-S specification of the timestamped digital document container.
    * Container contains single datafile object and one time assertion file.
    * Only read operations are implemented for the container (i.e. read-only datatype);
    * container does not implement creation, addition and removal functionality.
    *
    * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly
    * (see iconv --list for the list of supported encoding values for libiconv).
    *
    * @author Toomas Uudisaru
    */
    class ASiCSDoc : public Container
    {

    public:
        virtual ~ASiCSDoc();
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

        static bool isTimestampedASiC_S(const std::vector<std::string> &list);
        static Container* createInternal(const std::string &path);
        static Container* openInternal(const std::string &path);

    private:
        ASiCSDoc();
        ASiCSDoc(const std::string &path);
        DISABLE_COPY(ASiCSDoc);

        void validateDataObjects();
        void extractTimestamp(const ZipSerialize &z);
        void loadContainer(const ZipSerialize &z, const std::vector<std::string> &list);
        void loadWithoutManifest(const ZipSerialize &z, const std::vector<std::string> &list);
        void parseManifestAndLoadFiles(const ZipSerialize &z, const std::vector<std::string> &list);

        static void readMimetype(const ZipSerialize &z);

        ASiCSDocPrivate *d;
    };
}
