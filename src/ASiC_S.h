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
    * Implements the ASiC-S specification of the timestamped digital document container.
    * Container contains a single datafile object and one time assertion file.
    * The signing (timestamping) and save operations are not supported.
    */
    class ASiC_S : public ASiContainer
    {

    public:
        void save(const std::string &path = "") override;

        void addDataFile(const std::string &path, const std::string &mediaType) override;
        void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType) override;

        void addAdESSignature(std::istream &sigdata) override;
        Signature* prepareSignature(Signer *signer) override;
        Signature* sign(Signer* signer) override;

        static Container* createInternal(const std::string &path);
        static Container* openInternal(const std::string &path);

    private:
        ASiC_S();
        ASiC_S(const std::string &path);
        DISABLE_COPY(ASiC_S);
        
        void extractTimestamp(const ZipSerialize &z);
        void loadContainer(const ZipSerialize &z);
        
        static ASiCFormat detectContainerFormat(const std::string &path);
        static bool isTimestampedASiC_S(const std::vector<std::string> &list);
    };
}
