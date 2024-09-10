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
    class Digest;

    /**
    * Implements the ASiC-S specification of the timestamped digital document container.
    * Container contains a single datafile object and one time assertion file.
    * The signing (timestamping) and save operations are not supported.
    */
    class ASiC_S : public ASiContainer
    {
    public:
        static constexpr std::string_view ASIC_TST_PROFILE = "TimeStampToken";

        void addAdESSignature(std::istream &sigdata) override;
        Signature* prepareSignature(Signer *signer) override;
        Signature* sign(Signer* signer) override;

        Digest fileDigest(const std::string &file, std::string_view method = {}) const;

        static std::unique_ptr<Container> createInternal(const std::string &path);
        static std::unique_ptr<Container> openInternal(const std::string &path, ContainerOpenCB *cb);

    private:
        ASiC_S();
        ASiC_S(const std::string &path);
        DISABLE_COPY(ASiC_S);

        void addDataFileChecks(const std::string &path, const std::string &mediaType) override;
        void canSave() final;
        void save(const ZipSerialize &s) final;

        static bool isContainerSimpleFormat(const std::string &path);

        struct Data;
        std::vector<Data> metadata;
    };
}
