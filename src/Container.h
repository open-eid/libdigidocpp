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

#include "Exports.h"

#include <string>
#include <vector>

namespace digidoc
{
class ADoc;
class DataFile;
class Exception;
class Signature;
class Signer;
typedef std::vector<DataFile> DataFileList;
typedef std::vector<Signature*> SignatureList;
typedef void (*initCallBack)(const Exception *e);

EXP_DIGIDOC std::string appInfo();
EXP_DIGIDOC void initialize(const std::string &appInfo = "libdigidocpp");
EXP_DIGIDOC void initializeEx(const std::string &appInfo = "libdigidocpp", initCallBack callBack = nullptr);
EXP_DIGIDOC void terminate();
EXP_DIGIDOC std::string version();

class EXP_DIGIDOC Container
{
public:
    enum DocumentType
    {
        AsicType,
        BDocType,
        DDocType
    };

    Container( DocumentType type = AsicType );
    Container( const std::string &path );
    ~Container();

    void save(const std::string &path = "");
    std::string mediaType() const;

    void addDataFile(const std::string &path, const std::string &mediaType);
    void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
    DataFileList dataFiles() const;
    void removeDataFile(unsigned int id);

    void addRawSignature(const std::vector<unsigned char> &signature);
    void addRawSignature(std::istream &signature);
    SignatureList signatures() const;
    void removeSignature(unsigned int id);
    Signature* sign(Signer* signer);
    Signature* sign(Signer* signer, const std::string &profile);
    Signature* sign(const std::string &city, const std::string &stateOrProvince,
                    const std::string &postalCode, const std::string &countryName,
                    const std::vector<std::string> &signerRoles,
                    const std::string &pin, bool useFirstCertificate = true);

private:
    DISABLE_COPY(Container);
	ADoc *m_doc;
};

}
