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

#include "Exception.h"

namespace digidoc
{

class DataFile;
class Signature;
class Signer;
typedef std::vector<DataFile> DataFileList;
typedef std::vector<Signature*> SignatureList;

class ADoc
{
public:
    virtual ~ADoc();
    virtual void save(const std::string &path = "") = 0;
    virtual std::string mediaType() const = 0;

    virtual void addDataFile(const std::string &path, const std::string &mediaType) = 0;
    virtual void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType) = 0;
    virtual DataFileList dataFiles() const = 0;
    virtual void removeDataFile(unsigned int id) = 0;

    virtual void addRawSignature(std::istream &sigdata) = 0;
    unsigned int newSignatureId() const;
    virtual SignatureList signatures() const = 0;
    virtual void removeSignature(unsigned int id) = 0;
    virtual Signature* sign(Signer* signer, const std::string &profile) = 0;

protected:
    ADoc();

private:
    DISABLE_COPY(ADoc);
};

}
