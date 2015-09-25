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
class DataFile;
class Exception;
class Signature;
class Signer;
typedef std::vector<DataFile> DataFileList;
typedef std::vector<Signature*> SignatureList;
typedef void (*initCallBack)(const Exception *e);

EXP_DIGIDOC std::string appInfo();
EXP_DIGIDOC void initialize(const std::string &appInfo = "libdigidocpp", initCallBack callBack = nullptr);
EXP_DIGIDOC void terminate();
EXP_DIGIDOC std::string version();

class EXP_DIGIDOC Container
{
public:
    virtual ~Container();

    virtual void save(const std::string &path = "") = 0;
    virtual std::string mediaType() const = 0;

    virtual void addDataFile(const std::string &path, const std::string &mediaType) = 0;
    virtual void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType) = 0;
    virtual DataFileList dataFiles() const = 0;
    virtual void removeDataFile(unsigned int id) = 0;

    void addRawSignature(const std::vector<unsigned char> &signature);
    virtual void addRawSignature(std::istream &signature) = 0;
    virtual SignatureList signatures() const = 0;
    virtual void removeSignature(unsigned int id) = 0;
    virtual Signature* sign(Signer *signer) = 0;

    static Container* create(const std::string &path);
    static Container* open(const std::string &path);
    template<class T>
    static void addContainerImplementation();

protected:
    Container();
    unsigned int newSignatureId() const;

private:
    DISABLE_COPY(Container);
};

}
