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

#include <memory>
#include <string>
#include <vector>

namespace digidoc
{
class DataFile;
class Exception;
class Signature;
class Signer;
using initCallBack = void (*)(const Exception *e);

DIGIDOCPP_EXPORT std::string appInfo();
DIGIDOCPP_EXPORT void initialize(const std::string &appInfo = "libdigidocpp", initCallBack callBack = nullptr);
DIGIDOCPP_EXPORT void initialize(const std::string &appInfo, const std::string &userAgent, initCallBack callBack = nullptr);
DIGIDOCPP_EXPORT void terminate();
DIGIDOCPP_EXPORT std::string userAgent();
DIGIDOCPP_EXPORT std::string version();

class DIGIDOCPP_EXPORT Container
{
public:
    virtual ~Container();

    virtual void save(const std::string &path = "") = 0;
    virtual std::string mediaType() const = 0;

    virtual void addDataFile(const std::string &path, const std::string &mediaType) = 0;
    DIGIDOCPP_DEPRECATED virtual void addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
    virtual std::vector<DataFile*> dataFiles() const = 0;
    virtual void removeDataFile(unsigned int index) = 0;

    void addAdESSignature(const std::vector<unsigned char> &signature);
    virtual void addAdESSignature(std::istream &signature) = 0;
    virtual Signature* prepareSignature(Signer *signer) = 0;
    virtual std::vector<Signature*> signatures() const = 0;
    virtual void removeSignature(unsigned int index) = 0;
    virtual Signature* sign(Signer *signer) = 0;

    virtual void addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType);

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
