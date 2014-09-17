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

#include "DirectoryX509CertStore.h"

#include "log.h"
#include "util/File.h"

using namespace digidoc;

/**
 * Load all certificates found in directory and adds these to the cert store.
 *
 * @param path path to X.509 certificates in PEM format.
 * @throws IOException exception is throws if the folder does not exist.
 */
DirectoryX509CertStore::DirectoryX509CertStore(const std::string &path)
{
    if(!util::File::directoryExists(path))
        THROW("Directory %s does not exists, can not load cert store.", path.c_str());

    for(const std::string &file: util::File::listFiles(path))
    {
        try {
            addCert(X509Cert(file));
        } catch(const Exception &e) {
            WARN("Failed to parse cert '%s': %s", file.c_str(),
                 e.causes().empty() ? e.msg().c_str() : e.causes().front().msg().c_str());
        }
    }
    INFO("Loaded %d certificates into certificate store.", certs().size());
}
