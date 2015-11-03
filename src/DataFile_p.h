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

#include "DataFile.h"

#include <istream>
#include <memory>

namespace digidoc
{

class Digest;
class DataFilePrivate: public DataFile
{
public:
	DataFilePrivate(std::istream *is, const std::string &filename, const std::string &mediatype,
			 const std::string &id = "", const std::vector<unsigned char> &digestValue = std::vector<unsigned char>());

	std::string id() const override { return m_id; }
	std::string fileName() const override { return m_filename; }
	unsigned long fileSize() const override { return m_size; }
	std::string mediaType() const override { return m_mediatype; }

	std::vector<unsigned char> calcDigest(const std::string &method) const override;
	void calcDigest(Digest *method) const;
	void saveAs(std::ostream &os) const override;
	void saveAs(const std::string& path) const override;

	std::shared_ptr<std::istream> m_is;
	std::string m_id, m_filename, m_mediatype;
	std::vector<unsigned char> m_digestValue;
	unsigned long m_size;
};
}
