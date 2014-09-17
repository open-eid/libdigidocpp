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
#include "log.h"

#include <functional>
#include <memory>
#include <sstream>

#include <openssl/err.h>

namespace digidoc
{

#define SCOPE2(TYPE, VAR, DATA, FREE) std::unique_ptr<TYPE,std::function<void(TYPE *)>> VAR(DATA, FREE)
#define SCOPE(TYPE, VAR, DATA) SCOPE2(TYPE, VAR, DATA, TYPE##_free)

/**
* OpenSSL exception implementation. Thrown if the openssl returns error
*
*/
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

class OpenSSLException : public Exception
{
	public:
		/**
		* @param file filename, where the exception was thrown.
		* @param line line of the file, where the exception was thrown.
		* @see Exception::Exception(const std::string& file, int line, const std::string& msg)
		*/
		OpenSSLException(): Exception("", 0, message()) {}
	private:
		static std::string message()
		{
			unsigned long errorCode;
			std::stringstream str;
			while((errorCode =  ERR_get_error()) != 0)
				str << ERR_error_string(errorCode, 0) << std::endl;
			return str.str();
		}
};

#ifdef __APPLE__
#pragma clang diagnostic pop
#endif

#define THROW_OPENSSLEXCEPTION(...) THROW_CAUSE(OpenSSLException(), __VA_ARGS__)

}
