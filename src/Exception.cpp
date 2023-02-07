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

#include "Exception.h"

#include "util/File.h"
#include "util/log.h"

#include <algorithm>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

std::vector<Exception::ExceptionCode> Exception::ignores {};

/**
 * @class digidoc::Exception
 *
 * @brief Base exception class of the digidoc implementation.
 */

/**
 * @enum digidoc::Exception::ExceptionCode
 * Exception code
 *
 * @var digidoc::Exception::General
 * General error, no specific code
 * @var digidoc::Exception::NetworkError
 * Network error, network connection errors
 *
 * @var digidoc::Exception::CertificateIssuerMissing
 * Signer's certificate's issuer certificate is missing
 * @var digidoc::Exception::CertificateRevoked
 * Certificate status is revoked in OCSP response
 * @var digidoc::Exception::CertificateUnknown
 * Certificate status is unknown in OCSP response
 * @var digidoc::Exception::OCSPBeforeTimeStamp
 * OCSP producedAt time is before TimeStamp time
 * @var digidoc::Exception::OCSPResponderMissing
 * OCSP Responder is missing
 * @var digidoc::Exception::OCSPCertMissing
 * OCSP Responder certificate is missing
 * @var digidoc::Exception::OCSPTimeSlot
 * OCSP Response is not in valid time slot
 * @var digidoc::Exception::OCSPRequestUnauthorized
 * OCSP Responder requires the OCSP request to be signed
 * @var digidoc::Exception::TSForbidden
 * TSA service responds forbidden
 * @var digidoc::Exception::TSTooManyRequests
 * TSA service requests have reached limit
 *
 * @var digidoc::Exception::PINCanceled
 * PIN cancelled exception
 * @var digidoc::Exception::PINFailed
 * PIN verification error
 * @var digidoc::Exception::PINIncorrect
 * PIN incorrect error
 * @var digidoc::Exception::PINLocked
 * PIN locked error
 *
 * @var digidoc::Exception::ReferenceDigestWeak
 * One or more referenced objects in container are calculated by using weaker digest method that recommended
 * @var digidoc::Exception::SignatureDigestWeak
 * The digest that is signed in container has been calculated by using weaker digest method than recommended
 * @var digidoc::Exception::DataFileNameSpaceWarning
 * DDoc warning: &lt;DataFile&gt; XML element is missing xmlns attribute 
 * @var digidoc::Exception::IssuerNameSpaceWarning
 * DDoc warning: &lt;X509IssuerName&gt; and/or &lt;X509IssuerSerial&gt; XML element is missing xmlns attribute
 * @var digidoc::Exception::ProducedATLateWarning
 * TimeStamp and OCSP time difference is more than 15 minutes
 * @var digidoc::Exception::MimeTypeWarning
 * Mime type is not conformant mime-type strings
 *
 * @var digidoc::Exception::DDocError
 * DDoc libdigidoc error codes bit masked
 * @deprecated Unused
 */

/**
 * @param file source file name, where the exception was thrown.
 * @param line line of the file, where the exception was thrown.
 * @param msg error message.
 */
Exception::Exception(const string& file, int line, const string& msg)
 : m_file(File::fileName(file))
 , m_msg(msg)
 , m_line(line)
 , m_code(General)
{
}

/**
 * Convenience constructor when there is just one cause for this Exception.
 * 
 * @param file source file name, where the exception was thrown.
 * @param line line of the file, where the exception was thrown.
 * @param msg error message.
 * @param cause cause of the exception.
 * @see causes()
 */
Exception::Exception(const string& file, int line, const string& msg, const Exception& cause)
    : Exception(file, line, msg)
{
    addCause(cause);
}

/**
 * Copy constructor
 */
Exception::Exception(const Exception &other) = default;

/**
 * Move constructor
 */
Exception::Exception(Exception &&other) DIGIDOCPP_NOEXCEPT = default;

/**
 * Releases memory
 */
Exception::~Exception() = default;

/**
 * Copy operator
 */
Exception &Exception::operator=(const Exception &other) = default;

/**
 * Move operator
 */
Exception &Exception::operator=(Exception &&other) DIGIDOCPP_NOEXCEPT = default;

/**
 * Returns exception file
 */
string Exception::file() const
{
    return m_file;
}

/**
 * Returns exception line
 */
int Exception::line() const
{
    return m_line;
}

/**
 * Returns exception code
 */
Exception::ExceptionCode Exception::code() const { return m_code; }

/**
 * Returns error message.
 */
string Exception::msg() const { return m_msg; }

/**
 * Adds child Exception
 */
void Exception::addCause(const Exception& cause) { m_causes.push_back(cause); }

/**
 * Returns exception causes (other exceptions that caused this exception).
 */
Exception::Causes Exception::causes() const { return m_causes; }

/**
 * Sets exception code
 */
void Exception::setCode( ExceptionCode code ) { m_code = code; }

/**
 * Ignore Warning exceptions globaly
 * @param code Push additional exception to list
 */
void Exception::addWarningIgnore(ExceptionCode code) { ignores.push_back(code); }

/**
 * Ignore Warning exceptions globaly
 * @param list Set new exception list
 */
void Exception::setWarningIgnoreList(const std::vector<ExceptionCode> &list) { ignores = list; }

/**
 * Verifies if Warning exception is in igonre list
 */
bool Exception::hasWarningIgnore(ExceptionCode code) { return find(ignores.cbegin(), ignores.cend(), code) != ignores.cend(); }
