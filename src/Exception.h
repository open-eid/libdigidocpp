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
    class DIGIDOCPP_EXPORT Exception
    {
      public:
          /**
           * Exception code
           */
          enum ExceptionCode {
              General                  = 0,
              NetworkError             = 20,
              HostNotFound             = 101,
              InvalidUrl               = 102,
              //Verification errors
              CertificateIssuerMissing = 10,
              CertificateRevoked       = 5,
              CertificateUnknown       = 6,
              OCSPBeforeTimeStamp      = 19,
              OCSPResponderMissing     = 8,
              OCSPCertMissing          = 9,
              OCSPTimeSlot             = 7,
              OCSPRequestUnauthorized  = 11,
              TSForbidden              = 21,
              TSTooManyRequests        = 18,
              //Pin exceptions
              PINCanceled              = 2,
              PINFailed                = 4,
              PINIncorrect             = 1,
              PINLocked                = 3,
              //Warnings
              ReferenceDigestWeak      = 12,
              SignatureDigestWeak      = 13,
              DataFileNameSpaceWarning = 14,
              IssuerNameSpaceWarning   = 15,
              ProducedATLateWarning    = 16,
              MimeTypeWarning          = 17,
              //DDoc error codes
              DDocError                = 512 //DIGIDOCPP_DEPRECATED
          };
          using Causes = std::vector<Exception>;

          Exception(const std::string& file, int line, const std::string& msg);
          Exception(const std::string& file, int line, const std::string& msg, const Exception& cause);
          Exception(const Exception &other);
          Exception(Exception &&other) noexcept;
          virtual ~Exception();
          Exception &operator=(const Exception &other);
          Exception &operator=(Exception &&other) noexcept;

          std::string file() const;
          int line() const;
          ExceptionCode code() const;
          std::string msg() const;
          Causes causes() const;
          void addCause(const Exception& cause);
          void setCode( ExceptionCode Code );

          static void addWarningIgnore(ExceptionCode code);
          static void setWarningIgnoreList(const std::vector<ExceptionCode> &list);
          static bool hasWarningIgnore(ExceptionCode code);

      private:
          std::string m_file;
          std::string m_msg;
          int m_line;
          Causes m_causes;
          ExceptionCode m_code;

          static std::vector<ExceptionCode> ignores;
    };

}
