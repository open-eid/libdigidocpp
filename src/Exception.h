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
    class EXP_DIGIDOC Exception
    {
      public:
          /**
           * Exception code
           */
          enum ExceptionCode {
              General                  = 0,
              //Verification errors
              CertificateIssuerMissing = 10,
              CertificateRevoked       = 5,
              CertificateUnknown       = 6,
              OCSPResponderMissing     = 8,
              OCSPCertMissing          = 9,
              OCSPTimeSlot             = 7,
              OCSPRequestUnauthorized  = 11,
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
              ProducedATLateWarning     = 16,
              QSCDConformanceWarning   = 17,
              //DDoc error codes
              DDocError                = 512
          };
          typedef std::vector<Exception> Causes;

          Exception(const std::string& file, int line, const std::string& msg);
          Exception(const std::string& file, int line, const std::string& msg, const Exception& cause);
          virtual ~Exception();

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
