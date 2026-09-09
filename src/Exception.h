// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
