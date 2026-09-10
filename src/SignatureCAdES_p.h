// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <openssl/cms.h>
#include <openssl/rsa.h>

#include <memory>

namespace digidoc {

class SignatureCAdESPrivate: public std::shared_ptr<CMS_ContentInfo>
{
public:
	CMS_SignerInfo *si = nullptr;
	RSA_METHOD method;
};
}
