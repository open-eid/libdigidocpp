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

#include "WinSigner.h"

#include "Conf.h"
#include "log.h"
#include "crypto/X509Cert.h"
#include "crypto/Digest.h"
#include "util/File.h"

#include <algorithm>
#include <sstream>
#include <Windows.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

using namespace digidoc;
using namespace std;

#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) || DOXYGEN

extern "C" {

typedef BOOL (WINAPI * PFNCCERTDISPLAYPROC)(
  __in  PCCERT_CONTEXT pCertContext,
  __in  HWND hWndSelCertDlg,
  __in  void *pvCallbackData
);

using CRYPTUI_SELECTCERTIFICATE_STRUCT = struct {
  DWORD               dwSize;
  HWND                hwndParent;
  DWORD               dwFlags;
  LPCWSTR             szTitle;
  DWORD               dwDontUseColumn;
  LPCWSTR             szDisplayString;
  PFNCFILTERPROC      pFilterCallback;
  PFNCCERTDISPLAYPROC pDisplayCallback;
  void *              pvCallbackData;
  DWORD               cDisplayStores;
  HCERTSTORE *        rghDisplayStores;
  DWORD               cStores;
  HCERTSTORE *        rghStores;
  DWORD               cPropSheetPages;
  LPCPROPSHEETPAGEW   rgPropSheetPages;
  HCERTSTORE          hSelectedCertStore;
};

PCCERT_CONTEXT WINAPI CryptUIDlgSelectCertificateW(
  __in const CRYPTUI_SELECTCERTIFICATE_STRUCT *pcsc
);

}  // extern "C"

namespace digidoc
{

class WinSigner::Private
{
public:
    static BOOL WINAPI CertFilter(PCCERT_CONTEXT cert_context,
        BOOL *is_initial_selected_cert, void *callback_data);

    X509Cert cert;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL freeKey = FALSE;
    string pin;
    vector<unsigned char> thumbprint;
    bool selectFirst = false;
};

}

BOOL WinSigner::Private::CertFilter(PCCERT_CONTEXT cert_context, BOOL * /* is_initial_selected_cert */, void * /* callback_data */)
{
    DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL freeKey = FALSE;
    CryptAcquireCertificatePrivateKey(cert_context, flags, nullptr, &key, &spec, &freeKey);
    if(!key)
        return FALSE;
    switch(spec)
    {
    case CERT_NCRYPT_KEY_SPEC:
        if(freeKey)
            NCryptFreeObject(key);
        break;
    case AT_KEYEXCHANGE:
    case AT_SIGNATURE:
    default:
        if(freeKey)
            CryptReleaseContext(key, 0);
        break;
    }

    BYTE keyUsage = 0;
    CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_context->pCertInfo, &keyUsage, 1);
    return (keyUsage & CERT_NON_REPUDIATION_KEY_USAGE) > 0;
}

/**
 * @class digidoc::WinSigner
 * @brief Implements <code>Signer</code> interface for Windows Crypto backends.
 */
/**
 * Initializes WinSigner class
 *
 * @param pin Optional parameter to skip PIN dialog
 * @param selectFirst Optional parameter to skip certificate selection dialog
 *  when there is more than one token sertificate available
 * @throws Exception exception is thrown if the loading failed.
 */
WinSigner::WinSigner(const string &pin, bool selectFirst)
    : d(new Private)
{
    setPin(pin);
    setSelectFirst(selectFirst);
}

WinSigner::~WinSigner()
{
    switch(d->spec)
    {
    case CERT_NCRYPT_KEY_SPEC:
        if(d->freeKey)
            NCryptFreeObject(d->key);
        break;
    case AT_KEYEXCHANGE:
    case AT_SIGNATURE:
    default:
        if(d->freeKey)
            CryptReleaseContext(d->key, 0);
        break;
    }
    delete d;
}

X509Cert WinSigner::cert() const
{
    if(!!d->cert)
        return d->cert;

    HCERTSTORE store = CertOpenSystemStore(0, L"MY");
    if(!store)
        return d->cert;

    PCCERT_CONTEXT cert_context = nullptr;
    if(!d->thumbprint.empty())
    {
        CRYPT_HASH_BLOB hashBlob = { DWORD(d->thumbprint.size()), PBYTE(d->thumbprint.data()) };
        cert_context = CertFindCertificateInStore(store, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, PVOID(&hashBlob), nullptr);
    }
    else if(d->selectFirst)
    {
        PCCERT_CONTEXT find = nullptr;
        while((find = CertFindCertificateInStore(store, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, find)))
        {
            if(d->CertFilter(find, nullptr, nullptr))
            {
                cert_context = find;
                break;
            }
        }
    }
    else
    {
        CRYPTUI_SELECTCERTIFICATE_STRUCT pcsc = {};
        pcsc.dwSize = sizeof(pcsc);
        pcsc.pFilterCallback = Private::CertFilter;
        pcsc.pvCallbackData = d;
        pcsc.cDisplayStores = 1;
        pcsc.rghDisplayStores = &store;
        cert_context = CryptUIDlgSelectCertificateW(&pcsc);
    }
    if(!cert_context)
        THROW("No certificates selected");

    d->cert = X509Cert(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
    DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
    CryptAcquireCertificatePrivateKey(cert_context, flags, nullptr, &d->key, &d->spec, &d->freeKey);
    CertFreeCertificateContext(cert_context);

    return d->cert;
}

/**
 * Sets property PIN
 * @see WinSigner::WinSigner
 */
void WinSigner::setPin(const string &pin)
{
    d->pin = pin;
}

/**
 * Sets property select first certificate
 * @see WinSigner::WinSigner
 */
void WinSigner::setSelectFirst(bool first)
{
    d->selectFirst = first;
}

/**
 * Sets property select certificate with specified thumbprint
 * @see WinSigner::WinSigner
 */
void WinSigner::setThumbprint(const vector<unsigned char> &thumbprint)
{
    d->thumbprint = thumbprint;
}

vector<unsigned char> WinSigner::sign(const string &method, const vector<unsigned char> &digest) const
{
    DEBUG("sign(method = %s, digest = length=%d)", method.c_str(), digest.size());

    BCRYPT_PKCS1_PADDING_INFO padInfo = { nullptr };
    ALG_ID alg = 0;
    if(method == URI_RSA_SHA1) { padInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM; alg = CALG_SHA1; }
    else if(method == URI_RSA_SHA224) { padInfo.pszAlgId = L"SHA224"; }
    else if(method == URI_RSA_SHA256) { padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM; alg = CALG_SHA_256; }
    else if(method == URI_RSA_SHA384) { padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM; alg = CALG_SHA_384; }
    else if(method == URI_RSA_SHA512) { padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM; alg = CALG_SHA_512; }
    else if(method == URI_ECDSA_SHA224) {}
    else if(method == URI_ECDSA_SHA256) {}
    else if(method == URI_ECDSA_SHA384) {}
    else if(method == URI_ECDSA_SHA512) {}
    else THROW("Unsupported signature method");

    SECURITY_STATUS err = 0;
    vector<unsigned char> signature;
    switch(d->spec)
    {
    case CERT_NCRYPT_KEY_SPEC:
    {
        DWORD size = 0;
        wstring algo(5, 0);
        err = NCryptGetProperty(d->key, NCRYPT_ALGORITHM_GROUP_PROPERTY, PBYTE(algo.data()), DWORD((algo.size() + 1) * 2), &size, 0);
        algo.resize(size/2 - 1);
        bool isRSA = algo == L"RSA";

        if(!d->pin.empty())
        {
            wstring pin = util::File::encodeName(d->pin);
            err = NCryptSetProperty(d->key, NCRYPT_PIN_PROPERTY, PBYTE(pin.c_str()), DWORD(pin.size()), 0);
            if(err != ERROR_SUCCESS)
                break;
        }

        err = NCryptSignHash(d->key, isRSA ? &padInfo : nullptr, PBYTE(digest.data()), DWORD(digest.size()),
            nullptr, 0, &size, isRSA ? BCRYPT_PAD_PKCS1 : 0);
        if(FAILED(err))
            break;
        signature.resize(size);
        err = NCryptSignHash(d->key, isRSA ? &padInfo : nullptr, PBYTE(digest.data()), DWORD(digest.size()),
            signature.data(), DWORD(signature.size()), &size, isRSA ? BCRYPT_PAD_PKCS1 : 0);
        break;
    }
    case AT_SIGNATURE:
    case AT_KEYEXCHANGE:
    {
        if(method == URI_RSA_SHA224)
            THROW("Unsupported digest");

        if(!d->pin.empty() &&
           !CryptSetProvParam(d->key, d->spec == AT_SIGNATURE ? PP_SIGNATURE_PIN : PP_KEYEXCHANGE_PIN, LPBYTE(d->pin.c_str()), 0))
        {
            err = LONG(GetLastError());
            break;
        }

        HCRYPTHASH hash = 0;
        if(!CryptCreateHash(d->key, alg, 0, 0, &hash))
            THROW("Failed to sign");

        if(!CryptSetHashParam(hash, HP_HASHVAL, LPBYTE(digest.data()), 0))
        {
            CryptDestroyHash(hash);
            THROW("Failed to sign");
        }
        DWORD size = 0;
        if(!CryptSignHashW(hash, d->spec, nullptr, 0, nullptr, &size)) {
            err = LONG(GetLastError());
            CryptDestroyHash(hash);
            break;
        }
        signature.resize(size);
        if(!CryptSignHashW(hash, d->spec, nullptr, 0, signature.data(), &size))
            err = LONG(GetLastError());
        std::reverse(signature.begin(), signature.end());

        CryptDestroyHash(hash);
        break;
    }
    default:
        THROW("Failed to sign");
    }

    switch(err)
    {
    case ERROR_SUCCESS: break;
    case ERROR_CANCELLED:
    case SCARD_W_CANCELLED_BY_USER:
    {
        Exception e(__FILE__, __LINE__, "PIN acquisition canceled.");
        e.setCode(Exception::PINCanceled);
        throw e;
    }
    case SCARD_W_WRONG_CHV:
    default:
        ostringstream s;
        s << "Failed to login to token: " << err;
        Exception e(__FILE__, __LINE__, s.str());
        e.setCode(Exception::PINFailed);
        throw e;
    }
    return signature;
}

#endif
