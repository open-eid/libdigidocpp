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
#include <WinCrypt.h>
#include <cryptuiapi.h>

using namespace digidoc;
using namespace std;

#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)

extern "C" {

typedef BOOL (WINAPI * PFNCCERTDISPLAYPROC)(
  __in  PCCERT_CONTEXT pCertContext,
  __in  HWND hWndSelCertDlg,
  __in  void *pvCallbackData
);

typedef struct _CRYPTUI_SELECTCERTIFICATE_STRUCT {
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
} CRYPTUI_SELECTCERTIFICATE_STRUCT, *PCRYPTUI_SELECTCERTIFICATE_STRUCT;

typedef const CRYPTUI_SELECTCERTIFICATE_STRUCT
  *PCCRYPTUI_SELECTCERTIFICATE_STRUCT;

PCCERT_CONTEXT WINAPI CryptUIDlgSelectCertificateW(
  __in  PCCRYPTUI_SELECTCERTIFICATE_STRUCT pcsc
);

#define CryptUIDlgSelectCertificate CryptUIDlgSelectCertificateW

}  // extern "C"

namespace digidoc
{

class WinSignerPrivate
{
public:
    static BOOL WINAPI CertFilter(PCCERT_CONTEXT cert_context,
        BOOL *is_initial_selected_cert, void *callback_data);

    X509Cert cert;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL freeKey = false;
    string pin;
    bool selectFirst = false;
};

}

BOOL WinSignerPrivate::CertFilter(PCCERT_CONTEXT cert_context, BOOL *, void *)
{
    DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL freeKey = false;
    CryptAcquireCertificatePrivateKey(cert_context, flags, 0, &key, &spec, &freeKey);
    if(!key)
        return false;
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

    X509Cert cert(vector<unsigned char>(cert_context->pbCertEncoded,
        cert_context->pbCertEncoded+cert_context->cbCertEncoded));
    vector<X509Cert::KeyUsage> usage = cert.keyUsage();
    return find(usage.cbegin(), usage.cend(), X509Cert::NonRepudiation) != usage.cend();
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
 : d(new WinSignerPrivate)
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
    if(d->selectFirst)
    {
        PCCERT_CONTEXT find = nullptr;
        while(find = CertFindCertificateInStore(store, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, find))
        {
            if(d->CertFilter(find, 0, 0))
            {
                cert_context = find;
                break;
            }
        }
    }
    else
    {
        CRYPTUI_SELECTCERTIFICATE_STRUCT pcsc = { sizeof(pcsc) };
        pcsc.pFilterCallback = WinSignerPrivate::CertFilter;
        pcsc.pvCallbackData = d;
        pcsc.cDisplayStores = 1;
        pcsc.rghDisplayStores = &store;
        cert_context = CryptUIDlgSelectCertificate(&pcsc);
    }
    if(!cert_context)
        THROW("No certificates selected");

    d->cert = X509Cert(vector<unsigned char>(cert_context->pbCertEncoded,
        cert_context->pbCertEncoded+cert_context->cbCertEncoded));
    DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
    CryptAcquireCertificatePrivateKey(cert_context, flags, 0, &d->key, &d->spec, &d->freeKey);
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

vector<unsigned char> WinSigner::sign(const string &method, const vector<unsigned char> &digest) const
{
    DEBUG("sign(method = %s, digest = length=%d)", method.c_str(), digest.size());

    BCRYPT_PKCS1_PADDING_INFO padInfo;
    padInfo.pszAlgId = nullptr;
    ALG_ID alg = 0;
    if(method == URI_RSA_SHA1) { padInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM; alg = CALG_SHA1; }
    else if(method == URI_RSA_SHA224) { padInfo.pszAlgId = L"SHA224"; }
    else if(method == URI_RSA_SHA256) { padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM; alg = CALG_SHA_256; }
    else if(method == URI_RSA_SHA384) { padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM; alg = CALG_SHA_384; }
    else if(method == URI_RSA_SHA512) { padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM; alg = CALG_SHA_512; }
    else THROW("Unsupported signature method");

    SECURITY_STATUS err = 0;
    DWORD size = 256;
    vector<unsigned char> signature(size, 0);
    switch(d->spec)
    {
    case CERT_NCRYPT_KEY_SPEC:
    {
        if(!d->pin.empty())
        {
            wstring pin = util::File::encodeName(d->pin);
            err = NCryptSetProperty(d->key, NCRYPT_PIN_PROPERTY, PBYTE(pin.c_str()), DWORD(pin.size()), 0);
            if(err != ERROR_SUCCESS)
                break;
        }

        err = NCryptSignHash(d->key, &padInfo, PBYTE(digest.data()), DWORD(digest.size()),
            signature.data(), DWORD(signature.size()), &size, BCRYPT_PAD_PKCS1);
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
        if(!CryptSignHashW(hash, AT_SIGNATURE, 0, 0, signature.data(), &size))
            err = LONG(GetLastError());
        std::reverse(signature.begin(), signature.end());

        CryptDestroyHash(hash);
        break;
    }
    default:
        THROW("Failed to sign");
    }
    signature.resize(size);

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
