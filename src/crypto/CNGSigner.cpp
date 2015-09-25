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

#include "CNGSigner.h"

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

class CNGSignerPrivate
{
public:
    static BOOL WINAPI CertFilter(PCCERT_CONTEXT cert_context,
        BOOL *is_initial_selected_cert, void *callback_data);

    X509Cert cert;
    NCRYPT_KEY_HANDLE key;
    wstring pin;
    bool selectFirst;
};

}

BOOL CNGSignerPrivate::CertFilter(PCCERT_CONTEXT cert_context, BOOL *, void *)
{
    DWORD flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL ncrypt = false;
    CryptAcquireCertificatePrivateKey(cert_context, flags, 0, &key, &spec, &ncrypt);
    if(!key)
        return false;
    NCryptFreeObject(key);

    X509Cert cert( vector<unsigned char>(cert_context->pbCertEncoded,
        cert_context->pbCertEncoded+cert_context->cbCertEncoded));
    vector<X509Cert::KeyUsage> usage = cert.keyUsage();
    return find(usage.begin(), usage.end(), X509Cert::NonRepudiation) != usage.end();
}

/**
 * Initializes CNG library
 *
 * @throws SignException exception is thrown if the provided CNG driver
 *         loading failed.
 */
CNGSigner::CNGSigner(const string &pin, bool selectFirst)
 : d(new CNGSignerPrivate)
{
    d->key = 0;
    setPin(pin);
    setSelectFirst(selectFirst);
}

/**
 * Uninitializes CNG library and releases acquired memory.
 */
CNGSigner::~CNGSigner()
{
    NCryptFreeObject(d->key);
    delete d;
}

/**
 * Finds all slots connected with the computer, if the slots have tokens, lists all
 * certificates found in token. If there are more that 1 certificate lets the user
 * application select (by calling the <code>selectSignCertificate</code> callback
 * function) the certificate used for signing.
 *
 * @return returns certificate used for signing.
 * @throws throws exception if failed to select the signing certificate. For example
 *         no cards found or card has no certificate.
 */
X509Cert CNGSigner::cert() const
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
        pcsc.pFilterCallback = CNGSignerPrivate::CertFilter;
        pcsc.pvCallbackData = d;
        pcsc.cDisplayStores = 1;
        pcsc.rghDisplayStores = &store;
        cert_context = CryptUIDlgSelectCertificate(&pcsc);
    }
    if(!cert_context)
        THROW("No certificates selected");

    d->cert = X509Cert(vector<unsigned char>(cert_context->pbCertEncoded,
        cert_context->pbCertEncoded+cert_context->cbCertEncoded));
    DWORD flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
    DWORD spec = 0;
    BOOL ncrypt = false;
    CryptAcquireCertificatePrivateKey(cert_context, flags, 0, &d->key, &spec, &ncrypt);
    CertFreeCertificateContext(cert_context);

    return d->cert;
}

void CNGSigner::setPin(const string &pin)
{
    d->pin = util::File::encodeName(pin);
}

void CNGSigner::setSelectFirst(bool first)
{
    d->selectFirst = first;
}

/**
 * Signs the digest provided using the selected certificate. If the certificate needs PIN,
 * the PIN is acquired by calling the callback function <code>getPin</code>.
 *
 * @param digest digest, which is being signed.
 * @return the signature that is created.
 * @throws SignException throws exception if the signing operation failed.
 */
vector<unsigned char> CNGSigner::sign(const string &method, const vector<unsigned char> &digest) const
{
    DEBUG("sign(method = %s, digest = length=%d)", method.c_str(), digest.size());

    BCRYPT_PKCS1_PADDING_INFO padInfo;
    padInfo.pszAlgId = nullptr;
    if(method == URI_RSA_SHA1) padInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
    if(method == URI_RSA_SHA224) padInfo.pszAlgId = L"SHA224";
    if(method == URI_RSA_SHA256) padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
    if(method == URI_RSA_SHA384) padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
    if(method == URI_RSA_SHA512) padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;

    SECURITY_STATUS err = 0;
    if(!d->pin.empty())
        err = NCryptSetProperty(d->key, NCRYPT_PIN_PROPERTY, PBYTE(d->pin.c_str()), DWORD(d->pin.size()), 0);

    DWORD size = 256;
/*  ESTEID minidriver does not support signature size parameter, asks pin
    err = d->f_NCryptSignHash(d->key, &padInfo, PBYTE(&digest[0]), digest.size(),
        0, 0, &size, BCRYPT_PAD_PKCS1);*/

    vector<unsigned char> signature(size, 0);
    err = NCryptSignHash(d->key, &padInfo, PBYTE(&digest[0]), DWORD(digest.size()),
        &signature[0], DWORD(signature.size()), (DWORD*)&size, BCRYPT_PAD_PKCS1);
    signature.resize(size);

    switch(err)
    {
    case ERROR_SUCCESS: break;
    case SCARD_W_CANCELLED_BY_USER:
    {
        Exception e(__FILE__, __LINE__, "PIN acquisition canceled.");
        e.setCode(Exception::PINCanceled);
        throw e;
    }
    default:
        ostringstream s;
        s << "Failed to login to token: " << err;
        Exception e(__FILE__, __LINE__, s.str());
        e.setCode(Exception::PINFailed);
        throw e;
    }
    return signature;
}
