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

#include "PKCS11Signer.h"

#include "pkcs11.h"

#include "log.h"
#include "Conf.h"
#include "crypto/Digest.h"
#include "crypto/X509Cert.h"
#include "util/File.h"

#include <algorithm>
#include <sstream>
#include <cstring>
#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

namespace digidoc
{

struct SignSlot
{
    X509Cert certificate;
    CK_SLOT_ID slot;
    CK_ULONG cert;
};

class PKCS11SignerPrivate
{
public:
    PKCS11SignerPrivate()
    : h(0), f(0)
    {
        sign.slot = 0;
        sign.cert = 0;
    }

    bool attribute( CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
        CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG &size ) const;
    vector<CK_OBJECT_HANDLE> findObject(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls) const;

#ifdef _WIN32
    bool load(const string &driver)
    {
        wstring _driver = File::encodeName(driver);
        return (h = LoadLibraryW(_driver.c_str())) != 0;
    }

    void* resolve(const char *symbol)
    { return h ? (void*)GetProcAddress(h, symbol) : 0; }

    void unload()
    { if(h) FreeLibrary(h); h = 0; }

    HINSTANCE h;
#else
    bool load(const string &driver)
    { return (h = dlopen(driver.c_str(), RTLD_LAZY)); }

    void* resolve(const char *symbol)
    { return h ? dlsym(h, symbol) : 0; }

    void unload()
    { if(h) dlclose(h); h = 0; }

    void *h;
#endif

    CK_FUNCTION_LIST *f;
    SignSlot sign;
    string pin;

    static const unsigned char sha1[];
    static const unsigned char sha224[];
    static const unsigned char sha256[];
    static const unsigned char sha384[];
    static const unsigned char sha512[];
};

}

const unsigned char PKCS11SignerPrivate::sha1[] =
{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };

const unsigned char PKCS11SignerPrivate::sha224[] =
{ 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c };

const unsigned char PKCS11SignerPrivate::sha256[] =
{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

const unsigned char PKCS11SignerPrivate::sha384[] =
{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };

const unsigned char PKCS11SignerPrivate::sha512[] =
{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };



bool PKCS11SignerPrivate::attribute(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG &size) const
{
    CK_ATTRIBUTE attr = { type, value, size };
    CK_RV err = f->C_GetAttributeValue(session, obj, &attr, 1);
    size = attr.ulValueLen;
    return err == CKR_OK;
}

vector<CK_OBJECT_HANDLE> PKCS11SignerPrivate::findObject(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls) const
{
    CK_ATTRIBUTE attr = { CKA_CLASS, &cls, sizeof(cls) };
    if(f->C_FindObjectsInit(session, &attr, 1) != CKR_OK)
        return vector<CK_OBJECT_HANDLE>();

    CK_ULONG count = 32;
    vector<CK_OBJECT_HANDLE> result(count, 0);
    CK_RV err = f->C_FindObjects(session, &result[0], CK_ULONG(result.size()), &count);
    result.resize(err == CKR_OK ? count : 0);
    f->C_FindObjectsFinal(session);
    return result;
}


/**
 * @class digidoc::PKCS11Signer
 * @brief Implements <code>Signer</code> interface for ID-Cards, which support PKCS#11 protocol.
 *
 * Abstract method <code>selectSigningCertificate</code> is called if the signer needs
 * to choose the correct signing certificate. It is called also if there is only one certificate
 * found on ID-Card. Parameter <code>certificates</code> provides list of all certificates
 * found in the ID-Card.
 *
 * Abstract method <code>pin</code> is called if the selected certificate needs PIN
 * to log in.
 *
 * @see selectSigningCertificate
 * @see pin
 */


/**
 * Loads PKCS#11 driver.
 *
 * @param driver full path to the PKCS#11 driver (e.g. /usr/lib/opensc-pkcs11.so)
 * @throws Exception exception is thrown if the provided PKCS#11 driver loading failed.
 */
PKCS11Signer::PKCS11Signer(const string &driver)
 : d(new PKCS11SignerPrivate)
{
    string load = driver;
    if(driver.empty())
        load = Conf::instance()->PKCS11Driver();

    DEBUG("PKCS11Signer(driver = '%s')", load.c_str());
    if(load.empty())
        THROW("Failed to load driver for PKCS #11 engine: %s.", load.c_str());

    if(!d->load(load))
        THROW("Failed to load driver for PKCS #11 engine: %s.", load.c_str());

    CK_C_GetFunctionList l = CK_C_GetFunctionList(d->resolve( "C_GetFunctionList" ));
    if( !l ||
        l( &d->f ) != CKR_OK ||
        d->f->C_Initialize( 0 ) != CKR_OK )
        THROW("Failed to load driver for PKCS #11 engine: %s.", load.c_str());
}

/**
 * Unload PKCS#11 module and releases acquired memory.
 */
PKCS11Signer::~PKCS11Signer()
{
    DEBUG("~PKCS11Signer()");

    if(d->f)
    {
        d->f->C_Finalize( 0 );
        d->f = 0;
        d->unload();
    }

    delete d;
}

/**
 * @brief Reimplemented parent class method <code>digidoc::Signer::cert</code>
 *
 * Finds all slots connected with the computer, if the slots have tokens, lists all
 * certificates found in token. If there is more that 1 certificate lets the user
 * application select (by calling the <code>selectSignCertificate</code> callback
 * function) the certificate used for signing.
 *
 * @throws Exception throws exception if failed to select the signing certificate. For example
 * no cards found or card has no certificate.
 */
X509Cert PKCS11Signer::cert() const
{
    DEBUG("PKCS11Signer::getCert()");

    // If certificate is already selected return it.
    if(!!d->sign.certificate)
        return d->sign.certificate;

    // Load all slots.
    CK_ULONG size = 0;
    if(d->f->C_GetSlotList(true, 0, &size) != CKR_OK)
        THROW("Could not find any ID-Cards in any readers");
    vector<CK_SLOT_ID> slots(size, 0);
    if(size && d->f->C_GetSlotList(true, &slots[0], &size) != CKR_OK)
        THROW("Could not find any ID-Cards in any readers");

    // Iterate over all found slots, if the slot has a token, check if the token has any certificates.
    CK_SESSION_HANDLE session = 0;
    vector<X509Cert> certificates;
    vector<SignSlot> certSlotMapping;
    for(size_t i = 0; i < slots.size(); ++i)
    {
        CK_TOKEN_INFO token;
        vector<CK_OBJECT_HANDLE> objs;

        if(session)
           d->f->C_CloseSession(session);

        if(d->f->C_GetTokenInfo(slots[i], &token) != CKR_OK ||
           d->f->C_OpenSession(slots[i], CKF_SERIAL_SESSION, 0, 0, &session) != CKR_OK ||
           (objs = d->findObject(session, CKO_CERTIFICATE)).empty())
            continue;

        for(size_t j = 0; j < objs.size(); ++j)
        {
            CK_ULONG size = 0;
            if(!d->attribute(session, objs[j], CKA_VALUE, 0, size))
                continue;
            vector<unsigned char> value(size, 0);
            if(!d->attribute(session, objs[j], CKA_VALUE, &value[0], size))
                continue;
            X509Cert x509(value);
            vector<X509Cert::KeyUsage> usage = x509.keyUsage();
            if(!x509.isValid() || find(usage.begin(), usage.end(), X509Cert::NonRepudiation) == usage.end())
                continue;
            SignSlot signSlot = { x509, slots[i], CK_ULONG(j) };
            certSlotMapping.push_back(signSlot);
            certificates.push_back(x509);
        }
    }
    if(session)
        d->f->C_CloseSession(session);

    if(certificates.empty())
        THROW("No certificates found.");

    // Let the application select the signing certificate.
    X509Cert selectedCert = selectSigningCertificate(certificates);
    if(!selectedCert)
        THROW("No certificate selected.");

    // Find the corresponding slot and PKCS11 certificate struct.
    for(vector<SignSlot>::const_iterator i = certSlotMapping.begin(); i != certSlotMapping.end(); ++i)
    {
        if(i->certificate == selectedCert)
            d->sign = *i;
    }

    if(!d->sign.certificate)
        THROW("Could not find slot for selected certificate.");

    return d->sign.certificate;
}


/**
 * Abstract method that returns PIN code for the selected signing certificate.
 * If PIN code is not needed this method is never called. To cancel the login
 * this method should throw an exception.
 *
 * @param certificate certificate that is used for signing and needs a PIN
 * for login.
 * @return returns the PIN code to login.
 * @throws Exception should throw an exception if the login operation
 * should be canceled.
 */
string PKCS11Signer::pin(const X509Cert &) const
{
    return d->pin;
}


/**
 * Abstract method for selecting the correct signing certificate. If none of
 * the certificates suit for signing, this method should throw an Exception.
 * This method is always called, when there is at least 1 certificate available.
 *
 * @param certificates available certificates to choose from.
 * @return returns the certificate used for signing.
 * @throws Exception should throw an exception if no suitable certificate
 * is in the list or the operation should be cancelled.
 */
X509Cert PKCS11Signer::selectSigningCertificate(const vector<X509Cert> &certificates) const
{
    return certificates.front();
}

/**
 * If sub class does not want reimplement <code>pin</code> method then it is possible set default pin
 *
 * @param pin
 */
void PKCS11Signer::setPin(const string &pin)
{
    d->pin = pin;
}

/**
 * @brief Reimplemented parent class method <code>digidoc::Signer::sign</code>
 *
 * Signs the digest provided using the selected certificate. If the certificate needs PIN,
 * the PIN is acquired by calling the callback function <code>pin</code>.
 *
 * @param digest digest, which is being signed.
 * @param signature memory for the signature that is created.
 * @throws Exception throws exception if the signing operation failed.
 */
void PKCS11Signer::sign(const string &method, const vector<unsigned char> &digest,
                        vector<unsigned char> &signature)
{
    DEBUG("sign(mehthod = %s, digest = length=%d, signature=length=%d)",
          method.c_str(), digest.size(), signature.size());

    // Check that sign slot and certificate are selected.
    if(!d->sign.certificate)
        THROW("Signing slot or certificate are not selected.");

    // Login if required.
    CK_TOKEN_INFO token;
    CK_SESSION_HANDLE session;
    if(d->f->C_GetTokenInfo(d->sign.slot, &token) != CKR_OK ||
       d->f->C_OpenSession(d->sign.slot, CKF_SERIAL_SESSION, 0, 0, &session) != CKR_OK)
        THROW("Signing slot or certificate are not selected.");

    CK_RV rv = CKR_OK;
    if(token.flags & CKF_LOGIN_REQUIRED)
    {
        if(token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
            rv = d->f->C_Login(session, CKU_USER, 0, 0);
        else
        {
            string _pin = pin(d->sign.certificate);
            rv = d->f->C_Login(session, CKU_USER, CK_BYTE_PTR(_pin.c_str()), CK_ULONG(_pin.size()));
        }
        switch(rv)
        {
        case CKR_OK: break;
        case CKR_CANCEL:
        case CKR_FUNCTION_CANCELED:
        {
            Exception e(__FILE__, __LINE__, "PIN acquisition canceled.");
            e.setCode( Exception::PINCanceled );
            throw e;
        }
        case CKR_PIN_INCORRECT:
        {
            Exception e(__FILE__, __LINE__, "PIN Incorrect");
            e.setCode( Exception::PINIncorrect );
            throw e;
        }
        case CKR_PIN_LOCKED:
        {
            Exception e(__FILE__, __LINE__, "PIN Locked");
            e.setCode( Exception::PINLocked );
            throw e;
        }
        default:
            ostringstream s;
            s << "Failed to login to token '" << token.label << "': " << rv;
            Exception e(__FILE__, __LINE__, s.str());
            e.setCode( Exception::PINFailed );
            throw e;
        }
    }

    vector<CK_OBJECT_HANDLE> key = d->findObject(session, CKO_PRIVATE_KEY);
    if( key.empty() )
        THROW("Could not get key that matches selected certificate.");

    // Sign the digest.
    CK_MECHANISM mech = { CKM_RSA_PKCS, 0, 0 };
    if( d->f->C_SignInit( session, &mech, key[d->sign.cert] ) != CKR_OK )
        THROW("Failed to sign digest");

    const unsigned char *sha = nullptr;
    size_t shasize = 0;
    if( method == URI_RSA_SHA1 ) { sha = PKCS11SignerPrivate::sha1; shasize = sizeof(PKCS11SignerPrivate::sha1); }
    if( method == URI_RSA_SHA224 ) { sha = PKCS11SignerPrivate::sha224; shasize = sizeof(PKCS11SignerPrivate::sha224); }
    if( method == URI_RSA_SHA256 ) { sha = PKCS11SignerPrivate::sha256; shasize = sizeof(PKCS11SignerPrivate::sha256); }
    if( method == URI_RSA_SHA384 ) { sha = PKCS11SignerPrivate::sha384; shasize = sizeof(PKCS11SignerPrivate::sha384); }
    if( method == URI_RSA_SHA512 ) { sha = PKCS11SignerPrivate::sha512; shasize = sizeof(PKCS11SignerPrivate::sha512); }
    vector<unsigned char> data = digest;
    if(sha)
        data.insert(data.begin(), sha, sha + shasize);

    CK_ULONG size = 0;
    if(d->f->C_Sign(session, &data[0], CK_ULONG(data.size()), 0, &size) != CKR_OK)
        THROW("Failed to sign digest");

    signature.resize(size);
    rv = d->f->C_Sign(session, &data[0], CK_ULONG(data.size()), &signature[0], CK_ULONG_PTR(&size));
    if(rv != CKR_OK)
        THROW("Failed to sign digest");
}
