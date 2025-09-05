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

#include "Conf.h"
#include "crypto/Digest.h"
#include "crypto/X509Cert.h"
#include "crypto/X509Crypto.h"
#include "util/algorithm.h"
#include "util/log.h"
#include "util/File.h"

#include <openssl/evp.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

using namespace digidoc;
using namespace std;

class PKCS11Signer::Private
{
public:
#ifdef _WIN32
    bool load(const string &driver)
    {
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
        return (h = LoadLibraryW(util::File::encodeName(driver).c_str())) != 0;
#else
        return false;
#endif
    }

    void* resolve(const char *symbol) const
    { return h ? (void*)GetProcAddress(h, symbol) : nullptr; }

    void unload()
    { if(h) FreeLibrary(h); h = {}; }

    HINSTANCE h {};
#else
    bool load(const string &driver)
    { return (h = dlopen(driver.c_str(), RTLD_LAZY)); }

    void* resolve(const char *symbol) const
    { return h ? dlsym(h, symbol) : nullptr; }

    void unload()
    { if(h) dlclose(h); h = {}; }

    void *h {};
#endif

    CK_FUNCTION_LIST *f {};
    struct SignSlot
    {
        X509Cert certificate;
        CK_SLOT_ID slot{};
        vector<CK_BYTE> id;
    } sign;
    string pin;
};

template<typename> struct function_traits;
template<typename R, typename C, typename... Ps>
struct function_traits<R (*C::*)(Ps...)>
{
    using return_type = R;
    using arg_types = std::tuple<Ps...>;
    static constexpr std::size_t nargs = sizeof...(Ps);
};

template<auto Getter, typename... Args>
static auto PKCS11List(CK_FUNCTION_LIST *f, Args&&... args)
{
    using Traits = function_traits<decltype(Getter)>;
    using T = std::remove_pointer_t<std::tuple_element_t<Traits::nargs - 2, typename Traits::arg_types>>;
    std::vector<T> result;
    CK_ULONG count = 0;
    if((f->*Getter)(std::forward<Args>(args)..., static_cast<T*>(nullptr), &count) != CKR_OK || count == 0)
        return result;
    result.resize(size_t(count));
    if((f->*Getter)(std::forward<Args>(args)..., result.data(), &count) != CKR_OK)
        result.clear();
    return result;
}

struct PKCS11Session
{
    PKCS11Session(CK_FUNCTION_LIST *_f, CK_SLOT_ID slot)
        : f(_f)
    {
        f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &handle);
    }

    DISABLE_COPY(PKCS11Session);

    ~PKCS11Session()
    {
        if(handle)
            f->C_CloseSession(handle);
    }

    vector<CK_BYTE> attribute(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type) const;
    vector<CK_OBJECT_HANDLE> findObject(CK_OBJECT_CLASS cls, const vector<CK_BYTE> &id = {}) const;
    operator bool() const { return handle != CK_INVALID_HANDLE; }

    CK_FUNCTION_LIST *f;
    CK_SESSION_HANDLE handle = CK_INVALID_HANDLE;
};

vector<CK_BYTE> PKCS11Session::attribute(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type) const
{
    vector<CK_BYTE> value;
    CK_ATTRIBUTE attr { type, nullptr, 0 };
    if(f->C_GetAttributeValue(handle, obj, &attr, 1) != CKR_OK)
        return value;
    value.resize(size_t(attr.ulValueLen));
    attr.pValue = value.data();
    if(f->C_GetAttributeValue(handle, obj, &attr, 1) != CKR_OK)
        value.clear();
    return value;
}

vector<CK_OBJECT_HANDLE> PKCS11Session::findObject(CK_OBJECT_CLASS cls, const vector<CK_BYTE> &id) const
{
    CK_BBOOL _true = CK_TRUE;
    vector<CK_ATTRIBUTE> attrs {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_TOKEN, &_true, sizeof(_true) }
    };
    if(!id.empty())
        attrs.push_back({ CKA_ID, CK_VOID_PTR(id.data()), CK_ULONG(id.size()) });
    if(f->C_FindObjectsInit(handle, attrs.data(), CK_ULONG(attrs.size())) != CKR_OK)
        return {};

    CK_ULONG count = 32;
    vector<CK_OBJECT_HANDLE> result(count);
    CK_RV err = f->C_FindObjects(handle, result.data(), CK_ULONG(result.size()), &count);
    result.resize(err == CKR_OK ? count : 0);
    f->C_FindObjectsFinal(handle);
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
    : d(make_unique<Private>())
{
    string load = driver;
    if(driver.empty())
        load = Conf::instance()->PKCS11Driver();

    DEBUG("PKCS11Signer(driver = '%s')", load.c_str());
    if(load.empty())
        THROW("Failed to load driver for PKCS #11 engine: %s.", load.c_str());

    if(!d->load(load))
        THROW("Failed to load driver for PKCS #11 engine: %s.", load.c_str());

    if(auto l = CK_C_GetFunctionList(d->resolve("C_GetFunctionList"));
        !l ||
        l(&d->f) != CKR_OK ||
        d->f->C_Initialize(nullptr) != CKR_OK)
        THROW("Failed to load driver for PKCS #11 engine: %s.", load.c_str());
}

/**
 * Unload PKCS#11 module and releases acquired memory.
 */
PKCS11Signer::~PKCS11Signer()
{
    if(!d->f)
        return;
    d->f->C_Finalize(nullptr);
    d->f = nullptr;
    d->unload();
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
    if(d->sign.certificate)
        return d->sign.certificate;

    // Load all slots.
    auto slots = PKCS11List<&CK_FUNCTION_LIST::C_GetSlotList>(d->f, CK_TRUE);
    if(slots.empty())
        THROW("Could not find any ID-Cards in any readers");

    // Iterate over all found slots, if the slot has a token, check if the token has any certificates.
    vector<X509Cert> certificates;
    vector<Private::SignSlot> certSlotMapping;
    for(const CK_SLOT_ID &slot: slots)
    {
        for(PKCS11Session session(d->f, slot);
            CK_OBJECT_HANDLE obj: session.findObject(CKO_CERTIFICATE))
        {
            X509Cert x509(session.attribute(obj, CKA_VALUE));
            vector<X509Cert::KeyUsage> usage = x509.keyUsage();
            if(!x509.isValid() || !contains(usage, X509Cert::NonRepudiation) || x509.isCA())
                continue;
            vector<CK_BYTE> id = session.attribute(obj, CKA_ID);
            if(session.findObject(CKO_PUBLIC_KEY, id).empty())
                continue;
            certSlotMapping.push_back({x509, slot, std::move(id)});
            certificates.push_back(std::move(x509));
        }
    }

    if(certificates.empty())
        THROW("No certificates found.");

    // Let the application select the signing certificate.
    X509Cert selectedCert = selectSigningCertificate(certificates);
    if(!selectedCert)
        THROW("No certificate selected.");

    // Find the corresponding slot and PKCS11 certificate struct.
    for(Private::SignSlot &slot: certSlotMapping)
    {
        if(slot.certificate == selectedCert)
            d->sign = std::move(slot);
    }

    if(!d->sign.certificate)
        THROW("Could not find slot for selected certificate.");

    return d->sign.certificate;
}

string PKCS11Signer::method() const
{
    string parent = Signer::method();
    if(!d->sign.certificate || !X509Crypto(d->sign.certificate).isRSAKey() ||
        parent != CONF(signatureDigestUri))
        return parent;
    if(auto mech = PKCS11List<&CK_FUNCTION_LIST::C_GetMechanismList>(d->f, d->sign.slot);
        contains(mech, CKM_RSA_PKCS_PSS))
        return Digest::toRsaPssUri(std::move(parent));
    return parent;
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
string PKCS11Signer::pin(const X509Cert & /*certificate*/) const
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
 * @param method digest method to be used
 * @param digest digest to sign
 * @return signature signed result
 * @throws Exception throws exception if the signing operation failed.
 */
vector<unsigned char> PKCS11Signer::sign(const string &method, const vector<unsigned char> &digest) const
{
    DEBUG("sign(mehthod = %s, digest = length=%zu)", method.c_str(), digest.size());

    if(!d->sign.certificate)
        THROW("Signing certificate is not selected.");

    CK_TOKEN_INFO token{};
    if(d->f->C_GetTokenInfo(d->sign.slot, &token) != CKR_OK)
        THROW("Failed to get token info.");

    if(token.flags & CKF_USER_PIN_LOCKED)
    {
        Exception e(EXCEPTION_PARAMS("PIN Locked"));
        e.setCode(Exception::PINLocked);
        throw e;
    }

    PKCS11Session session(d->f, d->sign.slot);
    if(!session)
        THROW("Failed to open session.");

    CK_RV rv = CKR_OK;
    if(token.flags & CKF_LOGIN_REQUIRED)
    {
        if(token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
            rv = d->f->C_Login(session.handle, CKU_USER, nullptr, 0);
        else
        {
            string _pin = pin(d->sign.certificate);
            rv = d->f->C_Login(session.handle, CKU_USER, CK_BYTE_PTR(_pin.c_str()), CK_ULONG(_pin.size()));
        }
        switch(rv)
        {
        case CKR_OK: break;
        case CKR_USER_ALREADY_LOGGED_IN: break;
        case CKR_CANCEL:
        case CKR_FUNCTION_CANCELED:
        {
            Exception e(EXCEPTION_PARAMS("PIN acquisition canceled."));
            e.setCode(Exception::PINCanceled);
            throw e;
        }
        case CKR_PIN_INCORRECT:
        {
            Exception e(EXCEPTION_PARAMS("PIN Incorrect"));
            e.setCode(Exception::PINIncorrect);
            throw e;
        }
        case CKR_PIN_LOCKED:
        {
            Exception e(EXCEPTION_PARAMS("PIN Locked"));
            e.setCode(Exception::PINLocked);
            throw e;
        }
        default:
            Exception e(EXCEPTION_PARAMS("Failed to login to token '%s': %lu", token.label, rv));
            e.setCode(Exception::PINFailed);
            throw e;
        }
    }

    vector<CK_OBJECT_HANDLE> key = session.findObject(CKO_PRIVATE_KEY, d->sign.id);
    if(key.size() != 1)
        THROW("Could not get key that matches selected certificate.");

    // Sign the digest.
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ATTRIBUTE attribute { CKA_KEY_TYPE, &keyType, sizeof(keyType) };
    d->f->C_GetAttributeValue(session.handle, key.front(), &attribute, 1);

    CK_RSA_PKCS_PSS_PARAMS pssParams { CKM_SHA_1, CKG_MGF1_SHA1, 0 };
    CK_MECHANISM mech { keyType == CKK_ECDSA ? CKM_ECDSA : CKM_RSA_PKCS, nullptr, 0 };
    vector<CK_BYTE> data = digest;
    if(Digest::isRsaPssUri(method)) {
        int nid = Digest::toMethod(method);
        switch(nid)
        {
        case NID_sha224:
            pssParams = { CKM_SHA224, CKG_MGF1_SHA224, 0 };
            break;
        case NID_sha256:
            pssParams = { CKM_SHA256, CKG_MGF1_SHA256, 0 };
            break;
        case NID_sha384:
            pssParams = { CKM_SHA384, CKG_MGF1_SHA384, 0 };
            break;
        case NID_sha512:
            pssParams = { CKM_SHA512, CKG_MGF1_SHA512, 0 };
            break;
        default: break;
        }
        pssParams.sLen = CK_ULONG(EVP_MD_size(EVP_get_digestbynid(nid)));
        mech = { CKM_RSA_PKCS_PSS, &pssParams, sizeof(CK_RSA_PKCS_PSS_PARAMS) };
    }
    else if(keyType == CKK_RSA)
        data = Digest::addDigestInfo(std::move(data), method);
    if(d->f->C_SignInit(session.handle, &mech, key.front()) != CKR_OK)
        THROW("Failed to sign digest");

    auto signature = PKCS11List<&CK_FUNCTION_LIST::C_Sign>(d->f, session.handle, data.data(), CK_ULONG(data.size()));
    d->f->C_Logout(session.handle);
    if(signature.empty())
        THROW("Failed to sign digest");
    return signature;
}
