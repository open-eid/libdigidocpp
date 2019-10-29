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

#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocGen.h>
#include <libdigidoc/DigiDocSAXParser.h>

#include "DDoc.h"
#include "Exception.h"

#ifdef _WIN32
#include <Windows.h>
#define LIBDIGIDOCPP_NORETURN __declspec(noreturn)
#else
#include <dlfcn.h>
#define LIBDIGIDOCPP_NORETURN __attribute__((__noreturn__))
#endif

namespace digidoc
{
class DDocLibrary
{
private:
	DDocLibrary();
	~DDocLibrary();

	static DDocLibrary *m_instance;
    unsigned int ref = 0;

#ifdef LINKED_LIBDIGIDOC
    #define symd(x) using sym_##x = decltype(&x); \
        sym_##x f_##x = x
#elif defined(_WIN32)
    HINSTANCE h = LoadLibrary(TEXT("digidoc.dll"));
    #define symd(x) using sym_##x = decltype(&x); \
        sym_##x f_##x = sym_##x(h ? GetProcAddress(h, #x) : nullptr)
#elif defined(__APPLE__)
    void *h = dlopen("libdigidoc.dylib", RTLD_LAZY);
    #define symd(x) using sym_##x = decltype(&x); \
        sym_##x f_##x = sym_##x(h ? dlsym(h, #x) : nullptr)
#else
    void *h = dlopen("libdigidoc.so.2", RTLD_LAZY);
    #define symd(x) using sym_##x = decltype(&x); \
        sym_##x f_##x = sym_##x(h ? dlsym(h, #x) : nullptr)
#endif

public:
	static void destroy();
	static DDocLibrary *instance();

    symd(calculateDataFileSizeAndDigest);
    symd(cleanupConfigStore);
    symd(clearErrors);
    symd(convertStringToTimestamp);
    symd(createDataFileInMemory);
    symd(createOrReplacePrivateConfigItem);
    symd(createSignedDoc);
    symd(DataFile_delete);
    symd(DataFile_new);
#ifdef USE_SIGFROMMEMORY
    symd(ddocAddSignatureFromMemory);
#endif
    symd(ddocGetDataFileCachedData);
    symd(ddocGetDataFileFilename);
    symd(ddocMemBuf_free);
    symd(ddocPrepareSignature);
    symd(ddocSAXGetDataFile);
    symd(ddocSaxReadSignedDocFromFile);
    symd(ddocSaxReadSignedDocFromMemory);
    symd(ddocSigInfo_GetOCSPRespondersCert);
    symd(ddocSigInfo_GetSignatureValue_Value);
    symd(ddocSigInfo_GetSignersCert);
    symd(ddocSigInfo_SetSignatureValue);
    symd(finalizeDigiDocLib);
    symd(freeLibMem);
    symd(getCountOfDataFiles);
    symd(getCountOfSignatures);
    symd(getDataFile);
    symd(getErrorClass);
    symd(getErrorInfo);
    symd(getErrorString);
    symd(getSignature);
    symd(hasUnreadErrors);
    symd(initDigiDocLib);
    symd(initConfigStore);
    symd(notarizeSignature);
    symd(ddocSaxExtractDataFile);
    symd(setGUIVersion);
    symd(SignatureInfo_delete);
    symd(SignedDoc_free);
    symd(SignedDoc_new);
    symd(verifySignatureAndNotary);
};

class SignatureDDOC;

class DDocPrivate
{
public:
	DDocLibrary *lib = nullptr;
	SignedDoc *doc = nullptr;
	std::string filename;

	void loadSignatures();
	std::vector<Signature*> signatures;
	std::vector<DataFile*> documents;

	static std::vector<unsigned char> toVector( DigiDocMemBuf *m )
	{ return std::vector<unsigned char>((unsigned char*)m->pMem, (unsigned char*)m->pMem + m->nLen); }

	void throwCodeError(int err, const std::string &msg, int line) const;
	void throwDocOpenError( int line ) const;
	LIBDIGIDOCPP_NORETURN void throwError(const std::string &msg, int line, int err = -1,
        Exception::ExceptionCode e = Exception::General) const;
	void throwSignError( SignatureInfo *sig, int err, const std::string &msg, int line ) const;
};

}
