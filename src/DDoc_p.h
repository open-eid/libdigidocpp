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

#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocGen.h>

#include "DDoc.h"
#include "DataFile.h"
#include "Signature.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif


namespace digidoc
{
typedef int (*sym_calculateDataFileSizeAndDigest)( SignedDoc*, const char*, const char*, int );
typedef void (*sym_cleanupConfigStore)( ConfigurationStore* );
typedef void (*sym_clearErrors)();
typedef int (*sym_convertStringToTimestamp)( const SignedDoc*, const char*, Timestamp* );
typedef int (*sym_createDataFileInMemory)(::DataFile**, SignedDoc*, const char*,
	const char*, const char*, const char*, const char*, long);
typedef int (*sym_createOrReplacePrivateConfigItem)(ConfigurationStore*, const char*, const char* );
typedef int (*sym_createSignedDoc)( SignedDoc*, const char*, const char* );
typedef int (*sym_DataFile_delete)( SignedDoc*, const char* );
typedef int (*sym_DataFile_new)( ::DataFile**, SignedDoc*, const char*, const char*,
	const char*, const char*, long, const byte*, int, const char*, const char* );
typedef int (*sym_ddocAddSignatureFromMemory)(SignedDoc*, const char*, const void*, int);
typedef int (*sym_ddocGetDataFileCachedData)(SignedDoc*, const char*, void**, long*);
typedef int (*sym_ddocGetDataFileFilename)(SignedDoc*, const char*, void**, int*);
typedef int (*sym_ddocMemBuf_free)(DigiDocMemBuf*);
typedef int (*sym_ddocPrepareSignature)( SignedDoc*, SignatureInfo**, const char*, const char*,
	const char*, const char*, const char*, X509*, const char* );
typedef int (*sym_ddocSAXGetDataFile)(SignedDoc*, const char*, const char*, DigiDocMemBuf*, int);
typedef int (*sym_ddocSaxReadSignedDocFromFile)( SignedDoc**, const char*, int, long );
typedef int (*sym_ddocSaxReadSignedDocFromMemory)(SignedDoc**, const void*, int, long);
typedef X509* (*sym_ddocSigInfo_GetOCSPRespondersCert)( const SignatureInfo * );
typedef DigiDocMemBuf* (*sym_ddocSigInfo_GetSignatureValue_Value)( SignatureInfo* );
typedef X509* (*sym_ddocSigInfo_GetSignersCert)( const SignatureInfo* );
typedef int (*sym_ddocSigInfo_SetSignatureValue)( SignatureInfo*, const char*, long );
typedef void (*sym_finalizeDigiDocLib)();
typedef void (*sym_freeLibMem)(void*);
typedef int (*sym_getCountOfDataFiles)( const SignedDoc* );
typedef int (*sym_getCountOfSignatures)( const SignedDoc* );
typedef ::DataFile* (*sym_getDataFile)( const SignedDoc*, int );
typedef ErrorClass (*sym_getErrorClass)( int );
typedef ErrorInfo* (*sym_getErrorInfo)();
typedef char* (*sym_getErrorString)( int );
typedef SignatureInfo* (*sym_getSignature)( const SignedDoc*, int );
typedef int (*sym_hasUnreadErrors)();
typedef void (*sym_initDigiDocLib)();
typedef int (*sym_initConfigStore)( const char* );
typedef int (*sym_notarizeSignature)( SignedDoc*, SignatureInfo* );
typedef int (*sym_ddocSaxExtractDataFile)( SignedDoc*, const char*,
	const char*, const char*, const char* );
typedef void (*sym_setGUIVersion)( const char* );
typedef int (*sym_SignatureInfo_delete)( SignedDoc*, const char* );
typedef void (*sym_SignedDoc_free)( SignedDoc* );
typedef int (*sym_SignedDoc_new)( SignedDoc**, const char*, const char* );
typedef int (*sym_verifySignatureAndNotary)( SignedDoc*, SignatureInfo*, const char* );

class DDocLibrary
{
private:
	DDocLibrary();
	~DDocLibrary();

	static DDocLibrary *m_instance;
	unsigned int ref;

#ifndef LINKED_LIBDIGIDOC
#ifdef _WIN32
	HINSTANCE h;
#else
	void *h;
#endif
#endif

public:
	static void destroy();
	static DDocLibrary *instance();

#define symd(x) sym_##x f_##x
    symd(calculateDataFileSizeAndDigest);
    symd(cleanupConfigStore);
    symd(clearErrors);
    symd(convertStringToTimestamp);
    symd(createDataFileInMemory);
    symd(createOrReplacePrivateConfigItem);
    symd(createSignedDoc);
    symd(DataFile_delete);
    symd(DataFile_new);
    symd(ddocAddSignatureFromMemory);
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
	DDocLibrary *lib;
	SignedDoc *doc;
	std::string filename;

	void loadSignatures();
	SignatureList signatures;
	DataFileList documents;

	static std::vector<unsigned char> toVector( DigiDocMemBuf *m )
	{ return std::vector<unsigned char>((unsigned char*)m->pMem, (unsigned char*)m->pMem + m->nLen); }

	void throwCodeError(int err, const std::string &msg, int line) const;
	void throwDocOpenError( int line ) const;
	void throwError(const std::string &msg, int line, int err = -1,
		const Exception::ExceptionCode &e = Exception::General) const;
	void throwSignError( SignatureInfo *sig, int err, const std::string &msg, int line ) const;
};

}
