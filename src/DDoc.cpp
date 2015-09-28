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

#include "DDoc_p.h"

#include "Conf.h"
#include "Container.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/X509Cert.h"
#include "crypto/OCSP.h"
#include "crypto/Signer.h"
#include "util/DateTime.h"
#include "util/File.h"

#include <libdigidoc/DigiDocSAXParser.h>
#include <libdigidoc/DigiDocObj.h>

#include <fstream>

//#define DDOC_MEMORY
//#define DDOC_MEMORY_BUF 1024*1024*1024
#define DDOC_MEMORY_BUF 0
//#define USE_SIGFROMMEMORY

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

DDocLibrary* DDocLibrary::m_instance = nullptr;

DDocLibrary::DDocLibrary()
    : ref(0)
#ifndef LINKED_LIBDIGIDOC
#if defined(_WIN32)
    , h(LoadLibrary(TEXT("digidoc.dll")))
    #define symr(x) f_##x(sym_##x(h ? GetProcAddress(h, #x) : nullptr))
#elif defined(__APPLE__)
    , h(dlopen("libdigidoc.dylib", RTLD_LAZY))
    #define symr(x) f_##x(sym_##x(h ? dlsym(h, #x) : nullptr))
#else
    , h(dlopen("libdigidoc.so.2", RTLD_LAZY))
    #define symr(x) f_##x(sym_##x(h ? dlsym(h, #x) : nullptr))
#endif
#else
    #define symr(x) f_##x(x)
#endif
    , symr(calculateDataFileSizeAndDigest)
    , symr(cleanupConfigStore)
    , symr(clearErrors)
    , symr(convertStringToTimestamp)
    , symr(createDataFileInMemory)
    , symr(createOrReplacePrivateConfigItem)
    , symr(createSignedDoc)
    , symr(DataFile_delete)
    , symr(DataFile_new)
#ifdef USE_SIGFROMMEMORY
    , symr(ddocAddSignatureFromMemory)
#endif
    , symr(ddocGetDataFileCachedData)
    , symr(ddocGetDataFileFilename)
    , symr(ddocMemBuf_free)
    , symr(ddocPrepareSignature)
    , symr(ddocSAXGetDataFile)
    , symr(ddocSaxReadSignedDocFromFile)
    , symr(ddocSaxReadSignedDocFromMemory)
    , symr(ddocSigInfo_GetOCSPRespondersCert)
    , symr(ddocSigInfo_GetSignatureValue_Value)
    , symr(ddocSigInfo_GetSignersCert)
    , symr(ddocSigInfo_SetSignatureValue)
    , symr(finalizeDigiDocLib)
    , symr(freeLibMem)
    , symr(getCountOfDataFiles)
    , symr(getCountOfSignatures)
    , symr(getDataFile)
    , symr(getErrorClass)
    , symr(getErrorInfo)
    , symr(getErrorString)
    , symr(getSignature)
    , symr(hasUnreadErrors)
    , symr(initDigiDocLib)
    , symr(initConfigStore)
    , symr(notarizeSignature)
    , symr(ddocSaxExtractDataFile)
    , symr(setGUIVersion)
    , symr(SignatureInfo_delete)
    , symr(SignedDoc_free)
    , symr(SignedDoc_new)
    , symr(verifySignatureAndNotary)
{
    if(!f_initDigiDocLib)
        return;

#ifdef WIN32
    f_initDigiDocLib();
#endif
    string path = Conf::instance()->libdigidocConf();
    f_initConfigStore(!path.empty() ? path.c_str() : 0);
    f_setGUIVersion( appInfo().c_str() );
}

DDocLibrary::~DDocLibrary()
{
    if(f_cleanupConfigStore)
	{
		f_cleanupConfigStore( 0 );
		//f_finalizeDigiDocLib(); // dont finalize it unloads openssl also
	}
#ifndef LINKED_LIBDIGIDOC
#ifdef _WIN32
    if(h) FreeLibrary(h);
#else
    if(h) dlclose(h);
#endif
#endif
}

void DDocLibrary::destroy()
{
	if( !m_instance )
		return;
	--m_instance->ref;
	if( m_instance->ref > 0 )
		return;
	delete m_instance;
    m_instance = nullptr;
}

DDocLibrary* DDocLibrary::instance()
{
	if( !m_instance )
		m_instance = new DDocLibrary();
	++m_instance->ref;
	return m_instance;
}



void DDocPrivate::loadSignatures()
{
    for_each(signatures.begin(), signatures.end(), [](Signature *s){ delete s; });
    signatures.clear();
    int count = lib->f_getCountOfSignatures( doc );
    for(int i = 0; i < count; ++i)
        signatures.push_back(new SignatureDDOC(lib->f_getSignature(doc, i), this));
}

void DDocPrivate::throwCodeError(int err, const string &msg, int line) const
{
	switch( err )
	{
	case ERR_OK: break;
	case ERR_PKCS_LOGIN:
        throwError("PIN Incorrect", line, err, Exception::PINIncorrect);
	case ERR_OCSP_CERT_REVOKED:
        throwError("Certificate status: revoked", line, err, Exception::CertificateRevoked);
	case ERR_OCSP_CERT_UNKNOWN:
        throwError("Certificate status: unknown", line, err, Exception::CertificateUnknown);
	case ERR_OCSP_RESP_NOT_TRUSTED:
        throwError("Failed to find ocsp responder.", line, err, Exception::OCSPResponderMissing);
	case ERR_OCSP_CERT_NOTFOUND:
        throwError("OCSP certificate loading failed", line, err, Exception::OCSPCertMissing);
	case ERR_OCSP_UNAUTHORIZED:
        throwError("Unauthorized OCSP request", line, err, Exception::OCSPRequestUnauthorized);
	case ERR_CERT_READ:
	case ERR_UNKNOWN_CA:
	case ERR_SIGNERS_CERT_NOT_TRUSTED:
        throwError(msg, line, err, Exception::CertificateUnknown);
    case ERR_DF_WRONG_DIG:
        if(Exception::hasWarningIgnore(Exception::DataFileNameSpaceWarning))
            break;
        throwError(msg, line, err, Exception::DataFileNameSpaceWarning);
    case ERR_ISSUER_XMLNS:
        if(Exception::hasWarningIgnore(Exception::IssuerNameSpaceWarning))
            break;
        throwError(msg, line, err, Exception::IssuerNameSpaceWarning);
    default:
        throwError(msg, line, err);
	}
}

void DDocPrivate::throwDocOpenError( int line ) const
{
    if(!lib->f_initDigiDocLib)
        throwError("DDoc library not loaded", line);
	if( !doc )
        throwError("Document not open", line);
}

void DDocPrivate::throwError(const string &msg, int line, int err, const Exception::ExceptionCode &code) const
{
    Exception e(__FILE__, line, msg);
    e.setCode(code);
    if(err <= 0)
        throw e;

    if(lib->f_getErrorString)
    {
        static const char *errorClass[] = {"NO_ERRORS", "TECHNICAL", "USER", "LIBRARY"};
        while(lib->f_hasUnreadErrors())
        {
            ErrorInfo *i = lib->f_getErrorInfo();
            stringstream ddoc;
            ddoc << endl << "ERROR " << i->code
                << " (" << i->assertion << " " << errorClass[lib->f_getErrorClass(i->code)] << ") "
                << lib->f_getErrorString(i->code);
            Exception ddocexc(i->fileName, i->line, ddoc.str());
            switch(i->code)
            {
            case ERR_PKCS_LOGIN: ddocexc.setCode(Exception::PINIncorrect); break;
            case ERR_OCSP_CERT_REVOKED: ddocexc.setCode(Exception::CertificateRevoked); break;
            case ERR_OCSP_CERT_UNKNOWN: ddocexc.setCode(Exception::CertificateUnknown); break;
            case ERR_OCSP_RESP_NOT_TRUSTED: ddocexc.setCode(Exception::OCSPResponderMissing); break;
            case ERR_OCSP_CERT_NOTFOUND: ddocexc.setCode(Exception::OCSPCertMissing); break;
            case ERR_OCSP_UNAUTHORIZED: ddocexc.setCode(Exception::OCSPRequestUnauthorized); break;
            case ERR_CERT_READ:
            case ERR_UNKNOWN_CA:
            case ERR_SIGNERS_CERT_NOT_TRUSTED: ddocexc.setCode(Exception::CertificateUnknown); break;
            case ERR_DF_WRONG_DIG: ddocexc.setCode(Exception::DataFileNameSpaceWarning); break;
            case ERR_ISSUER_XMLNS: ddocexc.setCode(Exception::IssuerNameSpaceWarning); break;
            default: ddocexc.setCode(Exception::ExceptionCode(Exception::DDocError|i->code)); break;
            }
            e.addCause(ddocexc);
        }
        lib->f_clearErrors();
    }
    throw e;
}

void DDocPrivate::throwSignError( SignatureInfo *sig, int err, const string &msg, int line ) const
{
	if( err && sig )
		lib->f_SignatureInfo_delete( doc, sig->szId );
    throwCodeError(err, msg, line);
}



/**
 * DDoc profile signature media type.
 */
SignatureDDOC::SignatureDDOC(SignatureInfo_st *sig, DDocPrivate *priv)
    : d(priv)
    , s(sig)
{
    if(!s)
        throw Exception(__FILE__, __LINE__, "Null pointer in SignatureDDOC constructor");
}

/**
 * Destructs SignatureDDOC object
 */
SignatureDDOC::~SignatureDDOC() {}

string SignatureDDOC::id() const
{
    return s->szId ? s->szId : "";
}

/**
 * @return returns signature mimetype.
 */
string SignatureDDOC::profile() const
{
    ostringstream s;
    s << d->doc->szFormat << "/" << d->doc->szFormatVer;
	return s.str();
}

string SignatureDDOC::claimedSigningTime() const
{
    Timestamp ts = { 0, 0, 0, 0, 0, 0, 0 };
    d->lib->f_convertStringToTimestamp(d->doc, s->szTimeStamp, &ts);
    return date::xsd2string( xml_schema::DateTime( ts.year, ts.mon, ts.day, ts.hour, ts.min, ts.sec, ts.tz, 0 ) );
}

X509Cert SignatureDDOC::signingCertificate() const
{
    try { return X509Cert(d->lib->f_ddocSigInfo_GetSignersCert(s)); }
    catch( const Exception & ) {}
    return X509Cert();
}

string SignatureDDOC::signatureMethod() const
{
    return s->szDigestType ? s->szDigestType : URI_RSA_SHA1;
}

/**
 * The address where was the signature given.
 *
 * @return returns structure containing the address of signing place.
 */
string SignatureDDOC::city() const
{
    return s->sigProdPlace.szCity ? s->sigProdPlace.szCity : "";
}

string SignatureDDOC::stateOrProvince() const
{
    return s->sigProdPlace.szStateOrProvince ? s->sigProdPlace.szStateOrProvince : "";
}

string SignatureDDOC::postalCode() const
{
    return s->sigProdPlace.szPostalCode ? s->sigProdPlace.szPostalCode : "";
}

string SignatureDDOC::countryName() const
{
    return s->sigProdPlace.szCountryName ? s->sigProdPlace.szCountryName : "";
}

/**
 * The role that signer claims to hold while signing.
 *
 * @return returns the claimed role of the signer.
 */
vector<string> SignatureDDOC::signerRoles() const
{
    vector<string> roles;
    for(int i = 0; i < s->signerRole.nClaimedRoles; ++i)
        roles.push_back(s->signerRole.pClaimedRoles[i]);
    return roles;
}

/**
 * @return returns OCSP nonce value
 */
vector<unsigned char> SignatureDDOC::OCSPNonce() const
{
    NotaryInfo *n = s->pNotary;
    if(n && n->mbufOcspResponse.nLen)
        return OCSP(DDocPrivate::toVector(&n->mbufOcspResponse)).nonce();
    return vector<unsigned char>();
}

void SignatureDDOC::notarize()
{
    Conf *c = Conf::instance();
    if(!c->proxyHost().empty())
    {
        d->lib->f_createOrReplacePrivateConfigItem(0, "USE_PROXY", "true");
        d->lib->f_createOrReplacePrivateConfigItem(0, "DIGIDOC_PROXY_HOST", c->proxyHost().c_str());
        d->lib->f_createOrReplacePrivateConfigItem(0, "DIGIDOC_PROXY_PORT", c->proxyPort().c_str());
        d->lib->f_createOrReplacePrivateConfigItem(0, "DIGIDOC_PROXY_USER", c->proxyUser().c_str());
        d->lib->f_createOrReplacePrivateConfigItem(0, "DIGIDOC_PROXY_PASS", c->proxyPass().c_str());
    }
    else
        d->lib->f_createOrReplacePrivateConfigItem(0, "USE_PROXY", "false");

    if(!c->PKCS12Disable())
    {
        d->lib->f_createOrReplacePrivateConfigItem(0, "SIGN_OCSP", "true");
        d->lib->f_createOrReplacePrivateConfigItem(0, "DIGIDOC_PKCS_FILE", c->PKCS12Cert().c_str());
        d->lib->f_createOrReplacePrivateConfigItem(0, "DIGIDOC_PKCS_PASSWD", c->PKCS12Pass().c_str());
    }
    else
        d->lib->f_createOrReplacePrivateConfigItem(0, "SIGN_OCSP", "false");

    int err = d->lib->f_notarizeSignature(d->doc, s);
    d->throwSignError(s, err, "Failed to sign document", __LINE__);
}

/**
 * @return returns OCSP certificate
 */
X509Cert SignatureDDOC::OCSPCertificate() const
{
    try { return X509Cert(d->lib->f_ddocSigInfo_GetOCSPRespondersCert(s)); }
	catch( const Exception & ) {}
	return X509Cert();
}

/**
 * @return returns OCSP timestamp
 */
string SignatureDDOC::OCSPProducedAt() const
{
    NotaryInfo *n = s->pNotary;
	if( !n || !n->timeProduced )
		return "";
	Timestamp ts = { 0, 0, 0, 0, 0, 0, 0 };
    d->lib->f_convertStringToTimestamp(d->doc, n->timeProduced, &ts);
    return date::xsd2string( xml_schema::DateTime( ts.year, ts.mon, ts.day, ts.hour, ts.min, ts.sec, ts.tz, 0 ) );
}

void SignatureDDOC::setSignatureValue(const vector<unsigned char> &signature)
{
    int err = d->lib->f_ddocSigInfo_SetSignatureValue(s, (const char*)&signature[0], long(signature.size()));
    d->throwSignError(s, err, "Failed to sign document", __LINE__);
}

string SignatureDDOC::trustedSigningTime() const
{
    string time = OCSPProducedAt();
    return time.empty() ? claimedSigningTime() : time;
}

/**
 * Do TM offline validations.
 * <ul>
 *   <li>Validate BES offline</li>
 *   <li>Check OCSP response (RevocationValues) was signed by trusted OCSP server</li>
 *   <li>Check that nonce field in OCSP response is same as CompleteRevocationRefs-&gt;DigestValue</li>
 *   <li>Recalculate hash of signature and compare with nonce</li>
 * </ul>
 * @throws SignatureException if signature is not valid
 */
void SignatureDDOC::validate() const
{
    if(int err = d->lib->f_verifySignatureAndNotary(d->doc, s, d->filename.c_str()))
        d->throwError("Signature validation", __LINE__, err);
}



/**
 * Initialize DDOC container.
 */
DDoc::DDoc()
:	d( new DDocPrivate )
{
    d->doc = nullptr;
    d->lib = DDocLibrary::instance();
    if(!d->lib->f_initDigiDocLib)
		return;
	/*int err =*/ d->lib->f_SignedDoc_new( &d->doc, "DIGIDOC-XML", "1.3" );
	//throwError( err, "Failed to create new document", __LINE__ );
}

/**
 * Opens DDOC container from a file
 */
DDoc::DDoc(const string &path)
 :	d( new DDocPrivate )
{
    d->lib = DDocLibrary::instance();
    load(path);
}

void DDoc::load(const std::string &path)
{
    if(!d->lib->f_initDigiDocLib)
        d->throwError("DDoc library not loaded", __LINE__);

    if(d->doc)
        d->lib->f_SignedDoc_free(d->doc);
    d->documents.clear();
    d->doc = nullptr;
    d->filename = path;
    int err = d->lib->f_ddocSaxReadSignedDocFromFile(&d->doc, d->filename.c_str(), 0, DDOC_MEMORY_BUF);
    switch(err)
    {
    case ERR_OK:
    case ERR_OCSP_CERT_REVOKED:
    case ERR_OCSP_CERT_UNKNOWN:
    case ERR_ISSUER_XMLNS:
        if( d->doc )
            break;
        err = ERR_DIGIDOC_PARSE;
    default:
        d->lib->f_SignedDoc_free(d->doc);
        d->doc = nullptr;
        d->throwCodeError(err, "Failed to open ddoc file", __LINE__);
        return;
    }

    int count = d->lib->f_getCountOfDataFiles(d->doc);
    for(int i = 0; i < count; ++i)
    {
        ::DataFile *data = d->lib->f_getDataFile(d->doc, i);
#ifndef DDOC_MEMORY
        string path = File::tempFileName();
        int err = d->lib->f_ddocSaxExtractDataFile(d->doc, d->filename.c_str(),
            path.c_str(), data->szId, CHARSET_UTF_8);
        istream *is = new ifstream(File::encodeName(path).c_str(), ifstream::binary);
#else
        long size = 0;
        void *filedata = nullptr;
        int err = d->lib->f_ddocGetDataFileCachedData(d->doc, data->szId, &filedata, &size);
        istream *is = nullptr;
        if(err == 0 && size > 0)
            is = new stringstream(string(reinterpret_cast<const char*>(filedata), size));
        else
            is = new stringstream;
#endif
        if(err)
        {
            if(d->doc)
                d->lib->f_SignedDoc_free(d->doc);
            d->doc = nullptr;
            d->throwCodeError(err, "Failed to exctract files", __LINE__);
        }
        char *filename = nullptr;
        int size = 0;
        d->lib->f_ddocGetDataFileFilename(d->doc, data->szId, (void**)&filename, &size);
        d->documents.push_back(
            DataFile(is, filename, data->szMimeType, data->szId, DDocPrivate::toVector(&data->mbufDigest)));
        if(filename)
            d->lib->f_freeLibMem(filename);
    }

    d->loadSignatures();
}

/**
 * Releases resources.
 */
DDoc::~DDoc()
{
    for_each(d->signatures.begin(), d->signatures.end(), [](Signature *s){ delete s; });
    if(d->lib->f_SignedDoc_free)
        d->lib->f_SignedDoc_free(d->doc);
    d->lib->destroy();
    delete d;
}

/**
 * Adds document to the container. Documents can be removed from container only
 * after all signatures are removed.
 *
 * @param document a document, which is added to the container.
 * @throws ContainerException exception is thrown if the document path is incorrect or document
 *         with same file name already exists. Also no document can be added if the
 *         container already has one or more signatures.
 */
void DDoc::addDataFile(const string &path, const string &mediaType)
{
	d->throwDocOpenError( __LINE__ );
    if(!d->signatures.empty())
        THROW("Can not add document to container which has signatures, remove all signatures before adding new document.");

    ifstream *is = new ifstream(File::encodeName(path).c_str(), ifstream::binary);
    ::DataFile *data = nullptr;
#ifndef DDOC_MEMORY
    int err = d->lib->f_DataFile_new( &data, d->doc, 0, path.c_str(),
        CONTENT_EMBEDDED_BASE64, mediaType.c_str(), 0, 0, 0, 0, CHARSET_UTF_8 );
    d->throwCodeError(err, "Failed to add file '" + path + "'" , __LINE__);
    err = d->lib->f_calculateDataFileSizeAndDigest(
        d->doc, data->szId, path.c_str(), DIGEST_SHA1 );
    d->throwCodeError(err, "Failed calculate file digest and size", __LINE__);
#else
    stringstream buf;
    buf << is->rdbuf();
    d->lib->f_createDataFileInMemory(&data, d->doc, 0, path.c_str(),
        CONTENT_EMBEDDED_BASE64, mediaType.c_str(), buf.str().c_str(), buf.str().size());
#endif
    d->documents.push_back(
        DataFile(is, File::fileName(path), mediaType, data->szId, DDocPrivate::toVector(&data->mbufDigest)));
}

void DDoc::addDataFile(istream *, const string &, const string &)
{
    THROW("Stream API is not supported with DDoc.");
}

/**
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws ContainerException throws exception if there are no documents in container.
 */
void DDoc::addAdESSignature(istream &sigdata)
{
#if USE_SIGFROMMEMORY
    stringstream ofs;
    ofs << sigdata.rdbuf();
    ofs.flush();
    int err = d->lib->f_ddocAddSignatureFromMemory(d->doc, d->filename.c_str(), ofs.str().c_str(), ofs.str().size());
    d->throwCodeError(err, "Failed to sign document", __LINE__);
    d->loadSignatures();
#else
    string fileName = File::tempFileName();
    ofstream ofs(File::encodeName(fileName).c_str());
    ofs << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n";
    ofs << "<SignedDoc format=\"DIGIDOC-XML\" version=\"1.3\" xmlns=\"http://www.sk.ee/DigiDoc/v1.3.0#\">\n";
    ofs << sigdata.rdbuf();
    ofs << "</SignedDoc>";
    ofs.flush();
    ofs.close();

    SignedDoc *sigDoc = 0;
    int err = d->lib->f_ddocSaxReadSignedDocFromFile( &sigDoc, fileName.c_str(), 0, 0 );
    d->throwCodeError(err, "Failed to sign document", __LINE__);

    SignatureInfo **signatures = (SignatureInfo**)realloc( d->doc->pSignatures,
        (d->doc->nSignatures + sigDoc->nSignatures) * sizeof(SignatureInfo*));
    if( !signatures )
    {
        d->lib->f_SignedDoc_free( sigDoc );
        d->throwError("Failed to sign document", __LINE__);
        return;
    }

    d->doc->pSignatures = signatures;
    for( int i = 0; i < sigDoc->nSignatures; ++i )
    {
        d->doc->pSignatures[d->doc->nSignatures + i] = sigDoc->pSignatures[i]; // take ownership
        sigDoc->pSignatures[i] = 0;
        // from ddocReadNewSignaturesFromDdoc
        ((char*)d->doc->pSignatures[d->doc->nSignatures + i]->pDocs[0]->szDigest)[0] = 0x0A;
    }
    d->doc->nSignatures += sigDoc->nSignatures;
    sigDoc->nSignatures = 0;

    d->lib->f_SignedDoc_free( sigDoc );
#endif
    //Force reload
    save(fileName);
    load(fileName);
}

Container* DDoc::createInternal(const string &path)
{
    size_t pos = path.find_last_of(".");
    if(pos == string::npos)
        return nullptr;
    string ext = path.substr(pos + 1);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if(ext != "ddoc")
        return nullptr;
    DDoc *doc = new DDoc();
    doc->d->filename = path;
    return doc;
}

/**
 * @return returns container type.
 */
string DDoc::mediaType() const
{
    ostringstream s;
    if(d->doc->szFormat && d->doc->szFormatVer)
        s << d->doc->szFormat << "/" << d->doc->szFormatVer;
    return s.str();
}

/**
 * Returns document referenced by document id.
 *
 * @param id document id.
 * @return returns document referenced by document id.
 * @throws ContainerException throws exception if the document id is incorrect.
 */
DataFileList DDoc::dataFiles() const
{
    return d->documents;
}

Container* DDoc::openInternal(const string &path)
{
    size_t pos = path.find_last_of(".");
    if(pos == string::npos)
        return nullptr;
    string ext = path.substr(pos + 1);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if(ext != "ddoc")
        return nullptr;
    DDoc *doc = new DDoc(path);
    return doc;
}

/**
 * Returns signature referenced by signature id.
 *
 * @param id signature id.
 * @return returns signature referenced by signature id.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
SignatureList DDoc::signatures() const
{
    return d->signatures;
}

/**
 * Removes document from container by document id. Documents can be
 * removed from container only after all signatures are removed.
 *
 * @param id document's id, which will be removed.
 * @throws ContainerException throws exception if the document id is incorrect or there are
 *         one or more signatures.
 */
void DDoc::removeDataFile(unsigned int id)
{
	d->throwDocOpenError( __LINE__ );

	if( id >= d->documents.size() )
	{
        ostringstream s;
		s << "Incorrect document id " << id << ", there are only ";
		s << d->documents.size() << " documents in container.";
        d->throwError(s.str(), __LINE__);
	}
	if( !d->signatures.empty() )
	{
        d->throwError(
			"Can not remove document from container which has signatures, "
            "remove all signatures before removing document.", __LINE__);
	}

	int err = d->lib->f_DataFile_delete( d->doc, d->doc->pDataFiles[id]->szId );
    d->throwCodeError(err, "Failed to delete file", __LINE__);
	d->documents.erase( d->documents.begin() + id );
}

/**
 * Removes signature from container by signature id.
 *
 * @param id signature's id, which will be removed.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
void DDoc::removeSignature( unsigned int id )
{
	d->throwDocOpenError( __LINE__ );

	if( id >= d->signatures.size() )
	{
        ostringstream s;
		s << "Incorrect signature id " << id << ", there are only ";
		s << d->signatures.size() << " signatures in container.";
        d->throwError(s.str(), __LINE__);
	}

	int err = d->lib->f_SignatureInfo_delete( d->doc, d->doc->pSignatures[id]->szId );
    d->throwCodeError(err, "Failed to remove signature", __LINE__);
	d->loadSignatures();
}

/**
 * Saves the container using the <code>serializer</code> implementation provided in
 * <code>readFrom()</code> method.
 *
 * @throws IOException is thrown if there was a failure saving BDOC container. For example added
 *         document does not exist.
 * @throws ContainerException is thrown if BDoc class is not correctly initialized.
 */
void DDoc::save(const string &path)
{
    d->throwDocOpenError( __LINE__ );
    if(d->filename.empty() && path.empty())
        d->throwError("Path missing", __LINE__);
    string target = path.empty() ? d->filename : path;
    int err = d->lib->f_createSignedDoc(d->doc,
        d->filename.empty() || !File::fileExists(d->filename) ? nullptr : d->filename.c_str(), target.c_str());
    d->throwCodeError(err, "Failed to save document", __LINE__);
    d->filename = target;
}

/**
 * Signs all documents in container.
 *
 * @param signer signer implementation.
 * @throws ContainerException exception is throws if signing the BDCO container failed.
 */
Signature *DDoc::sign(Signer *signer)
{
    d->throwDocOpenError( __LINE__ );
    if(d->documents.empty())
        THROW("No documents in container, can not sign container.");
    if(!signer)
        THROW("Null pointer in DDoc::sign");

    X509Cert cert = signer->cert();
    if( !cert )
        throw Exception( __FILE__, __LINE__, "Failed to sign document, Certificate cannot be NULL" );

    ostringstream role;
    vector<string> r = signer->signerRoles();
    for( vector<string>::const_iterator i = r.begin(); i != r.end(); ++i )
    {
        role << *i;
        if( i + 1 != r.end() )
            role << " / ";
    }

#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    SignatureInfo *info = nullptr;
    int err = d->lib->f_ddocPrepareSignature( d->doc, &info,
        (role.str().empty() ? 0 : role.str().c_str()),
        (signer->city().empty() ? 0 : signer->city().c_str()),
        (signer->stateOrProvince().empty() ? 0 : signer->stateOrProvince().c_str()),
        (signer->postalCode().empty() ? 0 : signer->postalCode().c_str()),
        (signer->countryName().empty() ? 0 : signer->countryName().c_str()),
        X509_dup( cert.handle() ), 0 );
#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif
    d->throwSignError( info, err, "Failed to sign document", __LINE__ );
    if( !info )
        d->throwCodeError(ERR_NULL_POINTER, "Failed to sign document", __LINE__);

    vector<unsigned char> signature;
	try
    {
        signature = signer->sign(URI_RSA_SHA1, DDocPrivate::toVector(&info->pSigInfoRealDigest->mbufDigestValue));
	}
	catch( const Exception &e )
	{
		d->lib->f_SignatureInfo_delete( d->doc, info->szId );
        throw Exception(__FILE__, __LINE__, "Failed to sign document", e);
	}

    d->loadSignatures();
    SignatureDDOC *s = static_cast<SignatureDDOC*>(d->signatures.back());
    s->setSignatureValue(signature);
    try {
        s->notarize();
    } catch(const Exception &) {
        d->signatures.pop_back();
        delete s;
        throw;
    }

    return s;
}
