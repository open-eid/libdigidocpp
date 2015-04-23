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

#include "Container.h"

#include "BDoc.h"
#include "DDoc.h"
#include "DataFile.h"
#include "Exception.h"
#include "log.h"
#include "XmlConf.h"
#include "crypto/CNGSigner.h"
#include "crypto/PKCS11Signer.h"
#include "crypto/X509CertStore.h"
#include "util/File.h"

#include <xercesc/util/XMLString.hpp>
#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wnull-conversion"
#endif
#include <xsec/utils/XSECPlatformUtils.hpp>
#ifndef XSEC_NO_XALAN
#include <xalanc/XPath/XPathEvaluator.hpp>
#include <xalanc/XalanTransformer/XalanTransformer.hpp>
XALAN_USING_XALAN(XPathEvaluator)
XALAN_USING_XALAN(XalanTransformer)
#endif
#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif

#include <algorithm>
#include <sstream>
#include <thread>

using namespace digidoc;
using namespace std;
using namespace xercesc;

namespace digidoc
{
static string m_appInfo = "libdigidocpp";
}

/**
 * @class digidoc::Container
 * @brief Offers functionality for handling data files and signatures in a container.
 *
 * Container can contain several files and all these files can be signed using
 * signing certificates. Container can only be signed if it contains data files.
 * data files can be added and removed from container only if the container is
 * not signed. To add or remove data files from signed container remove all the
 * signatures before modifying data files list in container.
 */

/**
 * @enum digidoc::Container::DocumentType
 * Enum to select container type to create
 *
 * @var digidoc::Container::AsicType
 *
 * creates new \ref BDOC "BDOC 2.1" container with mime-type "application/vnd.etsi.asic-e+zip". See also \ref format
 *
 * @var digidoc::Container::BDocType
 *
 * creates new BDOC 1.0 container with mime-type "application/vnd.bdoc-1.0"
 * @deprecated Defauts to digidoc::Container::AsicType
 * @note the functionality of creating new files in DigiDoc file formats
 * BDOC 1.0 is not supported.
 *
 * @var digidoc::Container::DDocType
 *
 * creates new \ref DDOC "DIGIDOC-XML 1.3" container. Note that using BDOC 2.1 format is
 * preferred for new documents. Support for DIGIDOC-XML 1.3 format has been
 * added to Libdigidocpp via \ref CDigiDoc "CDigiDoc library". Note that usage of this
 * document format is tested only indirectly via DigiDoc3 Client desktop
 * application which uses CDigiDoc as a base layer.
 *
 * @note the functionality of creating new files in DigiDoc file formats
 * SK-XML, DIGIDOC-XML 1.1, DIGIDOC-XML 1.2 is not supported.
 */

/**
 * Returns registered application name
 */
string digidoc::appInfo() { return m_appInfo; }

/**
 * Returns libdigidocpp library version
 */
string digidoc::version() {
    string ver = VER_STR(MAJOR_VER.MINOR_VER.RELEASE_VER.BUILD_VER);
#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    ver += "_ddoc";
#endif
    return ver;
}

/**
 * Libdigidocpp’s initialization method: initializes dependent libraries,
 * loads configuration settings from default configuration files (see \ref conf) and initializes
 * certificate store using TSL lists
 *
 * @param appInfo Application name for user agent string
 */
void digidoc::initialize(const string &appInfo)
{
    digidoc::initializeEx(appInfo);
}

/**
 * Libdigidocpp’s initialization method: initializes dependent libraries,
 * loads configuration settings from default configuration files (see \ref conf) and initializes
 * certificate store using TSL lists
 *
 * @param appInfo Application name for user agent string
 * @param callBack Callback when background thread TSL loading is completed
 */
void digidoc::initializeEx(const string &appInfo, initCallBack callBack)
{
    m_appInfo = appInfo;

    try {
        XMLPlatformUtils::Initialize();
#ifndef XSEC_NO_XALAN
        XPathEvaluator::initialize();
        XalanTransformer::initialize();
#endif
        XSECPlatformUtils::Initialise();
    }
    catch (const XMLException &e) {
        char *msg = XMLString::transcode(e.getMessage());
        string result = msg;
        XMLString::release(&msg);
        THROW("Error during initialisation of Xerces: %s", result.c_str());
    }

    if(!Conf::instance())
        Conf::init(new XmlConfV4);
    if(X509CertStore::instance())
        return;
    if(callBack)
    {
        thread([=](){
            try {
                X509CertStore::init();
                callBack(nullptr);
            }
            catch(const Exception &e) {
                callBack(&e);
            }
        }).detach();
    }
    else
        X509CertStore::init();
}

/**
 * The termination method closes libraries used in Libdigidocpp
 * implementation and deletes temporary files that may have been
 * written to disk when working with the library.
 */
void digidoc::terminate()
{
    X509CertStore::destroy();
    Conf::init(0);

    XSECPlatformUtils::Terminate();
#ifndef XSEC_NO_XALAN
    XalanTransformer::terminate();
    XPathEvaluator::terminate();
#endif
    XMLPlatformUtils::Terminate();

    util::File::deleteTempFiles();
    m_appInfo.clear();
}

/**
 * Create a new container object and specify the DigiDoc container type
 */
Container::Container( DocumentType type )
    : m_doc(0)
{
    switch( type )
    {
#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    case DDocType: m_doc = new DDoc(); break;
#endif
    default: m_doc = new BDoc(); break;
    }
}

/**
 * Releases resources.
 */
Container::~Container()
{
    delete m_doc;
}

/**
 * Opens container from a file
 *
 * @param path
 * @throws Exception
 */
Container::Container( const string &path )
{
#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    string ext = path.substr( path.size() - 4 );
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if( ext == "ddoc" )
        m_doc = new DDoc( path );
    else
#endif
        m_doc = new BDoc( path );
}

/**
 * Adds data file from file system to the container.
 *
 * @param path a data file, which is added to the container.
 * @param mediaType MIME type of the data file, for example “text/plain” or “application/msword”
 * @throws Exception exception is thrown if the data file path is incorrect or a data file
 * with same file name already exists. Also, no data file can be added if the container
 * already has one or more signatures.
 * @note Data files can be removed from container only after all signatures are removed.
 */
void Container::addDataFile(const string &path, const string &mediaType)
{
	if( !m_doc )
        THROW("Document not open");

    m_doc->addDataFile(path, mediaType);
}

/**
 * Adds the data from an input stream (i.e. the data file contents can be read from internal memory buffer)
 *
 * @param is input stream from where data is read
 * @param fileName data file name in the container
 * @param mediaType MIME type of the data file, for example “text/plain” or “application/msword”
 * @throws Exception exception is thrown if the data file path is incorrect or a data file
 * with same file name already exists. Also, no data file can be added if the container
 * already has one or more signatures.
 * @note Data files can be removed from container only after all signatures are removed.
 */
void Container::addDataFile(istream *is, const string &fileName, const string &mediaType)
{
    if(!m_doc)
        THROW("Document not open");
    m_doc->addDataFile(is, fileName, mediaType);
}

/**
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws Exception throws exception if there are no data files in container.
 */
void Container::addRawSignature(const std::vector<unsigned char> &signature)
{
    std::stringstream s(std::string(&signature[0], &signature[0] + signature.size()));
    addRawSignature(s);
#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    if(m_doc->mediaType().compare(0, 11, "DIGIDOC-XML") == 0)
    {
        string path = util::File::tempFileName();
        m_doc->save(path);
        delete m_doc;
        m_doc = new DDoc(path);
    }
#endif
}

/**
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws Exception throws exception if there are no data files in container.
 */
void Container::addRawSignature(istream &signature)
{
	if( !m_doc )
        THROW("Document not open");

    m_doc->addRawSignature(signature);
}

/**
 * List of all the data files in the container
 */
DataFileList Container::dataFiles() const
{
    return m_doc ? m_doc->dataFiles() : DataFileList();
}

/**
 * Returnes list of all container's signatures.
 */
SignatureList Container::signatures() const
{
    return m_doc ? m_doc->signatures() : SignatureList();
}

/**
 * Removes data file from container by data file id. Data files can be
 * removed from container only after all signatures are removed.
 *
 * @param id data file's id, which will be removed.
 * @throws Exception throws exception if the data file id is incorrect or there are
 * one or more signatures.
 */
void Container::removeDataFile( unsigned int id )
{
	if( !m_doc )
        THROW("Document not open");

    m_doc->removeDataFile( id );
}

/**
 * Removes signature from container by signature id.
 *
 * @param id signature's id, which will be removed.
 * @throws Exception throws exception if the signature id is incorrect.
 */
void Container::removeSignature( unsigned int id )
{
	if( !m_doc )
        THROW("Document not open");

	m_doc->removeSignature( id );
}

/**
 * Saves the container.
 *
 * @throws Exception is thrown if there was a failure saving BDOC container. For example added
 * data file does not exist.
 */
void Container::save(const string &path)
{
    if( !m_doc )
        THROW("Document not open");
    m_doc->save(path);
}

/**
 * Signs all data files in container.
 *
 * @param signer signer implementation.
 * @throws Exception exception is thrown if signing the container failed.
 */
Signature* Container::sign( Signer *signer )
{
    return sign( signer, string() );
}

/**
 * Signs all data files in container.
 *
 * @param signer signer implementation.
 * @param profile type enables to specify the signature profile. Defaults to BDOC profile with time-stamp. To create BDOC with time-mark, set the parameter value to "time-mark". See also \ref Supported.
 * @throws Exception exception is thrown if signing the container failed.
 */
Signature* Container::sign( Signer *signer, const string &profile )
{
    if( !m_doc )
        THROW("Document not open");

    return m_doc->sign(signer, profile.empty() ? BDoc::ASIC_TS_PROFILE : profile);
}

/**
 * Signs all data files in container.
 *
 * @param city sets a signature production place signed property (optional)
 * @param stateOrProvince sets a signature production place signed property (optional)
 * @param postalCode sets a signature production place signed property (optional)
 * @param countryName sets a signature production place signed property (optional)
 * @param signerRoles the parameter may contain the signer’s role and optionally the signer’s resolution. Note that only one  signer role value (i.e. one &lt;ClaimedRole&gt; XML element) should be used. 
 * If the signer role contains both role and resolution then they must be separated with a slash mark, e.g. “role / resolution”. 
 * Note that when setting the resolution value then role must also be specified.
 * @param pin PIN code for accessing the private key
 * @param useFirstCertificate if set to “true”, determines that the first signing certificate that is found from the 
 * certificate store is chosen for signature creation and the certificate selection’s dialog window is not displayed to the
 * user
 */

Signature* Container::sign(const string &city, const string &stateOrProvince,
                           const string &postalCode, const string &countryName,
                           const vector<string> &signerRoles,
                           const string &pin, bool useFirstCertificate)
{
#ifdef _WIN32
    CNGSigner signer(pin, useFirstCertificate);
#else
    (void)useFirstCertificate;
    PKCS11Signer signer;
    signer.setPin(pin);
#endif
    signer.setSignatureProductionPlace(city, stateOrProvince, postalCode, countryName);
    signer.setSignerRoles(signerRoles);
    return sign(&signer);
}

/**
 * Returns current data file format
 */
string Container::mediaType() const
{
    return m_doc ? m_doc->mediaType() : "";
}
