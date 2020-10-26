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

#include "ASiC_E.h"
#include "ASiC_S.h"
#include "DataFile.h"
#include "DDoc.h"
#include "Exception.h"
#include "log.h"
#include "PDF.h"
#include "SiVaContainer.h"
#include "XmlConf.h"
#include "crypto/X509CertStore.h"
#include "util/File.h"

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_CLANG("-Wnull-conversion")
DIGIDOCPP_WARNING_DISABLE_MSVC(4005)
#include <xercesc/util/XMLString.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>
DIGIDOCPP_WARNING_POP
#if XSEC_VERSION_MAJOR == 1 && !defined(XSEC_NO_XALAN) || defined(XSEC_HAVE_XALAN)
#define USE_XALAN
#include <xalanc/XPath/XPathEvaluator.hpp>
DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_GCC("-Wunused-parameter")
#include <xalanc/XalanTransformer/XalanTransformer.hpp>
DIGIDOCPP_WARNING_POP
XALAN_USING_XALAN(XPathEvaluator)
XALAN_USING_XALAN(XalanTransformer)
#endif

#define XSD_CXX11
#include <xsd/cxx/xml/string.hxx>

#include <algorithm>
#include <sstream>
#include <thread>

using namespace digidoc;
using namespace std;
using namespace xercesc;

using plugin = unique_ptr<Container> (*)(const std::string &);

namespace digidoc
{
static string m_appName = "libdigidocpp";
static string m_userAgent = "libdigidocpp";
static vector<plugin> m_createList = {};
static vector<plugin> m_openList = {};
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
 * Returns registered application name
 */
string digidoc::appInfo() { return m_appName; }

/**
 * Returns user-agent info
 */
string digidoc::userAgent() { return m_userAgent; }

/**
 * Returns libdigidocpp library version
 */
string digidoc::version() {
    string ver = FILE_VER_STR;
#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    ver += "_ddoc";
#endif
#ifdef PDF_SUPPORT
    ver += "_siva";
#endif
    return ver;
}

/**
 * Libdigidocpp’s initialization method: initializes dependent libraries,
 * loads configuration settings from default configuration files (see \ref conf) and initializes
 * certificate store using TSL lists
 *
 * @param appInfo Application name for user agent string and container comments
 * @param callBack Callback when background thread TSL loading is completed
 */
void digidoc::initialize(const string &appInfo, initCallBack callBack)
{
    initialize(appInfo, appInfo, callBack);
}

/**
 * Libdigidocpp’s initialization method: initializes dependent libraries,
 * loads configuration settings from default configuration files (see \ref conf) and initializes
 * certificate store using TSL lists
 *
 * @param appInfo Application name for container comments
 * @param userAgent Application info for user agent string
 * @param callBack Callback when background thread TSL loading is completed
 */
void digidoc::initialize(const string &appInfo, const string &userAgent, initCallBack callBack)
{
    m_appName = appInfo;
    m_userAgent = userAgent;

    try {
        XMLPlatformUtils::Initialize();
#ifdef USE_XALAN
        XPathEvaluator::initialize();
        XalanTransformer::initialize();
#endif
        XSECPlatformUtils::Initialise();
    }
    catch (const XMLException &e) {
        try {
            string result = xsd::cxx::xml::transcode<char>(e.getMessage());
            THROW("Error during initialisation of Xerces: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Error during initialisation of Xerces.");
        }
    }

    if(!Conf::instance())
        Conf::init(new XmlConfCurrent);

#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    Container::addContainerImplementation<DDoc>();
#endif
#ifdef PDF_SUPPORT
    Container::addContainerImplementation<PDF>();
#endif
    Container::addContainerImplementation<SiVaContainer>();
    Container::addContainerImplementation<ASiC_S>();

    if(callBack)
    {
        thread([callBack]{
            try {
                X509CertStore::instance();
                callBack(nullptr);
            }
            catch(const Exception &e) {
                callBack(&e);
            }
        }).detach();
    }
    else
        X509CertStore::instance();
}

/**
 * The termination method closes libraries used in Libdigidocpp
 * implementation and deletes temporary files that may have been
 * written to disk when working with the library.
 */
void digidoc::terminate()
{
    try {
        Conf::init(nullptr);

        XSECPlatformUtils::Terminate();
#ifdef USE_XALAN
        XalanTransformer::terminate();
        XPathEvaluator::terminate();
#endif
        XMLPlatformUtils::Terminate();

        util::File::deleteTempFiles();
    } catch (...) {
        // Don't throw on terminate
    }
    m_createList.clear();
    m_openList.clear();
    m_appName.clear();
    m_userAgent.clear();
}

/**
 * Create a new container object and specify the DigiDoc container type
 */
Container::Container() = default;

/**
 * Releases resources.
 */
Container::~Container() = default;

/**
 * @fn digidoc::Container::addDataFile(const std::string &path, const std::string &mediaType)
 * Adds data file from file system to the container.
 *
 * @param path a data file, which is added to the container.
 * @param mediaType MIME type of the data file, for example “text/plain” or “application/msword”
 * @throws Exception exception is thrown if the data file path is incorrect or a data file
 * with same file name already exists. Also, no data file can be added if the container
 * already has one or more signatures.
 * @note Data files can be removed from container only after all signatures are removed.
 */

/**
 * Adds the data from an input stream (i.e. the data file contents can be read from internal memory buffer).
 *
 * Takes ownership std::istream *is object.
 * @deprecated digidoc::Container::addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType)
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
    addDataFile(unique_ptr<istream>(is), fileName, mediaType);
}

/**
 * Adds the data from an input stream (i.e. the data file contents can be read from internal memory buffer).
 *
 * @param is input stream from where data is read
 * @param fileName data file name in the container
 * @param mediaType MIME type of the data file, for example “text/plain” or “application/msword”
 * @throws Exception exception is thrown if the data file path is incorrect or a data file
 * with same file name already exists. Also, no data file can be added if the container
 * already has one or more signatures.
 * @note Data files can be removed from container only after all signatures are removed.
 */
void Container::addDataFile(unique_ptr<istream> /*is*/, const string & /*fileName*/, const string & /*mediaType*/)
{
    THROW("Not implemented.");
}

/**
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws Exception throws exception if there are no data files in container.
 */
void Container::addAdESSignature(const std::vector<unsigned char> &signature)
{
    stringstream s(string(signature.begin(), signature.end()));
    addAdESSignature(s);
}

/**
 * @fn digidoc::Container::addAdESSignature(std::istream &signature)
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws Exception throws exception if there are no data files in container.
 */

/**
 * Create a new container object and specify the DigiDoc container type
 *
 * @deprecated use Container::createPtr
 * This method gives ownership of object to caller
 */
Container* Container::create(const std::string &path)
{
    return createPtr(path).release();
}

/**
 * Create a new container object and specify the DigiDoc container type
 */
unique_ptr<Container> Container::createPtr(const std::string &path)
{
    for(auto create: m_createList)
    {
        if(unique_ptr<Container> container = create(path))
            return container;
    }
    return ASiC_E::createInternal(path);
}


/**
 * @fn digidoc::Container::dataFiles
 * List of all the data files in the container
 *
 * Container holds ownership of data files objects
 */

/**
 * @fn digidoc::Container::mediaType
 * Returns current data file format
 */

/**
 * Returns unique signature id
 */
unsigned int Container::newSignatureId() const
{
    vector<Signature*> list = signatures();
    for(unsigned int id = 0; ; ++id)
        if(!any_of(list.cbegin(), list.cend(), [id](Signature *s){ return s->id() == Log::format("S%u", id); }))
            return id;
}

/**
 * Opens container from a file
 *
 * This method gives ownership of object to caller
 *
 * @deprecated use Container::openPtr
 * @param path
 * @throws Exception
 */
Container* Container::open(const string &path)
{
    return openPtr(path).release();
}

/**
 * Opens container from a file
 *
 * @param path
 * @throws Exception
 */
unique_ptr<Container> Container::openPtr(const string &path)
{
    for(auto open: m_openList)
    {
        if(unique_ptr<Container> container = open(path))
            return container;
    }
    return ASiC_E::openInternal(path);
}

/**
 * @fn digidoc::Container::prepareSignature(Signer *signer)
 *
 * Prepares Signature object that can later signed.
 *
 * Container holds ownership of Signature object
 *
 * @see digidoc::Signature::dataToSign
 * @see digidoc::Signature::setSignatureValue
 * @see digidoc::Signature::extendSignatureProfile
 *
 * @param signer signer implementation.
 * @throws Exception exception is thrown if signing the container failed.
 */

/**
 * @fn digidoc::Container::removeDataFile
 * Removes data file from container by data file index. Data files can be
 * removed from container only after all signatures are removed.
 *
 * @param index data file's index, which will be removed.
 * @throws Exception throws exception if the data file id is incorrect or there are
 * one or more signatures.
 * @see digidoc::Container::dataFiles
 */

/**
 * @fn digidoc::Container::removeSignature
 * Removes signature from container by signature index.
 *
 * @param index signature's index, which will be removed.
 * @throws Exception throws exception if the signature id is incorrect.
 * @see digidoc::Container::signatures
 */

/**
 * @fn digidoc::Container::save
 * Saves the container.
 *
 * @throws Exception is thrown if there was a failure saving container. For example added
 * data file does not exist.
 */

/**
 * @fn digidoc::Container::sign(Signer *signer)
 *
 * Signs all data files in container.
 *
 * This method does not take ownership of signer object.
 * Container holds ownership of Signature object.
 *
 * @param signer signer implementation.
 * @throws Exception exception is thrown if signing the container failed.
 */

/**
 * Adds container implementation
 *
 * It must contain static members:
 * * static Container* createInternal(const std::string &path);
 * * static Container* openInternal(const std::string &path);
 *
 * @see Container::create, Container::open
 */
template<class T>
void Container::addContainerImplementation()
{
    m_createList.push_back(&T::createInternal);
    m_openList.push_back(&T::openInternal);
}

/**
 * @fn digidoc::Container::signatures
 * Returns list of all container's signatures.
 *
 * Container holds ownership of signature objects
 */
