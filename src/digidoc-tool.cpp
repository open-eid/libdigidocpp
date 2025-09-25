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

#include "Conf.h"
#include "Container.h"
#include "DataFile.h"
#include "Signature.h"
#include "XmlConf.h"
#include "crypto/Digest.h"
#include "crypto/PKCS11Signer.h"
#include "crypto/PKCS12Signer.h"
#include "crypto/TSL.h"
#include "crypto/WinSigner.h"
#include "crypto/X509Cert.h"
#include "util/File.h"
#include "util/log.h"

#include <algorithm>
#include <iostream>
#include <optional>
#include <sstream>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <conio.h>
#else
#include <cstring>
#include <unistd.h>
#endif

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
namespace fs = filesystem;

namespace std
{
static ostream &operator<<(ostream &os, const X509Cert &cert)
{
    return os << cert.subjectName("CN");
}

static ostream &operator<<(ostream &os, const vector<unsigned char> &data)
{
    os << hex << uppercase << setfill('0');
    for(unsigned char i: data)
        os << setw(2) << static_cast<int>(i) << ' ';
    return os << dec << nouppercase << setfill(' ');
}

static ostream &operator<<(ostream &os, const Exception::ExceptionCode code)
{
    switch(code)
    {
    case Exception::General: return os << "General";
    case Exception::NetworkError: return os << "NetworkError";
    case Exception::HostNotFound: return os << "HostNotFound";
    case Exception::InvalidUrl: return os << "InvalidUrl";
    case Exception::CertificateIssuerMissing: return os << "CertificateIssuerMissing";
    case Exception::CertificateRevoked: return os << "CertificateRevoked";
    case Exception::CertificateUnknown: return os << "CertificateUnknown";
    case Exception::OCSPBeforeTimeStamp: return os << "OCSPBeforeTimeStamp";
    case Exception::OCSPResponderMissing: return os << "OCSPResponderMissing";
    case Exception::OCSPCertMissing: return os << "OCSPCertMissing";
    case Exception::OCSPTimeSlot: return os << "OCSPTimeSlot";
    case Exception::OCSPRequestUnauthorized: return os << "OCSPRequestUnauthorized";
    case Exception::TSForbidden: return os << "TSForbidden";
    case Exception::TSTooManyRequests: return os << "TSTooManyRequests";
    case Exception::PINCanceled: return os << "PINCanceled";
    case Exception::PINFailed: return os << "PINFailed";
    case Exception::PINIncorrect: return os << "PINIncorrect";
    case Exception::PINLocked: return os << "PINLocked";
    case Exception::ReferenceDigestWeak: return os << "ReferenceDigestWeak";
    case Exception::SignatureDigestWeak: return os << "SignatureDigestWeak";
    case Exception::DataFileNameSpaceWarning: return os << "DataFileNameSpaceWarning";
    case Exception::IssuerNameSpaceWarning: return os << "IssuerNameSpaceWarning";
    case Exception::ProducedATLateWarning: return os << "ProducedATLateWarning";
    case Exception::MimeTypeWarning: return os << "MimeTypeWarning";
    case Exception::DDocError: return os << "DDocError";
    }
    return os;
}

static ostream &operator<<(ostream &os, const Exception &e)
{
    os << e.file() << ":" << e.line() << " code(" << e.code() << ") " << e.msg() << endl;
    for(const Exception &ex: e.causes())
        os << ex;
    return os;
}

static ostream &operator<<(ostream &os, Signature::Validator::Status status)
{
    switch(status)
    {
    case Signature::Validator::Valid: return os;
    case Signature::Validator::Warning: return os << "(Warning)";
    case Signature::Validator::NonQSCD: return os << "(NonQSCD)";
    case Signature::Validator::Test:
    case Signature::Validator::Unknown: return os << "(Unknown)";
    case Signature::Validator::Invalid: return os << "(Invalid)";
    }
    return os;
}

static ostream &endl(ostream &os)
{
    return os.put('\n');
}
}

/**
 * For demonstration purpose overwrites certificate selection to print out all
 * the certificates available on ID-Card.
 */
class ConsolePinSigner final : public PKCS11Signer
{
public:
    ConsolePinSigner(const string &driver, const string &pin)
        : PKCS11Signer(driver)
    {
        setPin(pin);
    }

private:
    string pin(const X509Cert &certificate) const final;
    X509Cert selectSigningCertificate(const vector<X509Cert> &certificates) const final
    {
        cout << "Available certificates:" << endl;
        for(const X509Cert &cert: certificates)
            cout << "  label: " << cert << endl;
        cout << "Selected:" << endl;
        X509Cert cert = certificates.front();
        cout << "  label: " << cert << endl;
        return cert;
    }
};

string ConsolePinSigner::pin(const X509Cert &certificate) const
{
    if(!PKCS11Signer::pin(certificate).empty())
        return PKCS11Signer::pin(certificate);

    char pin[16];
    size_t pinMax = 16;

    const char *prompt = "Please enter PIN for token '%s' or <enter> to cancel: ";
#if defined(_WIN32)
    // something that acts wildly similarily with getpass()
    {
        printf(prompt, certificate.subjectName("CN").c_str());
        size_t i = 0;
        int c;
        while ( (c = _getch()) != '\r' )
        {
            switch ( c )
            {
            default:
                if ( i >= pinMax-1 || iscntrl( c ) )
                {
                    // can't be a part of password
                    fputc( '\a', stdout );
                    break;
                }
                pin[i++] = static_cast<char>(c);
                fputc( '*', stdout );
                break;
            case EOF:
            {
                fputs( "[EOF]\n", stdout );
                Exception e(EXCEPTION_PARAMS("PIN acquisition canceled with [EOF]."));
                e.setCode( Exception::PINCanceled );
                throw e;
            }
            case 0:
            case 0xE0:  // FN Keys (0 or E0) start of two-character FN code
                c = ( c << 4 ) | _getch();
                if ( c != 0xE53 && c != 0xE4B && c != 0x053 && c != 0x04b )
                {
                    // not {DELETE}, {<--}, Num{DEL} and Num{<--}
                    fputc( '\a', stdout );
                    break;
                }
                // NO BREAK, fall through to the one-character deletes
            case '\b':
            case 127:
                if ( i == 0 )
                {
                    // nothing to delete
                    fputc( '\a', stdout );
                    break;
                }
                pin[--i] = '\0';
                fputs( "\b \b", stdout );
                break;
            case  3: // CTRL+C
            {
                fputs( "^C\n", stdout );
                Exception e(EXCEPTION_PARAMS("PIN acquisition canceled with ^C."));
                e.setCode( Exception::PINCanceled );
                throw e;
            }
            case  26: // CTRL+Z
            {
                fputs( "^Z\n", stdout );
                Exception e(EXCEPTION_PARAMS("PIN acquisition canceled with ^Z."));
                e.setCode( Exception::PINCanceled );
                throw e;
            }
            case  27: // ESC
                fputc('\n', stdout );
                printf(prompt, certificate.subjectName("CN").c_str());
                i = 0;
                break;
            }
        }
        fputc( '\n', stdout );
        pin[i] = '\0';
    }
#else
    char* pwd = getpass(Log::format(prompt, certificate.subjectName("CN").c_str()).c_str());
    strncpy(pin, pwd, pinMax);
#endif

    pin[pinMax-1] = '\0';

    string result(pin);
    if(result.empty())
    {
        Exception e(EXCEPTION_PARAMS("PIN acquisition canceled."));
        e.setCode( Exception::PINCanceled );
        throw e;
    }

    return result;
}

struct value: public string_view {
    using string_view::string_view;
    using string_view::operator=;

    constexpr value(string_view arg, string_view param) noexcept
        : string_view(arg.size() > param.size() && arg.starts_with(param) ?
                          arg.substr(param.size()) : string_view{})
    {}

    operator string() const
    {
        return {begin(), end()};
    }

    constexpr operator bool() const noexcept
    {
        return !empty();
    }
};

class NullSigner final: public Signer
{
public:
    explicit NullSigner(X509Cert cert): _cert(std::move(cert)) {}
    X509Cert cert() const final { return _cert; }
    vector<unsigned char> sign(const string & /*method*/, const vector<unsigned char> & /*digest*/) const final
    {
        THROW("Not implemented");
    }
    X509Cert _cert;
};

class ToolConfig final: public XmlConfCurrent
{
public:
    enum Warning : uint8_t {
        WError,
        WWarning,
        WIgnore
    };

    ToolConfig(int argc, char *argv[]);
    int logLevel() const final { return _logLevel.value_or(XmlConfCurrent::logLevel()); }
    string logFile() const final { return _logFile.value_or(XmlConfCurrent::logFile()); }
    string digestUri() const final { return uri.value_or(XmlConfCurrent::digestUri()); }
    string signatureDigestUri() const final { return siguri.value_or(XmlConfCurrent::signatureDigestUri()); }
    bool TSLAllowExpired() const final { return expired.value_or(XmlConfCurrent::TSLAllowExpired()); }
    vector<X509Cert> TSLCerts() const final { return tslcerts.value_or(XmlConfCurrent::TSLCerts()); }
    string TSUrl() const final { return tsurl.value_or(XmlConfCurrent::TSUrl()); }
    string TSLUrl() const final { return tslurl.value_or(XmlConfCurrent::TSLUrl()); }

    unique_ptr<Signer> getSigner(bool getwebsigner = false) const;

    // Config
    optional<int> _logLevel;
    optional<bool> expired;
    optional<vector<X509Cert>> tslcerts;
    optional<string> _logFile;
    optional<string> tsurl;
    optional<string> tslurl;
    optional<string> uri;
    optional<string> siguri;

    // Signer
    value profile, city, street, state, postalCode, country, userAgent;
    vector<string> roles;
    bool XAdESEN = false;

    // Token
    optional<bool> rsaPss;
    value pkcs11, pkcs12, pin, cert;
    vector<unsigned char> thumbprint;
    bool cng = true, selectFirst = false;

    // Params
    value path;
    unordered_map<value,value,std::hash<string_view>> files;
    bool doSign = true, dontValidate = false;
    static string_view RED, GREEN, YELLOW, RESET;
};



/**
 * Prints application usage.
 */
static int printUsage(const char *executable)
{
    cout
    << "Usage: " << executable << " COMMAND [OPTIONS] FILE" << endl << endl
    << "  Command create:" << endl
    << "    Example: " << executable << " create --file=file1.txt --file=file2.txt demo-container.asice" << endl
    << "    Available options:" << endl
    << "      --file=        - File(s) to be signed. The option can occur multiple times." << endl
    << "      --mime=        - Specifies the file's mime-type value. When used then must be written right " << endl
    << "                       after the \"-file\" parameter. Default value is application/octet-stream" << endl
    << "      --dontsign     - Don't sign the newly created container." << endl
    << "      for additional options look sign command" << endl << endl
    << "  Command createBatch:" << endl
    << "    Example: " << executable << " createBatch folder/content/to/sign" << endl
    << "    Available options:" << endl
    << "      for additional options look sign command" << endl << endl
    << "  Command open:" << endl
    << "    Example: " << executable << " open container-file.asice" << endl
    << "    Available options:" << endl
    << "      --warnings=(ignore,warning,error) - warning handling (default warning)" << endl
    << "      --extractAll[=path]    - extracts documents without validating signatures (to path when provided)" << endl
    << "      --validateOnExtract    - validates container before extracting files" << endl << endl
    << "      --offline              - open container offline (eg. Don't send to SiVa)" << endl << endl
    << "  Command add:" << endl
    << "    Example: " << executable << " add --file=file1.txt container-file.asice" << endl
    << "    Available options:" << endl
    << "      --file and --mime look create command for info" << endl << endl
    << "  Command remove:" << endl
    << "    Example: " << executable << " remove --document=0 --document=1 --signature=1 container-file.asice" << endl
    << "    Available options:" << endl
    << "      --document=    - documents to remove" << endl
    << "      --signature=   - signatures to remove" << endl << endl
    << "  Command websign:" << endl
    << "    Example: " << executable << " websign --cert=signer.crt demo-container.asice" << endl
    << "    Available options:" << endl
    << "      --cert=        - signer token certificate" << endl
    << "      for additional options look sign command" << endl << endl
    << "  Command sign:" << endl
    << "    Example: " << executable << " sign demo-container.asice" << endl
    << "    Available options:" << endl
    << "      --profile=     - signature profile, TS, TSA, time-stamp, time-stamp-archive, TimeStampToken, time-stamp-token" << endl
    << "      --XAdESEN      - use XAdES EN profile" << endl
    << "      --city=        - city of production place" << endl
    << "      --street=      - streetAddress of production place in XAdES EN profile" << endl
    << "      --state=       - state of production place" << endl
    << "      --postalCode=  - postalCode of production place" << endl
    << "      --country=     - country of production place" << endl
    << "      --role=        - option can occur multiple times. Signer role(s)" << endl
#ifdef _WIN32
    << "      --cng          - Use CNG api for signing under windows." << endl
    << "      --selectFirst  - Select first certificate in store." << endl
    << "      --thumbprint=  - Select certificate in store with specified thumbprint (HEX)." << endl
#endif
    << "      --pkcs11[=]    - default is " << CONF(PKCS11Driver) << ". Path of PKCS11 driver." << endl
    << "      --pkcs12=      - pkcs12 signer certificate (use --pin for password)" << endl
    << "      --pin=         - default asks pin from prompt" << endl
    << "      --sha(224,256,384,512) - set default digest method (default sha256)" << endl
    << "      --sigsha(224,256,384,512) - set default digest method (default sha256)" << endl
    << "      --sigpsssha(224,256,384,512) - set default digest method using RSA PSS (default sha256, same as --sigsha* with --rsapss)" << endl
    << "      --rsapkcs15    - Use RSA PKCS1.5 padding" << endl
    << "      --rsapss       - Use RSA PSS padding" << endl
    << "      --tsurl        - option to change TS URL (default " << CONF(TSUrl) << ")" << endl
    << "      --dontValidate - Don't validate container on signature creation" << endl << endl
    << "      --userAgent    - Additional info info that is sent to TSA or OCSP service" << endl << endl
    << "  Command extend:" << endl
    << "    Example: " << executable << " extend --signature=0 demo-container.asice" << endl
    << "    Available options:" << endl
    << "      --profile=     - signature profile, TS, TSA, time-stamp, time-stamp-archive" << endl
    << "      --signature=   - signature to extend" << endl
    << "      --dontValidate - Don't validate container on signature creation" << endl << endl
    << "  All commands:" << endl
    << "      --nocolor      - Disable terminal colors" << endl
    << "      --loglevel=[0,1,2,3,4] - Log level 0 - none, 1 - error, 2 - warning, 3 - info, 4 - debug" << endl
    << "      --logfile=     - File to log, empty to console" << endl;
    return EXIT_FAILURE;
}

string_view ToolConfig::RED = "\033[31m";
string_view ToolConfig::GREEN = "\033[32m";
string_view ToolConfig::YELLOW = "\033[33m";
string_view ToolConfig::RESET = "\033[0m";

ToolConfig::ToolConfig(int argc, char *argv[])
{
    for(int i = 2; i < argc; i++)
    {
        string_view arg(argv[i]);
        if(value v{arg, "--profile="}) profile = v;
        else if(value v{arg, "--file="})
        {
            value mime(i+1 < argc ? argv[i+1] : string_view(), "--mime=");
            files.emplace(v, mime ? mime : "application/octet-stream");
        }
#ifdef _WIN32
        else if(arg == "--cng") cng = true;
        else if(arg == "--selectFirst") selectFirst = true;
        else if(value v{arg, "--thumbprint="}) thumbprint = File::hexToBin(v);
#endif
        else if(arg == "--pkcs11")
            cng = false;
        else if(value v{arg, "--pkcs11="})
        {
            cng = false;
            pkcs11 = v;
        }
        else if(value v{arg, "--pkcs12="})
        {
            cng = false;
            pkcs12 = v;
        }
        else if(arg == "--dontValidate") dontValidate = true;
        else if(arg == "--XAdESEN") XAdESEN = true;
        else if(value v{arg, "--pin="}) pin = v;
        else if(value v{arg, "--cert="}) cert = v;
        else if(value v{arg, "--city="}) city = v;
        else if(value v{arg, "--street="}) street = v;
        else if(value v{arg, "--state="}) state = v;
        else if(value v{arg, "--postalCode="}) postalCode = v;
        else if(value v{arg, "--country="}) country = v;
        else if(value v{arg, "--role="}) roles.emplace_back(v);
        else if(arg == "--sha224") uri = URI_SHA224;
        else if(arg == "--sha256") uri = URI_SHA256;
        else if(arg == "--sha384") uri = URI_SHA384;
        else if(arg == "--sha512") uri = URI_SHA512;
        else if(arg == "--sigsha224") siguri = URI_SHA224;
        else if(arg == "--sigsha256") siguri = URI_SHA256;
        else if(arg == "--sigsha384") siguri = URI_SHA384;
        else if(arg == "--sigsha512") siguri = URI_SHA512;
        else if(arg == "--sigpsssha224") { siguri = URI_SHA224; rsaPss = true; }
        else if(arg == "--sigpsssha256") { siguri = URI_SHA256; rsaPss = true; }
        else if(arg == "--sigpsssha384") { siguri = URI_SHA384; rsaPss = true; }
        else if(arg == "--sigpsssha512") { siguri = URI_SHA512; rsaPss = true; }
        else if(arg == "--rsapkcs15") rsaPss = false;
        else if(arg == "--rsapss") rsaPss = true;
        else if(value v{arg, "--tsurl="}) tsurl = v;
        else if(value v{arg, "--tslurl="}) tslurl = v;
        else if(value v{arg, "--tslcert="}) tslcerts = vector<X509Cert>{ X509Cert(v) };
        else if(arg == "--TSLAllowExpired") expired = true;
        else if(arg == "--dontsign") doSign = false;
        else if(arg == "--nocolor") RED = GREEN = YELLOW = RESET = {};
        else if(value v{arg, "--loglevel="}) _logLevel = atoi(v.data());
        else if(value v{arg, "--logfile="}) _logFile = v;
        else path = arg;
    }
}

/**
 * Create Signer object from Params.
 *
 * @param getwebsigner get WebSigner object
 * @return Signer
 */
unique_ptr<Signer> ToolConfig::getSigner(bool getwebsigner) const
{
    unique_ptr<Signer> signer;
    if(getwebsigner)
        signer = make_unique<NullSigner>(X509Cert(cert, X509Cert::Pem));
#ifdef _WIN32
    else if(cng)
    {
        auto win = make_unique<WinSigner>(pin, selectFirst);
        win->setThumbprint(thumbprint);
        signer = std::move(win);
    }
#endif
    else if(!pkcs12.empty())
        signer = make_unique<PKCS12Signer>(pkcs12, pin);
    else
        signer = make_unique<ConsolePinSigner>(pkcs11, pin);
    signer->setENProfile(XAdESEN);
    signer->setSignatureProductionPlaceV2(city, street, state, postalCode, country);
    signer->setSignerRoles(roles);
    signer->setProfile(profile);
    signer->setUserAgent(userAgent);
    if(rsaPss.has_value())
        signer->setMethod(rsaPss.value() ? Digest::toRsaPssUri(signatureDigestUri()) : Digest::toRsaUri(signatureDigestUri()));
    return signer;
}

/**
 * Validate signature.
 *
 * @param signature Signature to validated
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int validateSignature(const Signature *s, ToolConfig::Warning warning = ToolConfig::WWarning)
{
    int returnCode = EXIT_SUCCESS;
    Signature::Validator v(s);
    cout << "    Validation: ";
    switch (v.status()) {
    case Signature::Validator::Valid:
        cout << ToolConfig::GREEN << "OK";
        break;
    case Signature::Validator::Warning:
    case Signature::Validator::NonQSCD:
        if(warning != ToolConfig::WError)
        {
            cout << ToolConfig::YELLOW << "OK " << v.status();
            break;
        }
        [[fallthrough]];
    case Signature::Validator::Test:
    case Signature::Validator::Unknown:
    case Signature::Validator::Invalid:
        cout << ToolConfig::RED << "FAILED " << v.status();
        returnCode = EXIT_FAILURE;
        break;
    }
    cout << ToolConfig::RESET << endl;
    if(!v.warnings().empty() && warning != ToolConfig::WIgnore)
    {
        cout << "    Warnings: " << ToolConfig::YELLOW;
        for(Exception::ExceptionCode code: v.warnings())
            cout << code;
        cout << ToolConfig::RESET << endl;
    }
    if(!v.diagnostics().empty())
        cout << "    Exception:" << endl << v.diagnostics() << endl;
    return returnCode;
}

/**
 * Open container
 *
 * @param argc number of command line arguments.
 * @param argv command line arguments.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int open(int argc, char* argv[])
{
    ToolConfig::Warning reportwarnings = ToolConfig::WWarning;
    value path;
    fs::path extractPath;
    bool validateOnExtract = false;
    int returnCode = EXIT_SUCCESS;
    struct OpenCB final: public ContainerOpenCB
    {
        bool online = true;
        bool validateOnline() const final { return online; }
    } cb;

    // Parse command line arguments.
    for(int i = 2; i < argc; i++)
    {
        string_view arg(argv[i]);
        if(arg == "--list")
            continue;
        if(value v{arg, "--warnings="})
        {
            if(v == "ignore") reportwarnings = ToolConfig::WIgnore;
            if(v == "error") reportwarnings = ToolConfig::WError;
        }
        else if(arg == "--extractAll")
            extractPath = fs::current_path();
        else if(value v{arg, "--extractAll="})
        {
            extractPath = fs::absolute(fs::path(v.begin(), v.end()));
            if(!fs::is_directory(extractPath))
                THROW("Path is not directory");
        }
        else if(arg == "--validateOnExtract")
            validateOnExtract = true;
        else if(arg == "--offline")
            cb.online = false;
        else
            path = arg;
    }

    if(path.empty())
        return printUsage(argv[0]);

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(path, &cb);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    auto extractFiles = [&doc,extractPath]() {
        cout << "Extracting documents: " << endl;
        for(const DataFile *file: doc->dataFiles())
        {
            try {
                auto dst = (extractPath / fs::path(file->fileName()).filename());
                file->saveAs(dst.string());
                cout << "  Document(" << file->mediaType() << ") extracted to " << dst << " (" << file->fileSize() << " bytes)" << endl;
            } catch(const Exception &e) {
                cout << "  Document " << file->fileName() << " extraction: " << ToolConfig::RED << "FAILED" << ToolConfig::RESET << endl;
                cout << "  Exception:" << endl << e;
                return EXIT_FAILURE;
            }
        }
        return EXIT_SUCCESS;
    };

    if(!extractPath.empty() && !validateOnExtract)
        return extractFiles();

    cout << "Container file: " << path << endl;
    cout << "Container type: " << doc->mediaType() << endl;

    // Print container document list.
    cout << "Documents (" << doc->dataFiles().size() << "):\n" << endl;
    for(const DataFile *file: doc->dataFiles())
    {
        cout << "  Document (" << file->mediaType() << "): " << file->fileName()
             << " (" << file->fileSize() << " bytes)" << endl;
    }

    // Print container signatures list.
    cout << endl << "Signatures (" << doc->signatures().size() << "):" << endl;
    unsigned int pos = 0;
    for(const Signature *s: doc->signatures())
    {
        cout << "  Signature " << pos++ << " (" << s->profile().c_str() << "):" << endl
             << "    ID: " << s->id() << endl;
        // Validate signature. Checks, whether signature format is correct
        // and signed documents checksums are correct.
        if(validateSignature(s, reportwarnings) == EXIT_FAILURE)
            returnCode = EXIT_FAILURE;

        // Get signature production place info.
        if(!s->city().empty() || !s->stateOrProvince().empty() || !s->streetAddress().empty() || !s->postalCode().empty() || !s->countryName().empty())
        {
            cout << "    Signature production place:" << endl
                 << "      City:              " << s->city() << endl
                 << "      State or Province: " << s->stateOrProvince() << endl
                 << "      Street address:    " << s->streetAddress() << endl
                 << "      Postal code:       " << s->postalCode() << endl
                 << "      Country:           " << s->countryName() << endl;
        }

        // Get signer role info.
        vector<string> roles = s->signerRoles();
        if(!roles.empty())
        {
            cout << "    Signer role(s):" << endl;
            for(const string &role : roles)
                cout << "      " << role << endl;
        }

        vector<unsigned char> msgImprint = s->messageImprint();
        cout << "    EPES policy: " << s->policy() << endl
            << "    SPUri: " << s->SPUri() << endl
            << "    Signature method: " << s->signatureMethod() << endl
            << "    Signing time: " << s->claimedSigningTime() << endl
            << "    Signing cert: " << s->signingCertificate() << endl
            << "    Signed by: " << s->signedBy() << endl
            << "    Produced At: " << s->OCSPProducedAt() << endl
            << "    OCSP Responder: " << s->OCSPCertificate() << endl
            << "    Message imprint (" << msgImprint.size() << "): " << msgImprint << endl
            << "    TS: " << s->TimeStampCertificate() << endl
            << "    TS time: " << s->TimeStampTime() << endl;
        for(const auto &tsaInfo: s->ArchiveTimeStamps())
        {
            cout
                << "    TSA: " << tsaInfo.cert << '\n'
                << "    TSA time: " << tsaInfo.time << '\n';
        }
    }
    if(returnCode == EXIT_SUCCESS && !extractPath.empty())
        return extractFiles();
    return returnCode;
}

/**
 * Extend signatures in container.
 *
 * @param argc number of command line arguments.
 * @param argv command line arguments.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int extend(int argc, char *argv[])
{
    vector<unsigned int> extendId;
    bool dontValidate = false;
    value path;
    NullSigner signer{X509Cert()};
    for(int i = 2; i < argc; i++)
    {
        string_view arg(argv[i]);
        if(value v{arg, "--profile="})
            signer.setProfile(v);
        else if(value v{arg, "--signature="})
            extendId.push_back(unsigned(atoi(v.data())));
        else if(arg == "--dontValidate")
            dontValidate = true;
        else
            path = arg;
    }

    if(path.empty())
        return printUsage(argv[0]);

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    auto signatures = doc->signatures();
    if(signatures.empty())
    {
        cout << "  Container does not contain signatures\n";
        return EXIT_SUCCESS;
    }

    for(unsigned int i : extendId)
    {
        if(i >= signatures.size())
            THROW("Incorrect signature id %u, there are only %zu signatures in container.", i, signatures.size());
        cout << "  Extending signature " << i << " to " << signer.profile() << endl;
        Signature *s = doc->signatures().at(i);
        s->extendSignatureProfile(&signer);
        if(!dontValidate)
            validateSignature(s);
    }

    if(extendId.empty())
    {
        cout << "  Extending " << signatures.size() << " signature(s)\n";
        if(auto wrapped = Container::extendContainerValidity(*doc, &signer))
        {
            doc = std::move(wrapped);
            cout << "  Wrapped to new container\n";
        }
    }

    doc->save();
    return EXIT_SUCCESS;
}

/**
 * Remove items from container.
 *
 * @param argc number of command line arguments.
 * @param argv command line arguments.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int remove(int argc, char *argv[])
{
    vector<unsigned int> documents, signatures;
    value path;
    for(int i = 2; i < argc; i++)
    {
        string_view arg(argv[i]);
        if(value v{arg, "--document="})
            documents.push_back(unsigned(atoi(v.data())));
        else if(value v{arg, "--signature="})
            signatures.push_back(unsigned(atoi(v.data())));
        else
            path = arg;
    }

    if(path.empty())
        return printUsage(argv[0]);

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    sort(signatures.begin(), signatures.end(), greater<unsigned int>());
    for(unsigned int i : signatures)
    {
        cout << "  Removing signature " << i << endl;
        doc->removeSignature(i);
    }

    sort(documents.begin(), documents.end(), greater<unsigned int>());
    for(unsigned int i : documents)
    {
        cout << "  Removing document " << i << endl;
        doc->removeDataFile(i);
    }

    doc->save();
    return EXIT_SUCCESS;
}


/**
 * Add items to the container.
 *
 * @param p ToolConfig object.
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int add(const ToolConfig &p, const char *program)
{
    if(p.path.empty() || p.files.empty())
        return printUsage(program);

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    for(const auto &[file, mime]: p.files)
        doc->addDataFile(file, mime);
    doc->save();
    return EXIT_SUCCESS;
}

/**
 * Sign the container.
 *
 * @param doc the container that is to be signed
 * @param signer Signer to used for sign
 * @param dontValidate Do not validate result
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int signContainer(Container *doc, const unique_ptr<Signer> &signer, bool dontValidate = false)
{
    if(Signature *signature = doc->sign(signer.get()))
        return dontValidate ? EXIT_SUCCESS : validateSignature(signature);
    return EXIT_FAILURE;
}

/**
 * Create new container and sign unless explicitly requested not to sign
 *
 * @param p ToolConfig object.
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int create(const ToolConfig &p, const char *program)
{
    if(p.path.empty() || p.files.empty())
        return printUsage(program);

    unique_ptr<Container> doc;
    try {
        doc = Container::createPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    for(const auto &[file, mime]: p.files)
        doc->addDataFile(file, mime);

    int returnCode = EXIT_SUCCESS;
    if(p.doSign)
        returnCode = signContainer(doc.get(), p.getSigner(), p.dontValidate);
    doc->save();
    return returnCode;
}

/**
 * Create new container.
 *
 * @param p ToolConfig object
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int createBatch(const ToolConfig &p, const char *program)
{
    if(p.path.empty())
        return printUsage(program);

    unique_ptr<Signer> signer = p.getSigner();
    error_code ec;
    int returnCode = EXIT_SUCCESS;
    for(const auto &file: fs::directory_iterator(string_view(p.path), ec))
    {
        if(!fs::is_regular_file(file.status()) || file.path().extension() == ".asice")
            continue;
        const auto path = file.path().string();
        cout << "Signing file: " << path << endl;
        try {
            unique_ptr<Container> doc = Container::createPtr(path + ".asice");
            doc->addDataFile(path, "application/octet-stream");
            if(signContainer(doc.get(), signer, p.dontValidate) == EXIT_FAILURE)
                returnCode = EXIT_FAILURE;
            doc->save();
        } catch(const Exception &e) {
            cout << "  Exception:" << endl << e;
            returnCode = EXIT_FAILURE;
        }
    }
    if(ec)
    {
        cout << "Failed to open directory " << p.path << endl;
        cout << "  Exception: " << ec.message() << endl;
        return EXIT_FAILURE;
    }
    return returnCode;
}

/**
 * Sign container.
 *
 * @param p ToolConfig object.
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int sign(const ToolConfig &p, const char *program)
{
    if(p.path.empty())
        return printUsage(program);

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    int returnCode = signContainer(doc.get(), p.getSigner(), p.dontValidate);
    doc->save();
    return returnCode;
}

static int websign(const ToolConfig &p, const char *program)
{
    if(p.path.empty())
        return printUsage(program);

    unique_ptr<Container> doc;
    try {
        doc = Container::createPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    for(const auto &[file, mime]: p.files)
        doc->addDataFile(file, mime);

    int returnCode = EXIT_FAILURE;
    if(auto signer = p.getSigner(true);
        Signature *signature = doc->prepareSignature(signer.get()))
    {
        cout << "Signature method: " << signature->signatureMethod() << endl
             << "Digest to sign:   " << signature->dataToSign() << endl
             << "Please enter signed digest in hex: " << endl;
        string signedData;
        cin >> signedData;
        signature->setSignatureValue(File::hexToBin(signedData));
        signature->extendSignatureProfile(signer.get());
        returnCode = validateSignature(signature);
    }
    doc->save();
    return returnCode;
}

static int tslcmd(int /*argc*/, char* /*argv*/[])
{
    int returnCode = EXIT_SUCCESS;
    string cache = CONF(TSLCache);
    auto certs = CONF(TSLCerts);
    for(const X509Cert &cert: certs)
        cout << "Signer: " << cert << endl;
    TSL t(File::path(cache, File::fileName(CONF(TSLUrl))));
    cout << "TSL: " << t.url() << endl
        << "         Type: " << t.type() << endl
        << "    Territory: " << t.territory() << endl
        << "     Operator: " << t.operatorName() << endl
        << "     Sequence: " << t.sequenceNumber() << endl
        << "       Issued: " << t.issueDate() << endl
        << "  Next update: " << t.nextUpdate() << endl;
    try {
        cout << "  Signature: ";
        t.validate(certs);
        cout << ToolConfig::GREEN << "VALID" << ToolConfig::RESET << endl;
    } catch(const Exception &e) {
        cout << ToolConfig::RED << "INVALID" << ToolConfig::RESET << endl;
        cout << "Caught Exception:" << endl << e;
        returnCode = EXIT_FAILURE;
    }
    for(const TSL::Service &s: t.services())
    {
        cout << " Service: " << s.name << endl;
        for(const X509Cert &x: s.certs)
            cout << "    Cert: " << x << endl;
    }
    cout << "Pointers: " << endl;
    for(const TSL::Pointer &p: t.pointers())
    {
        cout << "    Pointer: " << p.territory << endl
            << "        Url: " << p.location << endl;
        for(const X509Cert &cert: p.certs)
            cout << "     Signer: " << cert << endl;
        string path = cache + "/" + p.territory + ".xml";
        if(error_code ec; !fs::exists(fs::path(path), ec))
        {
            cout << "              TSL: missing" << endl;
            continue;
        }
        TSL tp(std::move(path));
        cout << "              TSL: " << p.location << endl
            << "             Type: " << tp.type() << endl
            << "        Territory: " << tp.territory() << endl
            << "         Operator: " << tp.operatorName() << endl
            << "         Sequence: " << tp.sequenceNumber() << endl
            << "           Issued: " << tp.issueDate() << endl
            << "      Next update: " << tp.nextUpdate() << endl;
        try {
            cout << "        Signature: ";
            tp.validate(p.certs);
            cout << ToolConfig::GREEN << "VALID" << ToolConfig::RESET << endl;
        } catch(const Exception &e) {
            cout << ToolConfig::RED << "INVALID" << ToolConfig::RESET << endl;
            cout << "Caught Exception:" << endl << e;
            returnCode = EXIT_FAILURE;
        }
        for(const TSL::Service &s: tp.services())
        {
            cout << "          Service: " << s.name << endl
                << "             Type: " << s.type << endl;
            for(const X509Cert &x: s.certs)
                cout << "             Cert: " << x << endl;
        }
    }
    return returnCode;
}

/**
 * Executes digidoc demonstration application.
 *
 * @param argc number of command line arguments.
 * @param argv command line arguments.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
int main(int argc, char *argv[]) try
{
#ifdef _WIN32
    struct codepage_scope {
        ~codepage_scope() noexcept { SetConsoleOutputCP(oldOutputCP); }
        UINT oldOutputCP;
    };
    codepage_scope scope{GetConsoleOutputCP()};
    SetConsoleOutputCP(CP_UTF8);
#endif
    printf("Version\n");
    printf("  digidoc-tool version: %s\n", VERSION_STR);
    printf("  libdigidocpp version: %s\n", version().c_str());

    ToolConfig *conf = nullptr;
    Conf::init(conf = new ToolConfig(argc, argv));
    stringstream info;
    info << "digidoc-tool/" << VERSION_STR << " (";
#ifdef _WIN32
    info << "Windows";
#elif __APPLE__
    info << "OS X";
#else
    info << "Unknown";
#endif
    info << ")";
    digidoc::initialize("digidoc-tool", info.str());
    atexit(&digidoc::terminate);

    if(argc < 2)
    {
        printUsage(argv[0]);
        return EXIT_SUCCESS;
    }

    string_view command(argv[1]);
    if(command == "open")
        return open(argc, argv);
    if(command == "create")
        return create(*conf, argv[0]);
    if(command == "add")
        return add(*conf, argv[0]);
    if(command == "createBatch")
        return createBatch(*conf, argv[0]);
    if(command == "remove")
        return remove(argc, argv);
    if(command == "sign")
        return sign(*conf, argv[0]);
    if(command == "extend")
        return extend(argc, argv);
    if(command == "websign")
        return websign(*conf, argv[0]);
    if(command == "tsl")
        return tslcmd(argc, argv);
    if(command == "version")
        return EXIT_SUCCESS;
    return printUsage(argv[0]);
} catch(const Exception &e) {
    cout << "Caught Exception:" << endl << e;
    return EXIT_FAILURE;
} catch(const std::exception &e) {
    cout << "Caught Exception:" << endl << e.what();
    return EXIT_FAILURE;
}
