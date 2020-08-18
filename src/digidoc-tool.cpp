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

#include "log.h"
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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

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

namespace std
{
static ostream &operator<<(ostream &os, const X509Cert &cert)
{
    return os << cert.subjectName("CN");
}

static ostream &operator<<(ostream &os, const vector<unsigned char> &data)
{
    os << hex << uppercase << setfill('0');
    for(const unsigned char &i: data)
        os << setw(2) << static_cast<int>(i) << ' ';
    return os << dec << nouppercase << setfill(' ');
}

static ostream &operator<<(ostream &os, const Exception::ExceptionCode code)
{
    switch(code)
    {
    case Exception::General: os << "General"; break;
    case Exception::CertificateIssuerMissing: os << "CertificateIssuerMissing"; break;
    case Exception::CertificateRevoked: os << "CertificateRevoked"; break;
    case Exception::CertificateUnknown: os << "CertificateUnknown"; break;
    case Exception::OCSPResponderMissing: os << "OCSPResponderMissing"; break;
    case Exception::OCSPCertMissing: os << "OCSPCertMissing"; break;
    case Exception::OCSPTimeSlot: os << "OCSPTimeSlot"; break;
    case Exception::OCSPRequestUnauthorized: os << "OCSPRequestUnauthorized"; break;
    case Exception::PINCanceled: os << "PINCanceled"; break;
    case Exception::PINFailed: os << "PINFailed"; break;
    case Exception::PINIncorrect: os << "PINIncorrect"; break;
    case Exception::PINLocked: os << "PINLocked"; break;
    case Exception::ReferenceDigestWeak: os << "ReferenceDigestWeak"; break;
    case Exception::SignatureDigestWeak: os << "SignatureDigestWeak"; break;
    case Exception::DataFileNameSpaceWarning: os << "DataFileNameSpaceWarning"; break;
    case Exception::IssuerNameSpaceWarning: os << "IssuerNameSpaceWarning"; break;
    case Exception::ProducedATLateWarning: os << "ProducedATLateWarning"; break;
    case Exception::MimeTypeWarning: os << "MimeTypeWarning"; break;
    default: os << code;
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
}

/**
 * For demonstration purpose overwrites certificate selection to print out all
 * the certificates available on ID-Card.
 */
class ConsolePinSigner : public PKCS11Signer
{
public:
    ConsolePinSigner(const string &driver, const string &pin): PKCS11Signer(driver)
    {
        setPin(pin);
    }

private:
    string pin(const X509Cert &certificate) const override;
    X509Cert selectSigningCertificate(const vector<X509Cert> &certificates) const override
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

class ToolConfig: public XmlConfCurrent
{
public:
    enum Warning {
        WError,
        WWarning,
        WIgnore
    };

    ToolConfig(int argc, char *argv[]);
    int logLevel() const override { return _logLevel; }
    string logFile() const override { return _logFile; }
    string digestUri() const override { return uri; }
    string signatureDigestUri() const override { return siguri; }
    bool TSLAllowExpired() const override { return expired; }
    vector<X509Cert> TSLCerts() const override { return tslcerts; }
    string TSUrl() const override { return tsurl; }
    string TSLUrl() const override { return tslurl; }

    unique_ptr<Signer> getSigner(bool getwebsigner = false) const;
    static string decodeParameter(const string &param)
    {
        if(param.empty())
            return string();
#ifdef _WIN32
        int len = MultiByteToWideChar(CP_ACP, 0, param.data(), int(param.size()), nullptr, 0);
        wstring out(size_t(len), 0);
        len = MultiByteToWideChar(CP_ACP, 0, param.data(), int(param.size()), &out[0], len);
        return File::decodeName(out);
#else
        return File::decodeName(param);
#endif
    }

    // Config
    int _logLevel;
    bool expired = false;
    vector<X509Cert> tslcerts;
    string _logFile, tsurl, tslurl, uri, siguri;

    // Params
    string path, profile, pkcs11, pkcs12, pin, city, street, state, postalCode, country, cert;
    vector<unsigned char> thumbprint;
    vector<pair<string,string> > files;
    vector<string> roles;
    bool cng = true, selectFirst = false, doSign = true, dontValidate = false, XAdESEN = false;
    static const map<string,string> profiles;
    static string RED, GREEN, YELLOW, RESET;
};



/**
 * Prints application usage.
 */
static void printUsage(const char *executable)
{
    cout
    << "Usage: " << executable << " COMMAND [OPTIONS] FILE" << endl << endl
    << "  Command create:" << endl
    << "    Example: " << executable << " create --file=file1.txt --file=file2.txt demo-container.asice" << endl
    << "    Available options:" << endl
    << "      --file=        - The option can occur multiple times. File(s) to be signed" << endl
    << "      --mime=        - can be after --file parameter. Default value is application/octet-stream" << endl
    << "      --dontsign     - Don't sign the newly created container." << endl
    << "      for additional options look sign command" << endl << endl
    << "  Command createBatch:" << endl
    << "    Example: " << executable << " createBatch folder/content/to/sign" << endl
    << "    Available options:" << endl
    << "      for additional options look sign command" << endl << endl
    << "  Command open:" << endl
    << "    Example: " << executable << " open container-file.asice" << endl
    << "    Available options:" << endl
    << "      --warnings=(ignore,warning,error) - warning handling" << endl
    << "      --policy=(POLv1,POLv2) - Signature Validation Policy (default POLv2)" << endl
    << "                               http://open-eid.github.io/SiVa/siva/appendix/validation_policy/" << endl
    << "      --extractAll[=path] - extracts documents (to path when provided)" << endl << endl
    << "  Command add:" << endl
    << "    Example: " << executable << " add --file=file1.txt container-file.asice" << endl
    << "    Available options:" << endl
    << "      --file=        - The option can occur multiple times. File(s) to be added to the container" << endl
    << "      --mime=        - can be after --file parameter. Default value is application/octet-stream" << endl << endl
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
    << "      --profile=     - signature profile, TM, time-mark, TS, time-stamp" << endl
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
    << "      --pkcs11[=]    - default is " << (CONF(PKCS11Driver)) << ". Path of PKCS11 driver." << endl
    << "      --pkcs12=      - pkcs12 signer certificate (use --pin for password)" << endl
    << "      --pin=         - default asks pin from prompt" << endl
    << "      --sha(224,256,384,512) - set default digest method (default sha256)" << endl
    << "      --sigsha(224,256,384,512) - set default digest method (default sha256)" << endl
    << "      --tsurl         - option to change TS URL (default " << (CONF(TSUrl)) << ")" << endl
    << "      --dontValidate  - Don't validate container" << endl << endl
    << "  All commands:" << endl
    << "      --nocolor       - Disable terminal colors" << endl
    << "      --loglevel=[0,1,2,3,4] - Log level 0 - none, 1 - error, 2 - warning, 3 - info, 4 - debug" << endl
    << "      --logfile=      - File to log, empty to console" << endl;
}

const map<string,string> ToolConfig::profiles = {
    {"BES", "BES"},
    {"EPES", "EPES"},
    {"TM", "time-mark"},
    {"TS", "time-stamp"},
    {"TMA", "time-mark-archive"},
    {"TSA", "time-stamp-archive"},
    {"time-mark", "time-mark"},
    {"time-stamp", "time-stamp"},
    {"time-mark-archive", "time-mark-archive"},
    {"time-stamp-archive", "time-stamp-archive"},
};
string ToolConfig::RED = "\033[31m";
string ToolConfig::GREEN = "\033[32m";
string ToolConfig::YELLOW = "\033[33m";
string ToolConfig::RESET = "\033[0m";

ToolConfig::ToolConfig(int argc, char *argv[])
    : _logLevel(XmlConfCurrent::logLevel())
    , expired(XmlConfCurrent::TSLAllowExpired())
    , tslcerts(XmlConfCurrent::TSLCerts())
    , _logFile(XmlConfCurrent::logFile())
    , tsurl(XmlConfCurrent::TSUrl())
    , tslurl(XmlConfCurrent::TSLUrl())
    , uri(XmlConfCurrent::digestUri())
    , siguri(XmlConfCurrent::signatureDigestUri())
{
    for(int i = 2; i < argc; i++)
    {
        string arg(decodeParameter(argv[i]));
        if(arg.find("--profile=") == 0)
        {
            profile = arg.substr(10);
            size_t pos = profile.find('.');
            profile = profiles.at(profile.substr(0, pos)) + (pos == string::npos ? string() : profile.substr(pos));
        }
        else if(arg.find("--file=") == 0)
        {
            string arg2(i+1 < argc ? decodeParameter(argv[i+1]) : string());
            files.emplace_back(pair<string,string>(arg.substr(7),
                arg2.find("--mime=") == 0 ? arg2.substr(7) : "application/octet-stream"));
        }
#ifdef _WIN32
        else if(arg == "--cng") cng = true;
        else if(arg == "--selectFirst") selectFirst = true;
        else if(arg.find("--thumbprint=") == 0) thumbprint = File::hexToBin(arg.substr(arg.find('=') + 1));
#endif
        else if(arg.find("--pkcs11") == 0)
        {
            cng = false;
            if(arg.find('=') != string::npos)
                pkcs11 = arg.substr(arg.find('=') + 1);
        }
        else if(arg.find("--pkcs12=") == 0)
        {
            cng = false;
            pkcs12 = arg.substr(9);
        }
        else if(arg == "--dontValidate") dontValidate = true;
        else if(arg == "--XAdESEN") XAdESEN = true;
        else if(arg.find("--pin=") == 0) pin = arg.substr(6);
        else if(arg.find("--cert=") == 0) cert = arg.substr(7);
        else if(arg.find("--city=") == 0) city = arg.substr(7);
        else if(arg.find("--street=") == 0) street = arg.substr(9);
        else if(arg.find("--state=") == 0) state = arg.substr(8);
        else if(arg.find("--postalCode=") == 0) postalCode = arg.substr(13);
        else if(arg.find("--country=") == 0) country = arg.substr(10);
        else if(arg.find("--role=") == 0) roles.push_back(arg.substr(7));
        else if(arg == "--sha224") uri = URI_SHA224;
        else if(arg == "--sha256") uri = URI_SHA256;
        else if(arg == "--sha384") uri = URI_SHA384;
        else if(arg == "--sha512") uri = URI_SHA512;
        else if(arg == "--sigsha224") siguri = URI_SHA224;
        else if(arg == "--sigsha256") siguri = URI_SHA256;
        else if(arg == "--sigsha384") siguri = URI_SHA384;
        else if(arg == "--sigsha512") siguri = URI_SHA512;
        else if(arg.find("--tsurl") == 0) tsurl = arg.substr(8);
        else if(arg.find("--tslurl=") == 0) tslurl = arg.substr(9);
        else if(arg.find("--tslcert=") == 0) tslcerts = { X509Cert(arg.substr(10)) };
        else if(arg == "--TSLAllowExpired") expired = true;
        else if(arg == "--dontsign") doSign = false;
        else if(arg == "--nocolor") RED = GREEN = YELLOW = RESET = string();
        else if(arg.find("--loglevel=") == 0) _logLevel = stoi(arg.substr(11));
        else if(arg.find("--logfile=") == 0) _logFile = arg.substr(10);
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
    {
        class WebSigner: public Signer
        {
        public:
            WebSigner(X509Cert cert): _cert(move(cert)) {}
            X509Cert cert() const override { return _cert; }
            vector<unsigned char> sign(const string & /*method*/, const vector<unsigned char> & /*digest*/) const override
            {
                THROW("Not implemented");
            }
            X509Cert _cert;
        };
        signer.reset(new WebSigner(X509Cert(cert, X509Cert::Pem)));
    }
#ifdef _WIN32
    else if(cng)
    {
        WinSigner *win = new WinSigner(pin, selectFirst);
        win->setThumbprint(thumbprint);
        signer.reset(win);
    }
    else
#endif
    if(!pkcs12.empty())
        signer.reset(new PKCS12Signer(pkcs12, pin));
    else
        signer.reset(new ConsolePinSigner(pkcs11, pin));
    signer->setENProfile(XAdESEN);
    signer->setSignatureProductionPlaceV2(city, street, state, postalCode, country);
    signer->setSignerRoles(roles);
    signer->setProfile(profile);
    return signer;
}

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
        if(warning == ToolConfig::WError)
        {
            cout << ToolConfig::RED << "FAILED (Warning)";
            returnCode = EXIT_FAILURE;
        }
        else
            cout << ToolConfig::YELLOW << "OK (Warning)";
        break;
    case Signature::Validator::NonQSCD:
        if(warning == ToolConfig::WError)
        {
            cout << ToolConfig::RED << "FAILED (NonQSCD)";
            returnCode = EXIT_FAILURE;
        }
        else
            cout << ToolConfig::YELLOW << "OK (NonQSCD)";
        break;
    case Signature::Validator::Test:
        if(warning == ToolConfig::WError)
        {
            cout << ToolConfig::RED << "OK (Test)";
            returnCode = EXIT_FAILURE;
        }
        else
            cout << ToolConfig::YELLOW << "OK (Test)";
        break;
    case Signature::Validator::Unknown:
        cout << ToolConfig::RED << "FAILED (Unknown)";
        returnCode = EXIT_FAILURE;
        break;
    case Signature::Validator::Invalid:
        cout << ToolConfig::RED << "FAILED (Invalid)";
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
    string path, extractPath, policy;
    int returnCode = EXIT_SUCCESS;

    // Parse command line arguments.
    for(int i = 2; i < argc; i++)
    {
        string arg(ToolConfig::decodeParameter(argv[i]));
        if(arg == "--list")
            continue;
        if(arg.find("--warnings=") == 0)
        {
            if(arg.substr(11, 6) == "ignore") reportwarnings = ToolConfig::WIgnore;
            if(arg.substr(11, 5) == "error") reportwarnings = ToolConfig::WError;
        }
        else if(arg.find("--extractAll") == 0)
        {
            extractPath = ".";
            size_t pos = arg.find('=');
            if(pos != string::npos)
                extractPath = arg.substr(pos + 1);
        }
        else if(arg.find("--policy=") == 0)
            policy = arg.substr(9);
        else
            path = arg;
    }

    if(path.empty())
    {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    try {
        if(!extractPath.empty())
        {
            cout << "Extracting documents: " << endl;
            for(const DataFile *file: doc->dataFiles())
            {
                try {
                    string dst = extractPath.empty() ? file->fileName() : extractPath + "/" + file->fileName();
                    file->saveAs(dst);
                    cout << "  Document(" << file->mediaType() << ") extracted to " << dst << " (" << file->fileSize() << " bytes)" << endl;
                } catch(const Exception &e) {
                    cout << "  Document " << file->fileName() << " extraction: " << ToolConfig::RED << "FAILED" << ToolConfig::RESET << endl;
                    cout << "  Exception:" << endl << e;
                    return EXIT_FAILURE;
                }
            }
            return EXIT_SUCCESS;
        }

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
            cout << "  Signature " << pos++ << " (" << s->profile().c_str() << "):" << endl;
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
                << "    TS time: " << s->TimeStampTime() << endl
                << "    TSA: " << s->ArchiveTimeStampCertificate() << endl
                << "    TSA time: " << s->ArchiveTimeStampTime() << endl;
        }
    } catch(const Exception &e) {
        cout << "Caught Exception:" << endl << e;
        returnCode = EXIT_FAILURE;
    }

    return returnCode;
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
    string path;
    for(int i = 2; i < argc; i++)
    {
        string arg(ToolConfig::decodeParameter(argv[i]));
        if(arg.find("--document=") == 0)
            documents.push_back(atoi(arg.substr(11).c_str()));
        else if(arg.find("--signature=") == 0)
            signatures.push_back(atoi(arg.substr(12).c_str()));
        else
            path = arg;
    }

    if(path.empty())
    {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    try {
        if(!signatures.empty())
        {
            sort(signatures.begin(), signatures.end(), greater<unsigned int>());
            for(vector<unsigned int>::const_iterator i = signatures.begin(); i != signatures.end(); ++i)
            {
                cout << "  Removing signature " << *i << endl;
                doc->removeSignature(*i);
            }
        }

        if(!documents.empty())
        {
            sort(documents.begin(), documents.end(), greater<unsigned int>());
            for(vector<unsigned int>::const_iterator i = documents.begin(); i != documents.end(); ++i)
            {
                cout << "  Removing document " << *i << endl;
                doc->removeDataFile(*i);
            }
        }

        doc->save();

        return EXIT_SUCCESS;
    } catch(const Exception &e) { cout << "Caught Exception:" << endl << e; }

    return EXIT_FAILURE;
}


/**
 * Add items to the container.
 *
 * @param p ToolConfig object.
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int add(const ToolConfig &p, char *program)
{
    if(p.path.empty() || p.files.empty())
    {
        printUsage(program);
        return EXIT_FAILURE;
    }

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    try {
        for(const pair<string,string> &file: p.files)
            doc->addDataFile(file.first, file.second);

        doc->save();

        return EXIT_SUCCESS;
    } catch(const Exception &e) { cout << "Caught Exception:" << endl << e; }

    return EXIT_FAILURE;
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
    {
        if(dontValidate)
            return EXIT_SUCCESS;
        try {
            signature->validate();
            cout << "    Validation: " << ToolConfig::GREEN << "OK" << ToolConfig::RESET << endl;
        } catch(const Exception &e) {
            cout << "    Validation: " << ToolConfig::RED << "FAILED" << ToolConfig::RESET << endl;
            cout << "     Exception:" << endl << e;
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

/**
 * Create new container and sign unless explicitly requested not to sign
 *
 * @param p ToolConfig object.
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int create(const ToolConfig &p, char *program)
{
    if(p.path.empty() || p.files.empty())
    {
        printUsage(program);
        return EXIT_FAILURE;
    }

    unique_ptr<Container> doc;
    try {
        doc = Container::createPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    try {
        for(const pair<string,string> &file: p.files)
            doc->addDataFile(file.first, file.second);

        int returnCode = EXIT_SUCCESS;
        if(p.doSign)
            returnCode = signContainer(doc.get(), p.getSigner(), p.dontValidate);
        doc->save();
        return returnCode;
    } catch(const Exception &e) {
        cout << "Caught Exception:" << endl << e;
        return EXIT_FAILURE;
    }
}

/**
 * Create new container.
 *
 * @param p ToolConfig object
 * @param program command line argument.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
static int createBatch(const ToolConfig &p, char *program)
{
    if(p.path.empty())
    {
        printUsage(program);
        return EXIT_FAILURE;
    }

    unique_ptr<Signer> signer;
    try {
        signer = p.getSigner();
    } catch(const Exception &e) {
        cout << "Caught Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    int returnCode = EXIT_SUCCESS;
    for(const string &file: File::listFiles(p.path))
    {
        if(file.compare(file.size() - 6, 6, ".asice") == 0)
            continue;
        cout << "Signing file: " << file << endl;
        try {
            unique_ptr<Container> doc = Container::createPtr(file + ".asice");
            doc->addDataFile(file, "application/octet-stream");
            if(signContainer(doc.get(), signer, p.dontValidate) == EXIT_FAILURE)
                returnCode = EXIT_FAILURE;
            doc->save();
        } catch(const Exception &e) {
            cout << "  Exception:" << endl << e;
            returnCode = EXIT_FAILURE;
        }
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
static int sign(const ToolConfig &p, char *program)
{
    if(p.path.empty())
    {
        printUsage(program);
        return EXIT_FAILURE;
    }

    unique_ptr<Container> doc;
    try {
        doc = Container::openPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    try {
        int returnCode = signContainer(doc.get(), p.getSigner(), p.dontValidate);
        doc->save();
        return returnCode;
    } catch(const Exception &e) {
        cout << "Caught Exception:" << endl << e;
        return EXIT_FAILURE;
    }
}

static int websign(const ToolConfig &p, char *program)
{
    if(p.path.empty())
    {
        printUsage(program);
        return EXIT_FAILURE;
    }

    unique_ptr<Container> doc;
    try {
        doc = Container::createPtr(p.path);
    } catch(const Exception &e) {
        cout << "Failed to parse container" << endl;
        cout << "  Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    int returnCode = EXIT_SUCCESS;
    try {
        for(const pair<string,string> &file: p.files)
            doc->addDataFile(file.first, file.second);

        if(Signature *signature = doc->prepareSignature(p.getSigner(true).get()))
        {
            cout << "Signature method: " << signature->signatureMethod() << endl
                 << "Digest to sign:   " << signature->dataToSign() << endl
                 << "Please enter signed digest in hex: " << endl;
            string signedData;
            cin >> signedData;
            signature->setSignatureValue(File::hexToBin(signedData));
            cout << "Test" << File::hexToBin(signedData);
            signature->extendSignatureProfile(p.profile);
            if(validateSignature(signature) == EXIT_FAILURE)
                returnCode = EXIT_FAILURE;
        }
        doc->save();
    } catch(const Exception &e) {
        cout << "Caught Exception:" << endl << e;
        returnCode = EXIT_FAILURE;
    }

    return returnCode;
}

static int tslcmd(int /*argc*/, char* /*argv*/[])
{
    int returnCode = EXIT_SUCCESS;
    string cache = CONF(TSLCache);
    TSL t({});
    cout << "TSL: " << t.url() << endl
        << "         Type: " << t.type() << endl
        << "    Territory: " << t.territory() << endl
        << "     Operator: " << t.operatorName() << endl
        << "       Issued: " << t.issueDate() << endl
        << "  Next update: " << t.nextUpdate() << endl
        << "Pointers:" << endl;
    try {
        cout << "  Signature: ";
        t.validate(CONF(TSLCerts));
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
    for(const TSL::Pointer &p: t.pointers())
    {
        cout << "    Pointer: " << p.territory << endl
            << "        Url: " << p.location << endl;
        for(const X509Cert &cert: p.certs)
            cout << "     Signer: " << cert << endl;
        TSL tp(cache + "/" + p.territory + ".xml");
        cout << "    TSL: " << p.location << endl
            << "             Type: " << tp.type() << endl
            << "        Territory: " << tp.territory() << endl
            << "         Operator: " << tp.operatorName() << endl
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
            cout << "          Service: " << s.name << endl;
            for(const X509Cert &x: s.certs)
                cout << "             Cert: " << x << endl;
        }
    };
    return returnCode;
}

/**
 * Executes digidoc demonstration application.
 *
 * @param argc number of command line arguments.
 * @param argv command line arguments.
 * @return EXIT_FAILURE (1) - failure, EXIT_SUCCESS (0) - success
 */
int main(int argc, char *argv[])
{
    printf("Version\n");
    printf("  digidoc-tool version: %s\n", FILE_VER_STR);
    printf("  libdigidocpp version: %s\n", version().c_str());

    ToolConfig *conf = nullptr;
    try {
        Conf::init(conf = new ToolConfig(argc, argv));
        stringstream info;
        info << "digidoc-tool/" << FILE_VER_STR << " (";
#ifdef _WIN32
        info << "Windows";
#elif __APPLE__
        info << "OS X";
#else
        info << "Unknown";
#endif
        info << ")";
        digidoc::initialize("digidoc-tool", info.str());
    } catch(const Exception &e) {
        cout << "Failed to initalize library:" << endl;
        cout << "Caught Exception:" << endl << e;
        return EXIT_FAILURE;
    }

    if(argc < 2)
    {
        printUsage(argv[0]);
        digidoc::terminate();
        return EXIT_SUCCESS;
    }

    int returnCode = EXIT_FAILURE;
    try {
        string command(argv[1]);
        if(command == "open")
            returnCode = open(argc, argv);
        else if(command == "create")
            returnCode = create(*conf, argv[0]);
        else if(command == "add")
            returnCode = add(*conf, argv[0]);
        else if(command == "createBatch")
            returnCode = createBatch(*conf, argv[0]);
        else if(command == "remove")
            returnCode = remove(argc, argv);
        else if(command == "sign")
            returnCode = sign(*conf, argv[0]);
        else if(command == "websign")
            returnCode = websign(*conf, argv[0]);
        else if(command == "tsl")
            returnCode = tslcmd(argc, argv);
        else if(command == "version")
            returnCode = EXIT_SUCCESS;
        else
            printUsage(argv[0]);
    } catch(const Exception &e) {
        cout << "Caught Exception:" << endl << e;
        returnCode = EXIT_FAILURE;
    }

    digidoc::terminate();

    return returnCode;
}
