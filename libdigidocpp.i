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

// digidocpp.i - SWIG interface for libdigidocpp library

// TODO: Add %newobject to stuff that is known to return
//       pointers to specifically allocated objects
//       http://www.swig.org/Doc1.3/Customization.html

// TODO: Look through the code to see if anything needs typemaps.i
//       and %apply to fix functions that use pointer arguments for output

%module digidoc
%{

#include "Container.h"
#include "DataFile.h"
#include "Exception.h"
#include "log.h"
#include "Signature.h"
#include "XmlConf.h"
#include "crypto/PKCS11Signer.h"
#include "crypto/PKCS12Signer.h"
#include "crypto/X509Cert.h"
#ifdef _WIN32
#include "crypto/WinSigner.h"
#endif
#include "util/File.h"

#include <vector>

class DigiDocConf: public digidoc::XmlConfCurrent
{
public:
    DigiDocConf(std::string _cache, std::string _tslUrl = std::string(), std::vector<X509Cert> _tslCerts = std::vector<X509Cert>())
        : digidoc::XmlConfCurrent(), cache(std::move(_cache)), tslUrl(std::move(_tslUrl)), tslCerts(std::move(_tslCerts)) {}
    int logLevel() const override { return 4; }
    std::string logFile() const override { return cache.empty() ? digidoc::XmlConfCurrent::logFile() : cache + "/digidocpp.log"; }
    std::string PKCS12Cert() const override
    {
        return cache.empty() ? digidoc::XmlConfCurrent::PKCS12Cert() :
            cache + "/" + digidoc::util::File::fileName(digidoc::XmlConfCurrent::PKCS12Cert());
    }
    std::string TSLCache() const override { return cache.empty() ? digidoc::XmlConfCurrent::TSLCache() : cache; }
    std::vector<X509Cert> TSLCerts() const override { return tslCerts.empty() ? digidoc::XmlConfCurrent::TSLCerts() : tslCerts; };
    std::string TSLUrl() const override { return tslUrl.empty() ? digidoc::XmlConfCurrent::TSLUrl() : tslUrl; }
    std::string xsdPath() const override { return cache.empty() ? digidoc::XmlConfCurrent::xsdPath() : cache; }

private:
    std::string cache, tslUrl;
    std::vector<X509Cert> tslCerts;
};

class WebSignerPrivate: public digidoc::Signer
{
public:
    WebSignerPrivate(const digidoc::X509Cert &cert): _cert(cert) {}

private:
    digidoc::X509Cert cert() const override { return _cert; }
    std::vector<unsigned char> sign(const std::string &, const std::vector<unsigned char> &) const override
    {
        THROW("Not implemented");
    }

    digidoc::X509Cert _cert;
};

static std::string parseException(const digidoc::Exception &e) {
    std::string msg = e.msg();
    for(const digidoc::Exception &ex: e.causes())
        msg += "\n" + parseException(ex);
    return msg;
}

namespace digidoc {
    static void initializeLibWithTSL(const std::string &appName, const std::string &path, const std::string &tslUrl = std::string(), const std::vector<unsigned char> &tslCert = std::vector<unsigned char>())
    {
        if(!Conf::instance())
        {
            std::vector<X509Cert> tslCerts;
            if(!tslCert.empty())
                tslCerts = { X509Cert(tslCert, X509Cert::Der) };
            digidoc::Conf::init(new DigiDocConf(path, tslUrl, tslCerts));
        }
        digidoc::initialize(appName);
    }
    static void initializeLib(const std::string &appName, const std::string &path)
    {
        initializeLibWithTSL(appName, path);
    }
}

#ifdef SWIGCSHARP
extern "C"
{
    SWIGEXPORT unsigned char* SWIGSTDCALL ByteVector_data(void *ptr) {
        return static_cast<std::vector<unsigned char>*>(ptr)->data();
    }
    SWIGEXPORT int SWIGSTDCALL ByteVector_size(void *ptr) {
       return static_cast<std::vector<unsigned char>*>(ptr)->size();
    }
    SWIGEXPORT void* SWIGSTDCALL ByteVector_to(unsigned char *data, int size) {
       return new std::vector<unsigned char>(data, data + size);
    }
}
#endif
%}

%pragma(csharp) imclasscode=%{
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_data")]
  public static extern global::System.IntPtr ByteVector_data(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_size")]
  public static extern int ByteVector_size(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_to")]
  public static extern global::System.IntPtr ByteVector_to(
    [global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPArray)]byte[] data, int size);
%}

#ifdef SWIGJAVA
%typemap(in) std::vector<unsigned char> %{
    jbyte *$input_ptr = jenv->GetByteArrayElements($input, NULL);
    jsize $input_size = jenv->GetArrayLength($input);
    std::vector<unsigned char> $1_data($input_ptr, $input_ptr+$input_size);
    $1 = &$1_data;
    jenv->ReleaseByteArrayElements($input, $input_ptr, JNI_ABORT);
%}
%typemap(out) std::vector<unsigned char> %{
    jresult = jenv->NewByteArray((&result)->size());
    jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte*)(&result)->data());
%}
#endif
%typemap(jtype) std::vector<unsigned char> "byte[]"
%typemap(jstype) std::vector<unsigned char> "byte[]"
%typemap(jni) std::vector<unsigned char> "jbyteArray"
%typemap(javain) std::vector<unsigned char> "$javainput"
%typemap(javaout) std::vector<unsigned char> {
    return $jnicall;
  }
#ifdef SWIGCSHARP
%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(csin,
		 pre= "	global::System.IntPtr cPtr$csinput = (global::System.IntPtr)digidocPINVOKE.ByteVector_to($csinput, $csinput.Length);
	global::System.Runtime.InteropServices.HandleRef handleRef$csinput = new global::System.Runtime.InteropServices.HandleRef(this, cPtr$csinput);"
) std::vector<unsigned char> "handleRef$csinput"
%typemap(csout, excode=SWIGEXCODE) std::vector<unsigned char> {
  global::System.IntPtr data = $imcall;$excode
  byte[] result = new byte[$modulePINVOKE.ByteVector_size(data)];
  global::System.Runtime.InteropServices.Marshal.Copy($modulePINVOKE.ByteVector_data(data), result, 0, result.Length);
  return result;
}
#endif
%apply std::vector<unsigned char> { std::vector<unsigned char> const & };

%exception %{
 try {
   $action
 } catch (const digidoc::Exception &e) {
#ifdef SWIGJAVA
   SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, parseException(e).c_str());
#elif defined(SWIGCSHARP)
   SWIG_CSharpSetPendingException(SWIG_CSharpApplicationException, parseException(e).c_str());
#endif
   return $null;
 }
%}

// Handle DigiDoc Export declarations
#define EXP_DIGIDOC
#define DEPRECATED_DIGIDOCPP

#ifdef SWIGPHP
// Broken in PHP :(
%feature("notabstract") digidoc::Signature;  // Breaks PHP if abstract
#endif

#ifdef SWIGJAVA
%ignore digidoc::initialize;
#endif
// ignore X509Cert and implement later cert as ByteVector
%ignore digidoc::Conf::TSLCerts;
%ignore digidoc::ConfV2::verifyServiceCert;
%ignore digidoc::XmlConfV2::verifyServiceCert;
%ignore digidoc::Signer::cert;
%ignore digidoc::Signature::signingCertificate;
%ignore digidoc::Signature::OCSPCertificate;
%ignore digidoc::Signature::TimeStampCertificate;
%ignore digidoc::Signature::ArchiveTimeStampCertificate;
// hide stream methods
%ignore digidoc::DataFile::saveAs(std::ostream &os) const;
%ignore digidoc::Container::addAdESSignature(std::istream &signature);
%ignore digidoc::Container::addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
// Other
%ignore digidoc::Conf::libdigidocConf;
%ignore digidoc::Conf::certsPath;
%ignore digidoc::Signature::Validator::warnings;
%ignore digidoc::Signature::OCSPNonce;

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
// Expose selected DigiDoc classes
%include "Conf.h"
%include "Container.h"
%include "DataFile.h"
%include "Signature.h"
%include "XmlConf.h"
%include "crypto/Signer.h"
%include "crypto/PKCS12Signer.h"
%include "crypto/PKCS11Signer.h"
#ifdef SWIGCSHARP
%include "crypto/WinSigner.h"
#endif

%template(StringVector) std::vector<std::string>;
%template(DataFiles) std::vector<digidoc::DataFile*>;
%template(Signatures) std::vector<digidoc::Signature*>;

namespace digidoc {
    static void initializeLib(const std::string &appName, const std::string &path)
    {
        initializeLib(appName, path);
    }
    static void initializeLibWithTSL(const std::string &appName, const std::string &path, const std::string &tslUrl, const std::vector<unsigned char> &tslCert)
    {
        initializeLib(appName, path, tslUrl, tslCert);
    }
}

// override X509Cert methods to return byte array
%extend digidoc::Signer {
    std::vector<unsigned char> cert() const
    {
        return $self->cert();
    }
}
%extend digidoc::Signature {
    std::vector<unsigned char> signingCertificateDer() const
    {
        return $self->signingCertificate();
    }
    std::vector<unsigned char> OCSPCertificateDer() const
    {
        return $self->OCSPCertificate();
    }
    std::vector<unsigned char> TimeStampCertificateDer() const
    {
        return $self->TimeStampCertificate();
    }
    std::vector<unsigned char> ArchiveTimeStampCertificateDer() const
    {
        return $self->ArchiveTimeStampCertificate();
    }
}

%extend digidoc::Container {
    Signature* prepareWebSignature(const std::vector<unsigned char> &cert, const std::string &profile = "",
                                   const std::vector<std::string> &roles = std::vector<std::string>(),
                                   const std::string &city = "", const std::string &state = "",
                                   const std::string &postalCode = "", const std::string &country = "")
    {
        WebSignerPrivate signer(X509Cert(cert, X509Cert::Der));
        signer.setProfile(profile);
        signer.setSignatureProductionPlace(city, state, postalCode, country);
        signer.setSignerRoles(roles);
        return $self->prepareSignature(&signer);
    }
}

// Target language specific functions
#ifdef SWIGPHP
%minit %{ %}
%mshutdown %{ %}
%rinit %{
    digidoc::initialize();
%}
%rshutdown %{
    digidoc::terminate();
%}
%pragma(php) phpinfo="
  zend_printf(\"DigiDoc libraries support\\n\");
  php_info_print_table_start();
  php_info_print_table_header(2, \"Directive\", \"Value\");
  php_info_print_table_row(2, \"DigiDoc support\", \"enabled\");
  php_info_print_table_end();
"
#endif // SWIGPHP
