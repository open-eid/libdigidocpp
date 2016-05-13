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

// digidoc.i - SWIG interface for DigiDoc C++ library

// TODO: Find a way to tap into PHP-s RINIT and RSHUTDOWN
//       (request init/shutdown), MSHUTDOWN and MINFO would
//       be nice too. Also investigate phppointers.i

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

#include <vector>

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

#ifdef SWIGJAVA
class DigiDocConf: public digidoc::XmlConfCurrent
{
public:
    DigiDocConf(const std::string &_cache)
        : digidoc::XmlConfCurrent(), cache(_cache), xsd(_cache) {}
    std::string TSLCache() const { return cache; }
    std::string xsdPath() const { return xsd; }

private:
    std::string cache, xsd;
};

extern "C"
{
SWIGEXPORT void JNICALL Java_ee_ria_libdigidocpp_digidocJNI_initJava(JNIEnv *jenv, jclass jcls, jstring path) {
  (void)jcls;
  if(!path) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return;
  }

  const char *path_pstr = (const char *)jenv->GetStringUTFChars(path, 0); 
  if (!path_pstr)
    return;
  std::string path_str(path_pstr);
  jenv->ReleaseStringUTFChars(path, path_pstr); 

  try {
    digidoc::Conf::init(new DigiDocConf(path_str));
    digidoc::initialize();
  } catch (const digidoc::Exception &e) {
    SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, parseException(e).c_str());
    return;
  }
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
%native(initJava) void initJava(char *);

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
%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(csin,
		 pre= "	global::System.IntPtr cPtr$csinput = (global::System.IntPtr)digidocPINVOKE.ByteVector_to($csinput, $csinput.Length);
	global::System.Runtime.InteropServices.HandleRef handleRef$csinput = new global::System.Runtime.InteropServices.HandleRef(this, cPtr$csinput);"
) std::vector<unsigned char> "handleRef$csinput"
%typemap(csout, excode=SWIGEXCODE) std::vector<unsigned char>
{
  global::System.IntPtr data = $imcall;$excode
  byte[] result = new byte[$modulePINVOKE.ByteVector_size(data)];
  global::System.Runtime.InteropServices.Marshal.Copy($modulePINVOKE.ByteVector_data(data), result, 0, result.Length);
  return result;
}
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
%ignore digidoc::Signer::cert;
%ignore digidoc::Signature::signingCertificate;
%ignore digidoc::Signature::OCSPCertificate;
%ignore digidoc::Signature::TimeStampCertificate;
%ignore digidoc::Signature::ArchiveTimeStampCertificate;
// hide stream methods
%ignore digidoc::DataFile::saveAs(std::ostream &os) const;
%ignore digidoc::Container::addAdESSignature(std::istream &signature);
%ignore digidoc::Container::addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);

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
//#ifdef SWIGWIN
%include "crypto/WinSigner.h"
//#endif

%template(StringVector) std::vector<std::string>;
%template(DataFiles) std::vector<digidoc::DataFile*>;
%template(Signatures) std::vector<digidoc::Signature*>;

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
