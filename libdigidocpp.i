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

%module(directors="1") digidoc

%begin %{
#ifdef _MSC_VER
#define SWIG_PYTHON_INTERPRETER_NO_DEBUG
#endif
%}
%{
#include "libdigidocpp.i.h"
#include "DataFile.h"
#include "Exception.h"
#include "Signature.h"
#include "crypto/PKCS11Signer.h"
#include "crypto/PKCS12Signer.h"
#ifdef _WIN32
#include "crypto/WinSigner.h"
#endif
#include "util/log.h"
DIGIDOCPP_WARNING_DISABLE_GCC("-Wdeprecated-declarations")

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
    SWIGEXPORT void SWIGSTDCALL ByteVector_free(void *ptr) {
        delete static_cast<std::vector<unsigned char>*>(ptr);
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
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_free")]
  public static extern void ByteVector_free(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_to")]
  public static extern global::System.IntPtr ByteVector_to(
  [global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPArray)]byte[] data, int size);
  public static byte[] To_ByteArray(global::System.IntPtr cPtr) {
    byte[] result = new byte[$modulePINVOKE.ByteVector_size(cPtr)];
    global::System.Runtime.InteropServices.Marshal.Copy($modulePINVOKE.ByteVector_data(cPtr), result, 0, result.Length);
    $modulePINVOKE.ByteVector_free(cPtr);
    return result;
  }
%}

#ifdef SWIGJAVA
%fragment("SWIG_VectorUnsignedCharToJavaArray", "header") {
static jbyteArray SWIG_VectorUnsignedCharToJavaArray(JNIEnv *jenv, const std::vector<unsigned char> &data) {
    jbyteArray jresult = JCALL1(NewByteArray, jenv, data.size());
    if (!jresult)
        return nullptr;
    JCALL4(SetByteArrayRegion, jenv, jresult, 0, data.size(), (const jbyte*)data.data());
    return jresult;
}}
%fragment("SWIG_JavaArrayToVectorUnsignedChar", "header") {
static std::vector<unsigned char>* SWIG_JavaArrayToVectorUnsignedChar(JNIEnv *jenv, jbyteArray data) {
    std::vector<unsigned char> *result = new std::vector<unsigned char>(JCALL1(GetArrayLength, jenv, data));
    JCALL4(GetByteArrayRegion, jenv, data, 0, result->size(), (jbyte*)result->data());
    return result;
}}
%typemap(in, fragment="SWIG_JavaArrayToVectorUnsignedChar") std::vector<unsigned char>
%{ $1 = SWIG_JavaArrayToVectorUnsignedChar(jenv, $input); %}
%typemap(out, fragment="SWIG_VectorUnsignedCharToJavaArray") std::vector<unsigned char>, digidoc::X509Cert
%{ $result = SWIG_VectorUnsignedCharToJavaArray(jenv, $1); %}
%typemap(jtype) std::vector<unsigned char>, digidoc::X509Cert "byte[]"
%typemap(jstype) std::vector<unsigned char> "byte[]"
%typemap(jstype) digidoc::X509Cert "java.security.cert.X509Certificate"
%typemap(jni) std::vector<unsigned char>, digidoc::X509Cert "jbyteArray"
%typemap(javain) std::vector<unsigned char>, digidoc::X509Cert "$javainput"
%typemap(javaout) std::vector<unsigned char> {
    return $jnicall;
  }
%typemap(javaout, throws="java.security.cert.CertificateException, java.io.IOException") digidoc::X509Cert {
    byte[] der = $jnicall;
    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X509");
    try (java.io.ByteArrayInputStream is = new java.io.ByteArrayInputStream(der)) {
        return (java.security.cert.X509Certificate) cf.generateCertificate(is);
    }
  }

#elif defined(SWIGCSHARP)
%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(cstype) digidoc::X509Cert "System.Security.Cryptography.X509Certificates.X509Certificate2"
%typemap(csin, pre= "    global::System.IntPtr cPtr$csinput = digidocPINVOKE.ByteVector_to($csinput, $csinput.Length);
    var handleRef$csinput = new global::System.Runtime.InteropServices.HandleRef($csinput, cPtr$csinput);"
) std::vector<unsigned char> "handleRef$csinput"
%typemap(csout, excode=SWIGEXCODE) std::vector<unsigned char> {
    global::System.IntPtr cPtr = $imcall;$excode
    return $modulePINVOKE.To_ByteArray(cPtr);
  }
%typemap(csout, excode=SWIGEXCODE) digidoc::X509Cert {
    global::System.IntPtr cPtr = $imcall;$excode
    return new System.Security.Cryptography.X509Certificates.X509Certificate2($modulePINVOKE.To_ByteArray(cPtr));
  }
%typemap(out) std::vector<unsigned char> %{  $result = new std::vector<unsigned char>(std::move($1)); %}
%typemap(out) digidoc::X509Cert %{  $result = new std::vector<unsigned char>($1.operator std::vector<unsigned char>()); %}

#elif defined(SWIGPYTHON)
%typemap(in) std::vector<unsigned char> %{
    if (PyBytes_Check($input)) {
        const char *data = PyBytes_AsString($input);
        $1 = new std::vector<unsigned char>(data, data + PyBytes_Size($input));
    } else if (PyString_Check($input)) {
        const char *data = PyString_AsString($input);
        $1 = new std::vector<unsigned char>(data, data + PyString_Size($input));
    } else {
        PyErr_SetString(PyExc_TypeError, "not a bytes");
        SWIG_fail;
    }
%}
%typemap(out) std::vector<unsigned char>
%{ $result = PyBytes_FromStringAndSize((const char*)(&result)->data(), (&result)->size()); %}
%typemap(out) digidoc::X509Cert {
    std::vector<unsigned char> temp = $1;
    $result = PyBytes_FromStringAndSize((const char*)temp.data(), temp.size());
}
#endif
%typemap(freearg) std::vector<unsigned char>
%{ delete $1; %}
%apply std::vector<unsigned char> { std::vector<unsigned char> const & };

%exception %{
 try {
   $action
 } catch (const digidoc::Exception &e) {
#ifdef SWIGJAVA
   SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, parseException(e).c_str());
   return $null;
#elif defined(SWIGCSHARP)
   SWIG_CSharpSetPendingException(SWIG_CSharpApplicationException, parseException(e).c_str());
   return $null;
#else
   SWIG_exception_fail(SWIG_RuntimeError, parseException(e).c_str());
#endif
 }
%}

#ifdef SWIGJAVA
%ignore digidoc::initialize;
#endif
#ifndef SWIGPYTHON
%ignore digidoc::initialize(const std::string &appInfo, initCallBack callBack);
%ignore digidoc::initialize(const std::string &appInfo, const std::string &userAgent, initCallBack callBack);
#endif
// ignore X509Cert and implement later cert as ByteVector
%ignore digidoc::Conf::TSLCerts;
%ignore digidoc::ConfV2::verifyServiceCert;
%ignore digidoc::ConfV4::verifyServiceCerts;
%ignore digidoc::ConfV5::TSCerts;
// hide stream methods, swig cannot generate usable wrappers
%ignore digidoc::DataFile::saveAs(std::ostream &os) const;
%ignore digidoc::Container::addAdESSignature(std::istream &signature);
%ignore digidoc::Container::addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
%ignore digidoc::Container::addDataFile(std::unique_ptr<std::istream> is, const std::string &fileName, const std::string &mediaType);
// Other
%ignore digidoc::Conf::libdigidocConf;
%ignore digidoc::Conf::certsPath;
%ignore digidoc::ConfV3::OCSPTMProfiles;
%ignore digidoc::Signature::Validator::warnings;
%ignore digidoc::Signature::OCSPNonce;
// std::unique_ptr is since swig 4.1
%ignore digidoc::Container::createPtr;
%ignore digidoc::Container::openPtr;

%newobject digidoc::Container::open;
%newobject digidoc::Container::create;

%feature("director") digidoc::ContainerOpenCB;

%typemap(javacode) digidoc::Conf %{
  public Conf transfer() {
    swigCMemOwn = false;
    return this;
  }
%}
%typemap(cscode) digidoc::Conf %{
  public Conf transfer() {
    swigCMemOwn = false;
    return this;
  }
%}
#ifdef SWIGPYTHON
%extend digidoc::Conf {
%pythoncode %{
def transfer(self):
    self.thisown = 0
    return self
%}
}
#endif

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"
#ifdef SWIGCSHARP
%typemap(imtype,
  inattributes="[global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)]",
  outattributes="[return: global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)]")
  std::string, const std::string & "string"
#endif

// Handle DigiDoc Export declarations
#define DIGIDOCPP_EXPORT
#define DIGIDOCPP_DEPRECATED
#define SWIGEXPORT
// Expose selected DigiDoc classes
%include "Conf.h"
%include "Container.h"
%include "DataFile.h"
%include "Signature.h"
%include "XmlConf.h"
%include "crypto/Signer.h"
%include "crypto/PKCS12Signer.h"
%include "crypto/PKCS11Signer.h"
#ifdef SWIGWIN
%include "crypto/WinSigner.h"
#endif
%include "libdigidocpp.i.h"

%template(StringVector) std::vector<std::string>;
%template(StringMap) std::map<std::string,std::string>;
%template(DataFiles) std::vector<digidoc::DataFile*>;
%template(Signatures) std::vector<digidoc::Signature*>;

%extend digidoc::Container {
    static digidoc::Container* open(const std::string &path, digidoc::ContainerOpenCB *cb)
    {
        return digidoc::Container::openPtr(path, cb).release();
    }

    digidoc::Signature* prepareWebSignature(const std::vector<unsigned char> &cert, const std::string &profile = {},
                                   const std::vector<std::string> &roles = {},
                                   const std::string &city = {}, const std::string &state = {},
                                   const std::string &postalCode = {}, const std::string &country = {})
    {
        digidoc::ExternalSigner signer(cert);
        signer.setProfile(profile);
        signer.setSignatureProductionPlace(city, state, postalCode, country);
        signer.setSignerRoles(roles);
        return $self->prepareSignature(&signer);
    }
}
