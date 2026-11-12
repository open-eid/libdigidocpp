// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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

#include <concepts>
#include <optional>
#include <utility>

DIGIDOCPP_WARNING_DISABLE_GCC("-Wdeprecated-declarations")

static std::string parseException(const digidoc::Exception &e) {
    std::string msg = e.msg();
    for(const digidoc::Exception &ex: e.causes())
        msg += "\n" + parseException(ex);
    return msg;
}

#ifdef SWIGJAVA
template<class T>
struct JNIObject {
    JNIEnv *jenv;
    T jobj;

    constexpr JNIObject(JNIEnv *env, jobject obj) noexcept
        : jenv(env), jobj(static_cast<T>(obj)) {}
    constexpr JNIObject(JNIEnv *env, const char *obj) noexcept
        : JNIObject(env, env->FindClass(obj)) {}
    static JNIObject fromBytes(JNIEnv *env, const auto &data) noexcept
        requires std::same_as<T, jbyteArray>
    {
        if(!std::in_range<jsize>(data.size())) {
            SWIG_JavaThrowException(env, SWIG_JavaOutOfMemoryError, "Java byte array too large");
            return {env, jobject{}};
        }
        JNIObject result{env, env->NewByteArray(jsize(data.size()))};
        if(result && !data.empty()) {
            env->SetByteArrayRegion(*result, 0, jsize(data.size()), reinterpret_cast<const jbyte*>(data.data()));
            if(env->ExceptionCheck())
                return {env, jobject{}};
        }
        return {env, result.release()};
    }
    JNIObject(const JNIObject &) = delete;
    JNIObject &operator=(const JNIObject &) = delete;
    ~JNIObject() noexcept { if(jobj) jenv->DeleteLocalRef(jobj); }
    explicit constexpr operator bool() const noexcept { return jobj != nullptr; }
    constexpr T operator*() const noexcept { return jobj; }
    constexpr const JNIObject *operator->() const noexcept { return this; }
    constexpr T release() noexcept { return std::exchange(jobj, nullptr); }
    template<class R, typename... Args>
    JNIObject<R> NewObject(const char *sig, Args... args) const {
        auto ctor = jobj ? jenv->GetMethodID(jobj, "<init>", sig) : nullptr;
        return {jenv, ctor ? jenv->NewObject(jobj, ctor, args...) : nullptr};
    }
};

static void throwJavaException(JNIEnv *jenv, const std::string &message) {
    JNIObject<jclass> charsetsClass{jenv, "java/nio/charset/StandardCharsets"};
    if(!charsetsClass) return;
    jfieldID utf8Field = jenv->GetStaticFieldID(*charsetsClass, "UTF_8", "Ljava/nio/charset/Charset;");
    if(!utf8Field) return;
    JNIObject<jobject> utf8{jenv, jenv->GetStaticObjectField(*charsetsClass, utf8Field)};
    if(!utf8) return;

    auto data = JNIObject<jbyteArray>::fromBytes(jenv, message);
    if(!data) return;
    JNIObject<jclass> stringClass{jenv, "java/lang/String"};
    auto text = stringClass->NewObject<jstring>("([BLjava/nio/charset/Charset;)V", *data, *utf8);
    if(!text) return;

    JNIObject<jclass> exceptionClass{jenv, "java/lang/RuntimeException"};
    if(auto exception = exceptionClass->NewObject<jthrowable>("(Ljava/lang/String;)V", *text))
        jenv->Throw(*exception);
}
#endif

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
    return JNIObject<jbyteArray>::fromBytes(jenv, data).release();
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
%typemap(out, fragment="SWIG_VectorUnsignedCharToJavaArray") digidoc::X509Cert *
%{ $result = SWIG_VectorUnsignedCharToJavaArray(jenv, *$1); %}
%typemap(jtype) std::vector<unsigned char>, digidoc::X509Cert, digidoc::X509Cert * "byte[]"
%typemap(jstype) std::vector<unsigned char> "byte[]"
%typemap(jstype) digidoc::X509Cert, digidoc::X509Cert* "java.security.cert.X509Certificate"
%typemap(jni) std::vector<unsigned char>, digidoc::X509Cert, digidoc::X509Cert * "jbyteArray"
%typemap(javain) std::vector<unsigned char>, digidoc::X509Cert "$javainput"
%typemap(javaout) std::vector<unsigned char> {
    return $jnicall;
  }
%typemap(javaout, throws="java.security.cert.CertificateException, java.io.IOException") digidoc::X509Cert, digidoc::X509Cert * {
    byte[] der = $jnicall;
    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X509");
    try (java.io.ByteArrayInputStream is = new java.io.ByteArrayInputStream(der)) {
        return (java.security.cert.X509Certificate) cf.generateCertificate(is);
    }
  }

#elif defined(SWIGCSHARP)
%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(cstype) digidoc::X509Cert, digidoc::X509Cert* "System.Security.Cryptography.X509Certificates.X509Certificate2"
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
%typemap(csvarout, excode=SWIGEXCODE2) digidoc::X509Cert * %{
    get {
      global::System.IntPtr cPtr = $imcall;$excode
      byte[] der = new byte[$modulePINVOKE.ByteVector_size(cPtr)];
      global::System.Runtime.InteropServices.Marshal.Copy($modulePINVOKE.ByteVector_data(cPtr), der, 0, der.Length);
      $modulePINVOKE.ByteVector_free(cPtr);
      return new System.Security.Cryptography.X509Certificates.X509Certificate2(der);
    } %}
%typemap(out) std::vector<unsigned char> %{  $result = new std::vector<unsigned char>(std::move($1)); %}
%typemap(out) digidoc::X509Cert %{  $result = new std::vector<unsigned char>($1.operator std::vector<unsigned char>()); %}
%typemap(out) digidoc::X509Cert * %{  $result = new std::vector<unsigned char>($1->operator std::vector<unsigned char>()); %}

#elif defined(SWIGPYTHON)
%fragment("SWIG_PyBytesToVectorUnsignedChar", "header") %{
static std::vector<unsigned char>* SWIG_PyBytesToVectorUnsignedChar(PyObject *input) {
    char *data {};
    Py_ssize_t size {};
    if (PyBytes_AsStringAndSize(input, &data, &size) == -1)
        return nullptr;
    return new std::vector<unsigned char>(data, data + size);
}%}
%fragment("SWIG_VectorUnsignedCharToPyBytes", "header") %{
static PyObject* SWIG_VectorUnsignedCharToPyBytes(const std::vector<unsigned char> &data) {
    return PyBytes_FromStringAndSize((const char*)data.data(), data.size());
}%}
%typemap(in, fragment="SWIG_PyBytesToVectorUnsignedChar") std::vector<unsigned char>
%{ if ($1 = SWIG_PyBytesToVectorUnsignedChar($input); !$1) SWIG_fail; %}
%typemap(out, fragment="SWIG_VectorUnsignedCharToPyBytes") std::vector<unsigned char>, digidoc::X509Cert
%{ $result = SWIG_VectorUnsignedCharToPyBytes($1); %}
%typemap(out, fragment="SWIG_VectorUnsignedCharToPyBytes") digidoc::X509Cert *
%{ $result = SWIG_VectorUnsignedCharToPyBytes(*$1); %}
#endif
%typemap(freearg) std::vector<unsigned char>
%{ delete $1; %}
%apply std::vector<unsigned char> { std::vector<unsigned char> const & };

%exception %{
 try {
   $action
 } catch (const digidoc::Exception &e) {
#ifdef SWIGJAVA
   throwJavaException(jenv, parseException(e));
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
%ignore digidoc::ConfV6::TSCertsArchive;
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
%ignore digidoc::Container::extendContainerValidity;

%newobject digidoc::Container::open;
%newobject digidoc::Container::create;
%newobject digidoc::Container::extendContainerValidity;

%immutable digidoc::TSAInfo::cert;
%immutable digidoc::TSAInfo::time;

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
%include <std_string.i>
%include <std_vector.i>
%include <std_map.i>
%include <typemaps.i>
%apply unsigned long long &OUTPUT { size_t &extendedCount };
#ifdef SWIGJAVA
%fragment("SWIG_JavaArrayToString", "header") {
static std::optional<std::string> SWIG_JavaArrayToString(JNIEnv *jenv, jbyteArray data) {
    if(jenv->ExceptionCheck())
        return std::nullopt;
    if(!data) {
        SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
        return std::nullopt;
    }
    std::string result(size_t(JCALL1(GetArrayLength, jenv, data)), '\0');
    if(!result.empty())
        JCALL4(GetByteArrayRegion, jenv, data, 0, jsize(result.size()), reinterpret_cast<jbyte*>(result.data()));
    if(jenv->ExceptionCheck())
        return std::nullopt;
    return result;
}}
%fragment("SWIG_StringToJavaArray", "header") {
static jbyteArray SWIG_StringToJavaArray(JNIEnv *jenv, const std::string &data) {
    return JNIObject<jbyteArray>::fromBytes(jenv, data).release();
}}
%typemap(jni) std::string, const std::string & "jbyteArray"
%typemap(jtype) std::string, const std::string & "byte[]"
%typemap(jstype) std::string, const std::string & "String"
%typemap(javain) std::string, const std::string & "$javainput.getBytes(java.nio.charset.StandardCharsets.UTF_8)"
%typemap(javaout) std::string, const std::string & {
    return new String($jnicall, java.nio.charset.StandardCharsets.UTF_8);
  }
%typemap(javadirectorin) std::string, const std::string & "new String($jniinput, java.nio.charset.StandardCharsets.UTF_8)"
%typemap(javadirectorout) std::string, const std::string & "$javacall.getBytes(java.nio.charset.StandardCharsets.UTF_8)"
%typemap(in, fragment="SWIG_JavaArrayToString") std::string
%{ auto $1_str = SWIG_JavaArrayToString(jenv, $input);
   if(!$1_str)
     return $null;
   $1 = std::move(*$1_str); %}
%typemap(in, fragment="SWIG_JavaArrayToString") const std::string &
%{ auto $1_str = SWIG_JavaArrayToString(jenv, $input);
   if(!$1_str)
     return $null;
   $1 = &*$1_str; %}
%typemap(out, fragment="SWIG_StringToJavaArray") std::string
%{ $result = SWIG_StringToJavaArray(jenv, $1); %}
%typemap(out, fragment="SWIG_StringToJavaArray") const std::string &
%{ $result = SWIG_StringToJavaArray(jenv, *$1); %}
%typemap(directorin, descriptor="[B", fragment="SWIG_StringToJavaArray") std::string, const std::string &
%{ $input = SWIG_StringToJavaArray(jenv, $1);
   Swig::LocalRefGuard $1_refguard(jenv, $input); %}
%typemap(directorout, fragment="SWIG_JavaArrayToString") std::string
%{ auto $1_str = SWIG_JavaArrayToString(jenv, $input);
   if(!$1_str)
     return $null;
   $result = std::move(*$1_str); %}
%typemap(directorout, warning=SWIGWARN_TYPEMAP_THREAD_UNSAFE_MSG,
  fragment="SWIG_JavaArrayToString") const std::string &
%{ auto $1_value = SWIG_JavaArrayToString(jenv, $input);
   if(!$1_value)
     return $null;
   /* possible thread/reentrant code problem */
   static $*1_ltype $1_str;
   $1_str = std::move(*$1_value);
   $result = &$1_str; %}

#elif defined(SWIGCSHARP)
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
%template(TSAInfos) std::vector<digidoc::TSAInfo>;

%rename("%s") digidoc::Container::extendContainerValidity;

%extend digidoc::Container {
#ifdef SWIGJAVA
    static Container* extendContainerValidity(Container &doc, Signer *signer)
    {
        size_t extendedCount{};
        return digidoc::Container::extendContainerValidity(doc, signer, extendedCount).release();
    }
#else
    static Container* extendContainerValidity(Container &doc, Signer *signer, size_t &extendedCount)
    {
        return digidoc::Container::extendContainerValidity(doc, signer, extendedCount).release();
    }
#endif

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
