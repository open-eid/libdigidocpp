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

%module digidoc
%{

#include "libdigidocpp.i.h"
#include "DataFile.h"
#include "Exception.h"
#include "log.h"
#include "Signature.h"
#include "crypto/PKCS11Signer.h"
#include "crypto/PKCS12Signer.h"
#ifdef _WIN32
#include "crypto/WinSigner.h"
#endif

class WebSignerPrivate: public digidoc::Signer
{
public:
    WebSignerPrivate(digidoc::X509Cert cert): _cert(std::move(cert)) {}

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
%}

%pragma(csharp) imclasscode=%{
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_data")]
  public static extern global::System.IntPtr ByteVector_data(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_size")]
  public static extern int ByteVector_size(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_to")]
  public static extern global::System.IntPtr ByteVector_to(
    [global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPArray)]byte[] data, int size);

  public class UTF8Marshaler : global::System.Runtime.InteropServices.ICustomMarshaler {
    static UTF8Marshaler static_instance = new UTF8Marshaler();

    public global::System.IntPtr MarshalManagedToNative(object managedObj) {
        if (managedObj == null)
            return global::System.IntPtr.Zero;
        if (!(managedObj is string))
            throw new global::System.Runtime.InteropServices.MarshalDirectiveException(
                   "UTF8Marshaler must be used on a string.");

        // not null terminated
        byte[] strbuf = global::System.Text.Encoding.UTF8.GetBytes((string)managedObj);
        global::System.IntPtr buffer = global::System.Runtime.InteropServices.Marshal.AllocHGlobal(strbuf.Length + 1);
        global::System.Runtime.InteropServices.Marshal.Copy(strbuf, 0, buffer, strbuf.Length);

        // write the terminating null
        global::System.Runtime.InteropServices.Marshal.WriteByte(buffer + strbuf.Length, 0);
        return buffer;
    }

    public unsafe object MarshalNativeToManaged(global::System.IntPtr pNativeData) {
        byte* walk = (byte*)pNativeData;

        // find the end of the string
        while (*walk != 0) {
            walk++;
        }
        int length = (int)(walk - (byte*)pNativeData);

        // should not be null terminated
        byte[] strbuf = new byte[length];
        // skip the trailing null
        global::System.Runtime.InteropServices.Marshal.Copy((global::System.IntPtr)pNativeData, strbuf, 0, length);
        return global::System.Text.Encoding.UTF8.GetString(strbuf);
    }

    public void CleanUpNativeData(global::System.IntPtr pNativeData) {
        global::System.Runtime.InteropServices.Marshal.FreeHGlobal(pNativeData);
    }

    public void CleanUpManagedData(object managedObj) {
    }

    public int GetNativeDataSize() {
        return -1;
    }

    public static global::System.Runtime.InteropServices.ICustomMarshaler GetInstance(string cookie) {
        return static_instance;
    }
  }
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
         pre= "	global::System.IntPtr cPtr$csinput = digidocPINVOKE.ByteVector_to($csinput, $csinput.Length);
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

#ifdef SWIGJAVA
%ignore digidoc::initialize;
#endif
%ignore digidoc::initialize(const std::string &appInfo, initCallBack callBack);
// ignore X509Cert and implement later cert as ByteVector
%ignore digidoc::Conf::TSLCerts;
%ignore digidoc::ConfV2::verifyServiceCert;
%ignore digidoc::Signer::cert;
%ignore digidoc::Signature::signingCertificate;
%ignore digidoc::Signature::OCSPCertificate;
%ignore digidoc::Signature::TimeStampCertificate;
%ignore digidoc::Signature::ArchiveTimeStampCertificate;
// hide stream methods, swig cannot generate usable wrappers
%ignore digidoc::DataFile::saveAs(std::ostream &os) const;
%ignore digidoc::Container::addAdESSignature(std::istream &signature);
%ignore digidoc::Container::addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
// Other
%ignore digidoc::Conf::libdigidocConf;
%ignore digidoc::Conf::certsPath;
%ignore digidoc::ConfV3::OCSPTMProfiles;
%ignore digidoc::Signature::Validator::warnings;
%ignore digidoc::Signature::OCSPNonce;

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
#ifdef SWIGCSHARP
namespace std {
  %typemap(imtype,
    inattributes="[global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(UTF8Marshaler))]",
    outattributes="[return: global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(UTF8Marshaler))]")
    string "string"
  %typemap(imtype,
    inattributes="[global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(UTF8Marshaler))]",
    outattributes="[return: global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(UTF8Marshaler))]") const string & "string"
}
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
#ifdef SWIGCSHARP
%include "crypto/WinSigner.h"
#endif
%include "libdigidocpp.i.h"

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
    Signature* prepareWebSignature(const std::vector<unsigned char> &cert, const std::string &profile = std::string(),
                                   const std::vector<std::string> &roles = {},
                                   const std::string &city = std::string(), const std::string &state = std::string(),
                                   const std::string &postalCode = std::string(), const std::string &country = std::string())
    {
        WebSignerPrivate signer(X509Cert(cert, X509Cert::Der));
        signer.setProfile(profile);
        signer.setSignatureProductionPlace(city, state, postalCode, country);
        signer.setSignerRoles(roles);
        return $self->prepareSignature(&signer);
    }
}
