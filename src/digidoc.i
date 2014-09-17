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
#undef seed // Combat braindead #defines that are present in PERL headers

#include "Container.h"
#include "DataFile.h"
#include "Signature.h"
#include "crypto/X509Cert.h"

%}

%insert(runtime) %{
  #include "Exception.h"
  #include <vector>

  // Code to handle throwing of C# DigidocApplicationException from C/C++ code.
  // The equivalent delegate to the callback, CSharpExceptionCallback_t, is DigidocExceptionDelegate
  // and the equivalent digidocExceptionCallback instance is digidocDelegate
  typedef void (SWIGSTDCALL* CSharpExceptionCallback_t)(const char *);
  CSharpExceptionCallback_t digidocExceptionCallback = NULL;

  extern "C"
  {
    SWIGEXPORT unsigned char* SWIGSTDCALL ByteVector_data(void *ptr) {
      std::vector<unsigned char> *arg = (std::vector<unsigned char>*)ptr;
      return (unsigned char*)&(*arg)[0];
    }
    SWIGEXPORT int SWIGSTDCALL ByteVector_size(void *ptr) {
      std::vector<unsigned char> *arg = (std::vector<unsigned char>*)ptr;
      return (int)arg->size();
    }
    SWIGEXPORT void* SWIGSTDCALL ByteVector_to(unsigned char *data, int size) {
      return new std::vector<unsigned char>(data, data + size);
    }

    SWIGEXPORT void SWIGSTDCALL DigidocExceptionRegisterCallback(CSharpExceptionCallback_t digidocCallback) {
      digidocExceptionCallback = digidocCallback;
    }
  }

  static void parseException(const digidoc::Exception &e, std::string &msg) {
      msg += e.msg() + "\n";
      digidoc::Exception::Causes list = e.causes();
      for(digidoc::Exception::Causes::const_iterator i = list.begin(); i != list.end(); ++i)
          parseException(*i, msg);
  }

  // Note that SWIG detects any method calls named starting with
  // CSharpSetPendingException for warning 845
  static void CSharpSetPendingExceptionDigidoc(const digidoc::Exception &e) {
    std::string msg;
    parseException(e, msg);
    digidocExceptionCallback(msg.c_str());
  }
%}

%pragma(csharp) imclasscode=%{
  [DllImport("$dllimport", EntryPoint="ByteVector_data")]
  public static extern IntPtr ByteVector_data(IntPtr data);
  [DllImport("$dllimport", EntryPoint="ByteVector_size")]
  public static extern int ByteVector_size(IntPtr data);
  [DllImport("$dllimport", EntryPoint="ByteVector_to")]
  public static extern HandleRef ByteVector_to([MarshalAs(UnmanagedType.LPArray)]byte[] data, int size);

  class DigidocExceptionHelper {

    public delegate void DigidocExceptionDelegate(string message);

    static DigidocExceptionDelegate digidocDelegate = new DigidocExceptionDelegate(SetPendingDigidocException);

    [DllImport("$dllimport", EntryPoint="DigidocExceptionRegisterCallback")]
    public static extern void DigidocExceptionRegisterCallback(DigidocExceptionDelegate digidocCallback);

    static void SetPendingDigidocException(string message) {
      SWIGPendingException.Set(new DigidocException(message));
    }

    static DigidocExceptionHelper() {
      DigidocExceptionRegisterCallback(digidocDelegate);
    }
  }
  static DigidocExceptionHelper exceptionHelper = new DigidocExceptionHelper();
%}

%typemap(throws, canthrow=1) Exception %{
    CSharpSetPendingExceptionDigidoc($1);
    return $null;
%}

//%feature("except", throws="Exception") {
%exception {
 try {
   $action
 } catch (const digidoc::Exception &e) {
   CSharpSetPendingExceptionDigidoc(e);
   return $null;
 }
}

%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(csin) std::vector<unsigned char> "$modulePINVOKE.ByteVector_to($csinput, $csinput.Length)"
%typemap(csout) std::vector<unsigned char>
{
  IntPtr data = $imcall;
  byte[] result = new byte[$modulePINVOKE.ByteVector_size(data)];
  Marshal.Copy($modulePINVOKE.ByteVector_data(data), result, 0, result.Length);
  return result;
}

%apply std::vector<unsigned char> { std::vector<unsigned char> const & };

// Handle DigiDoc Export declarations
#define EXP_DIGIDOC

#ifdef SWIGPHP
// Broken in PHP :(
%ignore digidoc::DataFile::DataFile;
%feature("notabstract") digidoc::Signature;  // Breaks PHP if abstract
#endif

// TODO: useful, but broken
%ignore *::sign;

// ignore X509Cert and implement later cert as ByteVector
%ignore digidoc::Signature::signingCertificate;
%ignore digidoc::Signature::OCSPCertificate;

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
// Expose selected DigiDoc classes
%include "Container.h"
%include "DataFile.h"
%include "Signature.h"

%template(StringVector) std::vector<std::string>;
%template(DataFiles) std::vector<digidoc::DataFile>;
%template(Signatures) std::vector<digidoc::Signature*>;

%extend digidoc::Signature {
    std::vector<unsigned char> signingCert() const
    {
        return $self->signingCertificate();
    }
    std::vector<unsigned char> OCSPCert() const
    {
        return $self->OCSPCertificate();
    }
}

// Target language specific functions
#ifdef SWIGPHP
%minit %{ %}
%mshutdown %{ %}
%rinit %{
    using namespace digidoc;

    // Initialize digidoc library.
    initialize();
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
