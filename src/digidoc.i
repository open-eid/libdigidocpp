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

  static void parseException(const digidoc::Exception &e, std::string &msg) {
      msg += e.msg() + "\n";
      for(const digidoc::Exception &ex: e.causes())
          parseException(ex, msg);
  }
%}

%pragma(csharp) imclasscode=%{
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_data")]
  public static extern global::System.IntPtr ByteVector_data(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_size")]
  public static extern int ByteVector_size(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_to")]
  public static extern global::System.Runtime.InteropServices.HandleRef ByteVector_to(
    [global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPArray)]byte[] data, int size);
%}

%typemap(throws, canthrow=1) Exception %{
    std::string msg;
    parseException(e, msg);
    SWIG_CSharpSetPendingException(SWIG_CSharpApplicationException, msg.c_str());
    return $null;
%}

//%feature("except", throws="Exception") {
%exception %{
 try {
   $action
 } catch (const digidoc::Exception &e) {
   std::string msg;
   parseException(e, msg);
   SWIG_CSharpSetPendingException(SWIG_CSharpApplicationException, msg.c_str());
   return $null;
 }
%}

%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(csin) std::vector<unsigned char> "$modulePINVOKE.ByteVector_to($csinput, $csinput.Length)"
%typemap(csout) std::vector<unsigned char>
{
  global::System.IntPtr data = $imcall;
  byte[] result = new byte[$modulePINVOKE.ByteVector_size(data)];
  global::System.Runtime.InteropServices.Marshal.Copy($modulePINVOKE.ByteVector_data(data), result, 0, result.Length);
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
%ignore digidoc::Signature::TSCertificate;
%ignore digidoc::Container::addRawSignature(std::istream &signature);
%ignore digidoc::Container::addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType);
%ignore digidoc::DataFile::saveAs(std::ostream &os) const;

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
    std::vector<unsigned char> TSCert() const
    {
        return $self->TSCertificate();
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
