# Using Libdigidocpp API {#manual}

This page describes the C++ API workflows for creating, signing, validating,
and extending containers. Related pages include the following.

- [Overview](README.md) – supported functional properties and component model
- [Supported container formats](formats.md) – format-specific behavior
- [Configuration guide](configuration.md) – file-based and operational settings
- [Standards and references](references.md) – specifications and related
  resources cited on this page

## String encoding {#string-encoding}

All `std::string` values passed to or returned from the API are UTF-8 encoded. This applies to file paths, media types, and all other string parameters and return values throughout the library.

Supply ordinary text, not XML-escaped strings. The library escapes values when
writing XML: `&` is accepted as text, and a literal `&#x1B;` remains that literal
string rather than becoming an ESC character. XML escaping cannot make a
disallowed character acceptable as input.

## Initialization {#initialization}

Libdigidocpp's initialization method conducts the following operations:
1. initializes the software libraries described in the
   [implementation notes](implementation.md)
2. loads configuration settings from default configuration files
3. initializes trust anchors from trusted lists (TSLs) as described in the
   [configuration guide](configuration.md)

If you would like to use non-default configuration settings then call out the configuration file's initialization before initializing the library, for example:
```cpp
    // Optionally initialize global configuration file to use non-default settings
    digidoc::Conf::init(new digidoc::XmlConfCurrent("<file-path-and-name>"));
    // Initialize the library
    digidoc::initialize();
```

Use digidoc::XmlConfCurrent, an alias for the newest XmlConf version, to access
all configuration methods. Older XmlConf classes expose the methods of their
respective versions. See the [configuration guide](configuration.md) for how
settings are loaded.

> [!NOTE]
> To use configuration values other than those provided by the configuration file, extend digidoc::XmlConfCurrent and override the virtual methods whose values need to be changed.

## Exception handling {#exceptions}

The Libdigidocpp library may throw exceptions that are instances of Exception class (defined in Exception.h source file). The code which uses Libdigidocpp’s API should be wrapped in a try/catch block as follows:
```cpp
try {

// code implementation

} catch(const digidoc::Exception &e) {
    printf("Exception:%s\n", parseException(e).c_str()); // Sample exception handling method
}
```

An Exception instance thrown by the library may contain a stack trace of the hierarchy of exceptions. For example, to parse the whole stack trace, do as follows:
```cpp
std::string parseException(const digidoc::Exception &e)
{
    std::string result = e.msg() + "\n"; // the error message is retrieved
    // Iteration through the list of causes:
    for(const digidoc::Exception &ex: e.causes())
        result += parseException(ex); // Parsing the exceptions recursively
    return result; // The error message is returned
}
```

## Creating and signing a DigiDoc document (local signing) {#creating}

### Creating a DigiDoc container {#containercreate}

Create a new container object and specify the DigiDoc document's type, for example:
```cpp
    auto doc = digidoc::Container::createPtr("<output-file's-path>"); // create new container
```
Container class is used to incorporate the data of a DigiDoc document.

### Adding data files {#adddatafile}

Add a data file from a filesystem path or an input stream.

```cpp
doc->addDataFile("reports/document.txt", "text/plain");

auto input = std::make_unique<std::istringstream>("Meeting notes");
doc->addDataFile(std::move(input), "notes.txt", "text/plain");
```

The filesystem overload stores the base name of the source path. With the
stream overload, pass a `fileName` that is non-empty, contains neither `/` nor
`\`, and is neither `.` nor `..`. For the widest interoperability, use the
file-name characters classified as unreserved in
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html).

Pass a MIME type in `type/subtype` form, such as `text/plain`, as specified in
section 5.1 of [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045.html). Use
`application/octet-stream` when the file type is unknown.

Each call adds a DataFile to the container. The container must be unsigned,
and each stored file name must be unique.

Both overloads reject stored file names and MIME types that are not valid UTF-8
or contain characters disallowed by XML 1.0, such as ESC (U+001B) or NUL
(U+0000). The check runs before the data file is added and does not modify the
supplied metadata. It does not change how existing containers are opened.

When adding a data file from a path or a seekable stream, `addDataFile()`
allows up to 1 GiB for the file and up to 2032 MiB for all data files with
known sizes. See [Container entry limits](#container-entry-limits) for details.

When saving an ASiC container, a file added from a path uses the source file's
modification time captured when it was added. A file added from a stream uses
the stored ZIP modification time for that name if available, or the time of
its first save otherwise.

> [!WARNING]
> When importing an XAdES signature into an ASiC-E container, make sure each
> data file's MIME type in `manifest.xml` matches the signed `MimeType` in
> `DataObjectFormat`. A mismatch invalidates the signature. The library sets
> matching values when it creates the signature.

### Adding signatures {#API-add-sign}

It is possible to add a signature to a container only if it contains at least one data file, multiple signatures can be added to a single container. The signer's certificate and PIN code to access the private signature key are required during signing.

> [!NOTE]
> During signing, the library uses trusted lists (TSLs) to identify trusted
> certificates. The [configuration guide](configuration.md) describes TSL
> settings.

A PKCS#11 module is the default way to access a smart card for signing. Use the
driver for the card, such as the Estonian ID card driver. See the
[configuration guide](configuration.md) for PKCS#11 settings.
```cpp
    digidoc::PKCS11Signer *signer = new digidoc::PKCS11Signer("<PKCS11-driver-path>");
    // optionally specify PKCS#11 driver's location. If left  unspecified then location is
    // looked up from configuration file's parameter "pkcs11.driver.path".
    std::string pin = "<pin-code>"; //PIN2 in case of Estonian ID cards
    signer->setPin(pin);
```
If you would like to add PIN insertion dialog window for the signer to enter the PIN code then you can write a new class which extends the PKCS11Signer class, overwrite the `std::string pin(const X509Cert &cert)` method and write your own PIN dialog implementation code there.

#### Optionally specify the signature profile {#API-sign-profile}

The [overview](README.md) lists the supported signature profiles.

- "time-stamp" (TS) adds an OCSP confirmation of the signing certificate's
  validity and a time-stamp token from a time-stamping service. Libdigidocpp
  reports the token's issuance time as the trusted signing time, using the
  `TSTInfo.genTime` field defined in
  [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html).

If the signature profile value is not specified then then a "time-stamp" profile is used by default.

Set the profile value as follows:
```cpp
std::string profile = "time-stamp"; // or "time-stamp-archive"
signer->setProfile(profile);
```

#### Optionally specify additional signer's data {#API-sign-data}

Signature production place and signer role are optional signed meta-data about the signature. If left unspecified then the respective elements in the `signatures*.xml` file are created with no contents.

Production-place fields, including the street address accepted by
digidoc::Signer::setSignatureProductionPlaceV2, and signer roles must be valid
UTF-8 and contain only characters allowed by XML 1.0. The setters reject invalid
values before updating the stored signer metadata. Supply ordinary text as
described in [String encoding](#string-encoding).

```cpp
    std::string city, state, postalCode, country;
    std::vector<std::string> roles;
    signer->setSignatureProductionPlace(city, state, postalCode, country); // location where the signature is created
    signer->setSignerRoles(roles); // role(s) of the signer
```

#### Optionally specify signature digest method {#API-signature-hash}

By default, the hash that is being signed is calculated with SHA-256 algorithm.
You can also use a different digest algorithm for calculating the hash that is signed (this does not affect calculating other hash values). For that, use the `digidoc::Signer::setMethod(const std::string &method)` method.

#### Create the signature {#API-sign-create}

The signing method adds validation data from the OCSP responder and, for the
TS profile, the time-stamping service. Set any custom values during
[initialization](#initialization) using the
[configuration guide](configuration.md). The default time-stamping service
is https://eid-dd.ria.ee/ts.
Container holds the Signature object reference and there is no need cleanup memory.

```cpp
Signature *signature = doc->sign(signer);
```

#### Validating the created signatures {#validatesig}

After the signature has been added to the container, it should be validated before writing the signed container to an output file. For validating the signature, do as follows:
```cpp
    signature->validate();
```
The validation method above validates the signed data files', signer certificate's and OCSP confirmation's correspondence to the signature value. Note that the validation method above does not validate other signatures which may belong to the same container.

> [!NOTE]
> See also [Validating signature containers and signatures](#validate) about more information for validating existing signatures and signature containers.

#### Save container changes {#savesig}

After the signature has been added and validated, container changes should be saved ([Reading and writing DigiDoc documents](#containeropen)):
```cpp
    doc->save();
```

## Creating and signing a DigiDoc document (external signing, e.g. in browser) {#websigning}

External signing (two-step signing) can be used in case of signing in web applications, where the signature value is calculated externally, via a browser plug-in or extension.

Container holds the Signature object reference and there is no need cleanup memory.

In order to conduct web signing with Libdigidocpp library, do as follows:

1. In Container class, prepare signature XML structure:
   ```cpp
   Signature *signature = doc->prepareSignature(signer);
   ```
2. In Signature class, get the hash to be signed in browser:
   ```cpp
   std::vector<unsigned char> dataToSign = signature->dataToSign();
   std::vector<unsigned char> signatureMethod = signature->signatureMethod();
   std::string id = signature->id();
   ```
   ID can be used when container is saved with digidoc::Container::save and later reloaded to locate signature object.
3. Sign the hash in browser (e.g. use the [hwcrypto.js library](https://github.com/open-eid/hwcrypto.js))
4. Add RSA or ECDSA signature value to the signature XML structure:
   When container was stored on disk before reload container with digidoc::Container::open and use digidoc::Container::signatures() to enumerate signatures to locate correct object with previosly selected ID.
   ```cpp
   std::vector<unsigned char> signatureValue = ...;
   signature->setSignatureValue(signatureValue);
   ```
5. Add time-stamp and OCSP data to Signature object, according to the signature's profile (see also section [Optionally specify the signature profile](#API-sign-profile) for more information):
   ```cpp
   signature->extendSignatureProfile(signer);
   ```
6. Write the document to output, as specified in section [Reading and writing DigiDoc documents](#containeropen)

## Creating and timestamping an ASiC-S container {#asics-create}

Use an `.asics` or `.scs` output file name to create an ASiC-S container. An
ASiC-S TimeStampToken container supports one data file and one initial
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) time-stamp token.

```cpp
auto doc = digidoc::Container::createPtr("timestamped-document.asics");
doc->addDataFile("document.txt", "text/plain");

digidoc::Signer *signer = ...;
signer->setProfile("TimeStampToken"); // "time-stamp-token" is also accepted
digidoc::Signature *timestamp = doc->sign(signer);
timestamp->validate();
doc->save();
```

ASiC-S TimeStampToken creation uses the one-step digidoc::Container::sign method. External two-step signing with digidoc::Container::prepareSignature is not supported for this format. Additional archive-manifest time-stamp layers can be added with the workflow described in [Extending container validity](#extend-validity).

## Reading and writing DigiDoc documents {#containeropen}

In order to read an existing DigiDoc file from the file system, do as follows:
```cpp
    auto doc = digidoc::Container::openPtr("<input-file's-path>");
```
The method above reads in the DigiDoc file from the specified location in file system and creates the respective Container object representing the document's data. The file's structure is also validated during its parsing according to the corresponding standards.

When opening an existing ASiC-E container, the library accepts safe relative
subdirectories separated by `/`. It rejects absolute paths, backslashes,
trailing slashes, and empty, `.` or `..` path segments. ASiC-S data files must
be at the container root.

When opening a ZIP-based container, the library reads its data files into
memory if the archive's total uncompressed size is at most 500 MiB. Above
that limit, it extracts the data files to temporary files and deletes them
when the container is destroyed.

> [!NOTE]
> Pass a digidoc::ContainerOpenCB to digidoc::Container::openPtr to decide
> whether the library may send a container to SiVa. A callback that permits
> SiVa validation is required to open a DDoc enclosed in an ASiC-S container.
> Other network access, such as TSL updates, can still occur.
> See the [implementation notes](implementation.md).

Write a DigiDoc file (represented with a Container object) to file system with the following method:
```cpp
    digidoc::Container::save("<output-file's-path>");
```

> [!NOTE]
> ASiC-S containers with TimeStampToken signatures can be saved. Saving a read-only format or an unsupported ASiC-S signature variant throws a digidoc::Exception.

## Validating signature containers and signatures {#validate}

Validation of a signed DigiDoc document consists of three main steps:
1. Call out the main validation method of the library. If there are multiple validation errors then get the errors list.
2. Check for additional errors/warnings (separate implementation);
3. Determine the validation status of the document (according to the returned error codes and validation status priorities).

### Overview of validation activities {#validation-overview}

Overview of validation activities is as follows:
1. checking that all the data files and signature’s meta-data (signer’s role, etc.) are included in the signature by calculating the data objects’ digest values and comparing them with the `<Reference>` element values in the signature;
2. checking that the claimed signer’s certificate is the actual certificate that was used for signing; checking that the "Non-repudiaton" value is set in the "Key Usage" extension of the signer’s certificate;
3. checking that the signature value is correct by decrypting the value with the signer’s public key and comparing the result with digest calculated from `<SignedInfo>` element block;
4. case of time-stamp corresponds to the signature value (by comparing the digest value of `<SignatureValue>` element’s value and TS response’s digest value);
5. checking that the OCSP response confirms the signer certificate’s validity and case of time-mark corresponds to the signature value (by comparing the digest value of `<SignatureValue>` element’s value and OCSP response’s nonce value);
6. checking that the signer’s, TSA and OCSP responder’s certificates are trusted (i.e. the certificates’ issuers are registered in trust store).

> [!NOTE]
> During validation, the library uses trusted lists (TSLs) to identify trusted
> certificates. The [configuration guide](configuration.md) describes TSL
> settings.

### Using the main validation method {#main-method}

You can validate a signature and its validation data - OCSP confirmation and time-stamp (in case of TS profile) - with method:
```cpp
void digidoc::Signature::validate();
```
If an exception is thrown from the validation method then the signature can be either **INVALID** or **VALID WITH WARNINGS**; otherwise the signature is VALID. Before determining the final validation status, additional errors must be checked, as described in the following chapters.

If an exception is thrown then its causes can be retrieved with the following method:
```cpp
std::vector<digidoc::Exception> digidoc::Exception::causes();
```

For formats validated through SiVa, archive time-stamp information returned by the service is available through digidoc::Signature::ArchiveTimeStamps in the same way as locally validated archive time-stamps.

digidoc::Signature::Validator provides the validation status, warning codes,
and diagnostics. Pass `false` as the second constructor argument to omit
warning messages from the diagnostics. Other diagnostics, the validation
status, and warning codes remain available.

### Checking for additional errors/warnings {#additional}

There is a validation case that is not checked in the default validation method of the library, instead, separate method for checking this specific situation has to be implemented by the library’s user. In Libdigidocpp library, checking for an old file format must be done separately.

After checking for old signature format errors/warnings, collect all of the error codes and continue with determining the validation status as described in the next chapter. It is possible to check the source code of digidoc-tool or DigiDoc desktop application, accessible from https://github.com/open-eid/DigiDoc4-Client.

### Determining the validation status {#validation-status}

After validating the signed DigiDoc document, the validation result must be determined by the library's user. Final validation result must be one of the possible validation statuses that are described below, the status must be chosen according to its priority.
The validation status priorities have to be applied in two cases:
1. **Returning a validation result of a single signature:** If there are more than one validation errors that occur when validating a single signature in DigiDoc container then the overall status of the signature should be chosen according to the status priorities.
2. **Returning a validation result of the whole DigiDoc container:** If there are more than one signatures in a DigiDoc container and the signatures have different validation statuses or validation of the container structure returns a different status then the overall status of the DigiDoc file should be chosen according to the status priorities.

> [!NOTE]
> The user of the library has to determine the validation status according to the error code returned by the library's validation method.

**Priority 1: INDETERMINATE/UNKNOWN**

Error codes:
- **10** CertificateIssuerMissing (signer's certificate is unknown)
- **6** CertificateUnknown (OCSP responder certificate is unknown)

Validation process determines that one or more of the certificates included in the document are unknown or not trusted, i.e. the certificates have been issued by an unknown Certificate Authority (the CA has not been added to trusted list). Notes:
- The file and signature(s) are not legally valid.
- If the CA will later be added to the trusted list/trust store then the validation status can change to any of the other statuses described in the current list.

Suggested warning message (also displayed in DigiDoc desktop application): "Signature status is displayed as unknown if you don't have all validity confirmation service certificates and/or certificate authority certificates available in TSL"

**Priority 2: INVALID**

Error codes: all errors except of the ones that are regarded as warnings by the library's user.

Validation process returns error(s), the errors have not been explicitly determined as minor error(s) by the library's user.
- The file and signature(s) are not legally valid.
- No further alterations should be made to the file, i.e. no signatures should be added or removed.

**Priority 3: VALID WITH WARNINGS**

Error codes: see [Validation status VALID WITH WARNINGS](#validatewarnings).

Validation process returns error(s) that have been previously explicitly categorized (by the library's user) as minor technical errors. Note that this status is used only in exceptional cases, more details of which are given in the next chapter.
- The file and signature(s) are handled as legally valid.
- The error(s) are regarded as validation warnings.
- Validation warnings should be displayed to the user.
- No further alterations should be made to the file, i.e. no signatures should be added or removed.
- Creator of the file should be informed about the error situation.

**Priority 4: VALID**

Error codes: N/A

Validation process returns no errors. The signature is legally valid.

The error codes described above are defined in Exception.h source file.

Sample code of DigiDoc file validation can be found from digidoc-tool.cpp utility program, from the following method:
```cpp
    open(int argc, char* argv[]); //utility program's command "open"
```

#### Validation status VALID WITH WARNINGS {#validatewarnings}

In special cases, validation errors can be regarded as minor technical errors and the file's validation status can be regarded as VALID WITH WARNINGS instead.

> [!WARNING]
> User of the DigiDoc library has to decide on his/her own when to use VALID WITH WARNINGS status instead of INVALID: there may be different interpretations of the severity of validation errors in different information systems then the final decision when to use this status has to be made by the library's user according to the requirements of the specific information system.

It is recommended to use the validation status VALID WITH WARNINGS in case of the error situations that are listed below - these error situations are regarded as VALID WITH WARNINGS in DigiDoc applications and software libraries, including:
- DigiDoc desktop application,
- Libdigidocpp and DigiDoc4j software libraries' utility programs.

Validation error codes recommended to be handled as VALID WITH WARNINGS:

**12 RefereneceDigest Weak, 13 SignatureDigestWeak** (BDOC 2.1 / ASiC)

Weaker digest method (SHA-1, SHA-224 or SHA3-224) has been used than recommended when calculating either `<Reference>` or `<Signature>` element's digest value.

Suggested warning message (also displayed in DigiDoc desktop application): "The current DigiDoc container uses weaker encryption method than officially accepted in Estonia."

**16 ProducedATLateWarning** (BDOC 2.1 TS / ASiC)

This warning applies whenever the OCSP response's `producedAt` is more than
15 minutes after the time-stamp token's `TSTInfo.genTime` as defined in
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html).

Suggested warning message: "Time-stamp and OCSP issuance time difference is over 15 minutes."

**14 DataFileNameSpaceWarning** (DDOC 1.0, DDOC 1.1, DDOC 1.2, DDOC 1.3)

`<DataFile>` element's xmlns attribute is missing.

Suggested warning message (also displayed in DigiDoc desktop application): "This DigiDoc documents has not been created according to specification, but the digital signatures is legally valid. You are not allowed to add or remove signatures to this container."

More info: https://www.id.ee/en/article/digital-signing-and-electronic-signatures/

**15 IssuerNameSpace Warning** (DDOC 1.1, DDOC 1.2, DDOC 1.3)

`<IssuerSerial><X509IssuerName>` and/or `<IssuerSerial><X509SerialNumber>` element's xmlns attribute is missing.

Suggested warning message (also displayed in DigiDoc desktop application): "This DigiDoc documents has not been created according to specification, but the digital signatures is legally valid. You are not allowed to add or remove signatures to this container."

More info: https://www.id.ee/en/article/digital-signing-and-electronic-signatures/

**22 GeneralWarning** (formats validated through SiVa)

A warning with no more specific code, such as "Old and unsupported format:
SK-XML version: 1.0". The exception message contains the text returned by SiVa.
If validation reports only warnings, digidoc::Signature::Validator returns
`Warning`. Available since version 4.6.0.

Suggested warning message: the exception message.

**N/A (Separate error code has not been determined.)** (DDOC 1.0, DDOC 1.1, DDOC 1.2)

DigiDoc file's version is older than currently supported. Note that the error situation affects only the container and not the signatures, therefore, in DigiDoc libraries, it is returned and displayed only at container level.

Suggested warning message (also displayed in DigiDoc desktop application): "The current file is a DigiDoc container that is not supported officially any longer. You are not allowed to add or remove signatures to this container"

More info: https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/

## Extending container validity {#extend-validity}

Since version 4.5.0, digidoc::Container::extendContainerValidity provides the high-level workflow for extending the validity evidence of a container. The method sets the required signer profile automatically and uses the following strategy:
- eligible ASiC-E LT-level signatures are extended in place with archive time-stamps;
- an ASiC-S TimeStampToken is extended in place with an ASiC archive manifest and a new time-stamp token;
- when in-place extension is unsuitable, the original container is embedded as the data file of a new timestamped ASiC-S container.

Only signatures with an Estonian signing certificate are considered for in-place extension, and e-seal signatures are skipped. A container with no applicable Estonian signatures, or with only T-level signatures lacking OCSP validation data, cannot be extended by this workflow.

```cpp
auto doc = digidoc::Container::openPtr("signed-document.asice");
digidoc::Signer *signer = ...;
std::size_t extendedCount = 0;

if(auto wrapped = digidoc::Container::extendContainerValidity(*doc, signer, extendedCount))
    doc = std::move(wrapped); // original container was wrapped in a new ASiC-S container
// Otherwise doc was extended in place and extendedCount contains the number
// of signatures that received new validity evidence.
doc->save();
```

The returned unique pointer is empty when extension was performed in place. It contains the new ASiC-S container when wrapping was necessary; in that case extendedCount is zero. The caller must save the modified or newly returned container.

The generated language bindings expose the same workflow with language-specific return values:
- C#: `Container.extendContainerValidity(doc, signer, out ulong extendedCount)` returns the wrapping container, or null for an in-place extension.
- Python: `Container.extendContainerValidity(doc, signer)` returns a tuple `(wrapping_container_or_None, extended_count)`.
- Java: `Container.extendContainerValidity(doc, signer)` returns the wrapping container, or null for an in-place extension; the count is not exposed.

In every binding, replace the original container with the returned container when the return value is not null/None, then save the resulting container. A null/None result means the original object was modified in place.

## Extracting data files {#extracting}

A data file can be extracted from container and written to the specified location in the file system or to an output stream.
1. You can write the data file to a stream and keep it in memory:
   ```cpp
   void digidoc::DataFile::saveAs(std::ostream &os) const;
   ```
2. The file can be written to file system with the following method:
   ```cpp
   void digidoc::DataFile::saveAs(const std::string &path) const;
   ```

List of all the document’s data files can be retrieved with the following method:
```cpp
std::vector<digidoc::DataFile *> digidoc::Container::dataFiles() const;
```

For example, read in a DigiDoc document and write its data files to file system as follows:
```cpp
auto doc = digidoc::Container::openPtr("<input-file's-path>");
for(const digidoc::DataFile *file: doc->dataFiles()) {
    try {
        std::string dst = file->fileName();
        file->saveAs(dst);
    } catch(const digidoc::Exception &e) {
        printf("  Document %s extraction: FAILED\n", file->fileName().c_str());
    }
}
```

## Removing signatures and data files {#removing}

In order to remove a signature from DigiDoc document, use the following method:
```cpp
void digidoc::Container::removeSignature(unsigned int index);
```

Data files can be removed from a container only after all of its signatures have been removed. Use the following method to remove a data file from DigiDoc container:
```cpp
void digidoc::Container::removeDataFile(unsigned int index);
```

The index parameters of the methods above are the signature and data file sequence numbers in the container, starting from zero.

> [!NOTE]
> Directly modifying the data file or initial signature of an existing ASiC-S container is not supported. Adding archive-manifest time-stamp layers through digidoc::Container::extendContainerValidity is supported. Signatures cannot be removed from an ASiC-S container while an enclosed DDoc opened through SiVa is exposed.

## Shutting down the library {#shutting-down}

After finishing work with Libdigidocpp, then the last task is to shut down the library:
```cpp
digidoc::terminate();
```

The termination method releases the configuration and shuts down the libraries used in Libdigidocpp implementation. Temporary data files are deleted earlier, when their container is destroyed.
