# Libdigidocpp Programmer's Guide {#manual}

## Using Libdigidocpp API {#usage}

Note that Libdigidocpp uses internal memory buffers in case of all the operations, so that intermediary data is not written to temporary files on the disk. Also, the data files to be added to a DigiDoc container can be read from a data stream and later extracted from the container to a stream so that the data can be kept in memory.

### String encoding {#string-encoding}

All `std::string` values passed to or returned from the API are UTF-8 encoded. This applies to file paths, media types, and all other string parameters and return values throughout the library.

Supply ordinary text, not XML-escaped strings. The library escapes values when
writing XML: `&` is accepted as text, and a literal `&#x1B;` remains that literal
string rather than becoming an ESC character. XML escaping cannot make a
disallowed character acceptable as input.

### Initialization {#initialization}

Libdigidocpp's initialization method conducts the following operations:
1. initializes dependent libraries (see also \ref libraries)
2. loads configuration settings from default configuration files
3. initializes trust anchors: initializes TSL lists. See \ref TSL-init for more information about the TSL initialization process.

If you would like to use non-default configuration settings then call out the configuration file's initialization before initializing the library, for example:
```cpp
    // Optionally initialize global configuration file to use non-default settings
    digidoc::Conf::init(new digidoc::XmlConf("<file-path-and-name>"));
    // Initialize the library
    digidoc::initialize();
```

The digidoc::XmlConf class must be used in order to access all the configuration methods that are available.

> [!NOTE]
> If you would like to use different configuration values that are fixed as constants in the digidoc::Conf configuration class then it is possible to extend the class and override the values that need to be reset.

### Creating and signing a DigiDoc document (local signing) {#creating}

#### Creating a DigiDoc container {#containercreate}

Create a new container object and specify the DigiDoc document's type, for example:
```cpp
    auto doc = digidoc::Container::createPtr("<output-file's-path>"); // create new container
```
Container class is used to incorporate the data of a DigiDoc document.

#### Creating and timestamping an ASiC-S container {#asics-create}

Create an ASiC-S container by using an .asics or .scs output file name. An ASiC-S TimeStampToken container supports exactly one data file and one initial \ref RFC3161 "RFC 3161" time-stamp token.

```cpp
auto doc = digidoc::Container::createPtr("timestamped-document.asics");
doc->addDataFile("document.txt", "text/plain");

digidoc::Signer *signer = ...;
signer->setProfile("TimeStampToken"); // "time-stamp-token" is also accepted
digidoc::Signature *timestamp = doc->sign(signer);
timestamp->validate();
doc->save();
```

ASiC-S TimeStampToken creation uses the one-step digidoc::Container::sign method. External two-step signing with digidoc::Container::prepareSignature is not supported for this format. Additional archive-manifest time-stamp layers can be added with the workflow described in \ref extend-validity.

#### Adding data files {#adddatafile}

Data files can be added to a DigiDoc container in two alternative ways:
1. adding the data from an input stream (i.e. the data file contents can be read from internal memory buffer):
   ```cpp
       std::unique_ptr<std::istream> is = ...;
       void digidoc::Container::addDataFile(std::move(is), // input stream
           const std::string &fileName, // file name that is written to the container
           const std::string &mediaType); // mime type of the data file
   ```
2. adding the data by reading the it from file system
   ```cpp
       void digidoc::Container::addDataFile(const std::string &path, //data file's name and path in file system
           const std::string &mediaType); // mime type of the data file
   ```

Parameter mediaType in the methods above stands for a MIME type of the data file, for example "text/plain" or "application/msword". Value "application/octet-stream" is used by default.
Calling out any of the methods listed above shall create a new DataFile object and add it to the DigiDoc container's data file collection.
Note that in order to add a data file to a container, the container has to be unsigned and there shouldn't be an existing data file with the same name in the container. If a container is signed then it is possible to add data files to it only after the signatures are removed.

Both overloads reject stored file names and MIME types that are not valid UTF-8 or contain characters disallowed by XML 1.0, such as ESC (U+001B) or NUL (U+0000). The check runs before the data file is added and does not modify the supplied metadata. It does not change how existing containers are opened.

The stream overload's fileName is the name stored inside the container. It must be a single non-empty path component: ".", "..", forward slashes, and backslashes are rejected. The file-system overload accepts a source path and stores only its base name. When an existing ASiC-E container is opened, safe relative subdirectories separated by forward slashes are accepted, but absolute paths, backslashes, trailing slashes, and empty, ".", or ".." path segments are rejected. ASiC-S data files must be at the container root.

> [!WARNING]
> It is important to pay attention that the data file's mime type value in `manifest.xml` file and in `signatures*.xml` file's `<DataObjectFormat><MimeType>` element are the same, otherwise the signature is invalid! In case of the ordinary signature creation process, the library sets the correct value automatically. However, if you create a ASiC-E container with Libdigidocpp library and want to add `signatures*.xml` file that you have received from another source then make sure that the data files' mime-type values in manifest-xml file and in `signatures*.xml` file are the same.

> [!WARNING]
> Data file’s mime-type value must be formatted as specified in \ref RFC2045 "RFC 2045", section 5.1, i.e. the "type" and "subtype" values must be separated with a forward slash character.

> [!WARNING]
> It is recommended not to use special characters in the data file’s name, i.e. it is suggested to only use the characters that are categorized as "unreserved" according to \ref RFC3986 "RFC 3986".

> [!NOTE]
> By default, it is recommended to use data file mime-type value "application/octet-stream" for all file types.

> [!NOTE]
> For resource-exhaustion protection, structural and other non-data ZIP entries, such as manifests and signature XML, are limited to 10 MiB when read into memory. HTTP service responses are also limited to 10 MiB after decompression. Data files use a separate streaming and temporary-file strategy and are not subject to the 10 MiB metadata limit.

#### Adding signatures {#API-add-sign}

It is possible to add a signature to a container only if it contains at least one data file, multiple signatures can be added to a single container. The signer's certificate and PIN code to access the private signature key are required during signing.

> [!NOTE]
> Libdigidocpp library uses TSL lists (Trust Service Status list) to obtain information about trusted certificates during signature creation process. See also \ref TSL-overview "TSL overview", \ref TSL "TSL standard" and \ref CA-settings "Configuring TSL settings".

Signing can be done by using PKCS#11 module for accessing the signature token. PKCS#11 module is the default module for singing with smart card (e.g. Estonian ID card or any other smart card provided that you have the external native language PKCS#11 driver for it). See also \ref pkcs11-settings.
```cpp
    digidoc::PKCS11Signer *signer = new digidoc::PKCS11Signer("<PKCS11-driver-path>");
    // optionally specify PKCS#11 driver's location. If left  unspecified then location is
    // looked up from configuration file's parameter "pkcs11.driver.path".
    std::string pin = "<pin-code>"; //PIN2 in case of Estonian ID cards
    signer->setPin(pin);
```
If you would like to add PIN insertion dialog window for the signer to enter the PIN code then you can write a new class which extends the PKCS11Signer class, overwrite the `std::string pin(const X509Cert &cert)` method and write your own PIN dialog implementation code there.

##### Optionally specify the signature profile {#API-sign-profile}

The supported signature profiles are (see also \ref Supported, under "Signature profiles"):
- "time-stamp" (TS) - signature profile in case of which the certificate validity information is added to the signature with an OCSP confirmation (retrieved from OCSP server); the signing time information is added with a time-stamp token (retrieved from a time-stamping service). Signature creation time is the issuance time recorded in the token's \ref RFC3161 "RFC 3161 TSTInfo.genTime" field.

If the signature profile value is not specified then then a "time-stamp" profile is used by default.

Set the profile value as follows:
```cpp
std::string profile = "time-stamp"; // or "time-stamp-archive"
signer->setProfile(profile);
```

##### Optionally specify additional signer's data {#API-sign-data}

Signature production place and signer role are optional signed meta-data about the signature. If left unspecified then the respective elements in the `signatures*.xml` file are created with no contents.

Production-place fields, including the street address accepted by
digidoc::Signer::setSignatureProductionPlaceV2, and signer roles must be valid
UTF-8 and contain only characters allowed by XML 1.0. The setters reject invalid
values before updating the stored signer metadata. Supply ordinary text as
described in \ref string-encoding.

```cpp
    std::string city, state, postalCode, country;
    std::vector<std::string> roles;
    signer->setSignatureProductionPlace(city, state, postalCode, country); // location where the signature is created
    signer->setSignerRoles(roles); // role(s) of the signer
```

##### Optionally specify signature digest method {#API-signature-hash}

By default, the hash that is being signed is calculated with SHA-256 algorithm.
You can also use a different digest algorithm for calculating the hash that is signed (this does not affect calculating other hash values). For that, use the `digidoc::Signer::setMethod(const std::string &method)` method.

##### Create the signature {#API-sign-create}

The signing method also adds validation data from external services (OCSP and time-stamping servers). Note that the OCSP responder and time-stamping server settings (in case of TS profile) should be configured before calling out the following method (see also \ref initialization and \ref parameters). By default, the RIA's time-stamping service https://eid-dd.ria.ee/ts is used.
Container holds the Signature object reference and there is no need cleanup memory.

```cpp
Signature *signature = doc->sign(signer);
```

##### Validating the created signatures {#validatesig}

After the signature has been added to the container, it should be validated before writing the signed container to an output file. For validating the signature, do as follows:
```cpp
    signature->validate();
```
The validation method above validates the signed data files', signer certificate's and OCSP confirmation's correspondence to the signature value. Note that the validation method above does not validate other signatures which may belong to the same container.

> [!NOTE]
> See also \ref validate about more information for validating existing signatures and signature containers.

##### Save container changes {#savesig}

After the signature has been added and validated, container changes should be saved (\ref containeropen):
```cpp
    doc->save();
```

### Creating and signing a DigiDoc document (external signing, e.g. in browser) {#websigning}

External signing (two-step signing) can be used in case of signing in web applications, where the signature value is calculated externally, via a browser plug-in or extension.

In order to conduct web signing with Libdigidocpp library, do as follows:
Container holds the Signature object reference and there is no need cleanup memory.

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
5. Add time-stamp and OCSP data to Signature object, according to the signature's profile (see also section \ref API-sign-profile for more information):
   ```cpp
   signature->extendSignatureProfile(signer);
   ```
6. Write the document to output, as specified in section \ref containeropen

### Reading and writing DigiDoc documents {#containeropen}

In order to read an existing DigiDoc file from the file system, do as follows:
```cpp
    auto doc = digidoc::Container::openPtr("<input-file's-path>");
```
The method above reads in the DigiDoc file from the specified location in file system and creates the respective Container object representing the document's data. The file's structure is also validated during its parsing according to the corresponding standards.

> [!NOTE]
> Formats that are not validated locally are sent to the \ref SiVa service while opening. Pass a digidoc::ContainerOpenCB to digidoc::Container::openPtr to control online access; the callback is also required for opening a DDoc enclosed in an ASiC-S container. See \ref siva-requests.

Write a DigiDoc file (represented with a Container object) to file system with the following method:
```cpp
    digidoc::Container::save("<output-file's-path>");
```

> [!NOTE]
> ASiC-S containers with TimeStampToken signatures can be saved. Saving a read-only format or an unsupported ASiC-S signature variant throws a digidoc::Exception.

### Validating signature containers and signatures {#validate}

Validation of a signed DigiDoc document consists of three main steps:
1. Call out the main validation method of the library. If there are multiple validation errors then get the errors list.
2. Check for additional errors/warnings (separate implementation);
3. Determine the validation status of the document (according to the returned error codes and validation status priorities).

#### Using the main validation method {#main-method}

You can validate a signature and its validation data - OCSP confirmation and time-stamp (in case of TS profile) - with method:
```cpp
void digidoc::Signature::validate();
```
If an exception is thrown from the validation method then the signature can be either **INVALID** or **VALID WITH WARNINGS**; otherwise the signature is VALID. Before determining the final validation status, additional errors must be checked, as described in the following chapters.

If an exception is thrown then its causes can be retrieved with the following method:
```cpp
std::vector<digidoc::Exception> digidoc::Exception::causes();
```

#### Checking for additional errors/warnings {#additional}

There is a validation case that is not checked in the default validation method of the library, instead, separate method for checking this specific situation has to be implemented by the library’s user. In Libdigidocpp library, checking for an old file format must be done separately.

The following subchapter describes how this check can be implemented. After checking for old signature format errors/warnings, collect all of the error codes and continue with determining the validation status as described in the next chapter. It is possible to check the source code of digidoc-tool or DigiDoc desktop application, accessible from https://github.com/open-eid/DigiDoc4-Client.

#### Determining the validation status {#validation-status}

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

- Sample file: `unknown_CA_TS.asice` (BDOC 2.1, time-stamp profile)
- Sample file: `unknown_CA_TM.asice` (BDOC 2.1, time-mark profile)

**Priority 2: INVALID**

Error codes: all errors except of the ones that are regarded as warnings by the library's user.

Validation process returns error(s), the errors have not been explicitly determined as minor error(s) by the library's user.
- The file and signature(s) are not legally valid.
- No further alterations should be made to the file, i.e. no signatures should be added or removed.

**Priority 3: VALID WITH WARNINGS**

Error codes: see \ref validatewarnings.

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

##### Validation status VALID WITH WARNINGS {#validatewarnings}

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

- Sample file: `weak-sha1-warning-TS.asice` (time-stamp profile)
- Sample file: `weak-sha1-warning-TM.bdoc` (time-mark profile)

**16 ProducedATLateWarning** (BDOC 2.1 TS / ASiC)

The difference between the time-stamp issuance time (\ref RFC3161 "RFC 3161 TSTInfo.genTime") and the OCSP response's issuance time (producedAt value) exceeds 15 minutes but is less than 24 hours.

Suggested warning message: "Time-stamp and OCSP issuance time difference is over 15 minutes."

- Sample file: `TS_OCPS_difference_exceeds_15min.asice`

**14 DataFileNameSpaceWarning** (DDOC 1.0, DDOC 1.1, DDOC 1.2, DDOC 1.3)

`<DataFile>` element's xmlns attribute is missing.

Suggested warning message (also displayed in DigiDoc desktop application): "This DigiDoc documents has not been created according to specification, but the digital signatures is legally valid. You are not allowed to add or remove signatures to this container."

More info: https://www.id.ee/en/article/digital-signing-and-electronic-signatures/

- Sample file: `datafile_xmlns_missing.ddoc`

**15 IssuerNameSpace Warning** (DDOC 1.1, DDOC 1.2, DDOC 1.3)

`<IssuerSerial><X509IssuerName>` and/or `<IssuerSerial><X509SerialNumber>` element's xmlns attribute is missing.

Suggested warning message (also displayed in DigiDoc desktop application): "This DigiDoc documents has not been created according to specification, but the digital signatures is legally valid. You are not allowed to add or remove signatures to this container."

More info: https://www.id.ee/en/article/digital-signing-and-electronic-signatures/

- Sample file: `issuerserial_xmlns_missing.ddoc`

**N/A (Separate error code has not been determined.)** (DDOC 1.0, DDOC 1.1, DDOC 1.2)

DigiDoc file's version is older than currently supported. Note that the error situation affects only the container and not the signatures, therefore, in DigiDoc libraries, it is returned and displayed only at container level.

Suggested warning message (also displayed in DigiDoc desktop application): "The current file is a DigiDoc container that is not supported officially any longer. You are not allowed to add or remove signatures to this container"

More info: https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/

- Sample file: `old_digidoc_format_1.0.ddoc`

#### Additional information about validation {#validation-info}

##### Overview of validation activities {#validation-overview}

Overview of validation activities is as follows:
1. checking that all the data files and signature’s meta-data (signer’s role, etc.) are included in the signature by calculating the data objects’ digest values and comparing them with the `<Reference>` element values in the signature;
2. checking that the claimed signer’s certificate is the actual certificate that was used for signing; checking that the "Non-repudiaton" value is set in the "Key Usage" extension of the signer’s certificate;
3. checking that the signature value is correct by decrypting the value with the signer’s public key and comparing the result with digest calculated from `<SignedInfo>` element block;
4. case of time-stamp corresponds to the signature value (by comparing the digest value of `<SignatureValue>` element’s value and TS response’s digest value);
5. checking that the OCSP response confirms the signer certificate’s validity and case of time-mark corresponds to the signature value (by comparing the digest value of `<SignatureValue>` element’s value and OCSP response’s nonce value);
6. checking that the signer’s, TSA and OCSP responder’s certificates are trusted (i.e. the certificates’ issuers are registered in trust store).

> [!NOTE]
> Libdigidocpp library uses TSL lists (Trust Service Status list) to obtain information about trusted certificates during signature validation process. See also \ref TSL-overview "TSL overview", \ref TSL "TSL standard" and \ref CA-settings "Configuring TSL settings".

For formats validated through SiVa, archive time-stamp information returned by the service is available through digidoc::Signature::ArchiveTimeStamps in the same way as locally validated archive time-stamps.

### Extending container validity {#extend-validity}

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

### Extracting data files {#extracting}

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

### Removing signatures and data files {#removing}

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

### Shutting down the library {#shutting-down}

After finishing work with Libdigidocpp, then the last task is to shut down the library:
```cpp
digidoc::terminate();
```

The termination method closes libraries used in Libdigidocpp implementation and deletes temporary files that may have been written to disk when working with the library.

### Exception handling {#exceptions}

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
