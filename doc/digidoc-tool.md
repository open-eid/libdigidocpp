# digidoc-tool {#digidoc-tool}

The command line utility program digidoc-tool which is included in the Libdigidocpp distribution can be used to test the library or simply use it directly to handle digitally signed documents.

\note The utility program is intended for testing and presentation of sample implementation of the library’s API. The interface of the utility program is not fixed and its long-term stability is not guaranteed.

The general format for executing the program is:
```
> digidoc-tool [command] [options] [input/output file]
```

Available optional options on all commands:
<table>
<tr><td>\-\-nocolor	</td><td>
Disable terminal colors</td></tr>
<tr><td>\-\-loglevel=[0,1,2,3,4]	</td><td>
Log level: 0 - none, 1 - error, 2 - warning, 3 - info, 4 - debug</td></tr>
<tr><td>\-\-logfile=	</td><td>
File to log, empty to console</td></tr>
</table>

## Creating and signing a document (local signing) {#Creating}

Command "create" can be used to create a new DigiDoc container, add data files, optionally some meta-info about the signer and sign the document. The output extension selects ASiC-E (.asice or .sce) or ASiC-S (.asics or .scs). ASiC-S creation requires exactly one data file and the TimeStampToken signature profile.
General form of the command is:
```
> digidoc-tool create --file=<data-file> <output-container-file>
```

Available options:
<table>
<tr><td>\-\-file=	</td><td>Required</td><td>
Data file(s) to be signed. The option can occur multiple times.

\warning It is recommended not to use special characters in the data file’s name, i.e. it is suggested to only use the characters that are categorized as "unreserved" according to \ref RFC3986 "RFC 3986".</td></tr>
<tr><td>\-\-mime=	</td><td>Optional</td><td>
Specifies the data file's mime-type value. When used then must be written right after the "--file" parameter. If left unspecified then the default mime-type value "application/octet-stream" is used.

\warning Data file’s mime-type value must be formatted as specified in \ref RFC2045 "RFC 2045", section 5.1, i.e. the "type" and "subtype" values must be separated with a forward slash character.</td></tr>
<tr><td>\-\-dontsign	</td><td>Optional</td><td>
Don't sign the newly created container.</td></tr>
</table>

Additional options for the "create" command are the same as for "sign" command (see \ref Adding).

Sample commands for creating and signing DigiDoc files:

```
Sample: creating an ASiC-S container with one data file and an RFC 3161 time-stamp token
> digidoc-tool create --file=file1.txt --mime=text/plain --profile=TimeStampToken timestamped-document.asics

The profile alias time-stamp-token is also accepted.
```

```
Sample: creating new ASiC-E file, adding multiple data files and signing via PKCS#11 driver
> digidoc-tool create --file=file1.txt --mime=text/plain --file=file2.pdf --mime=application/pdf --country=Estonia
--state=Harjumaa --city=Tallinn --postalCode=12345 --pkcs11 demo-container.asice

Input:
  --file=file1.txt			- a data file to be added to container
  --mime=text/plain			- data file 'file1.txt' mime-type
  --file=file2.pdf			- a data file to be added to container
  --mime=application/pdf	- data file 'file2.pdf' mime-type
  --country=Estonia			- country where the signature is created
  --state=Harjumaa			- state where the signature is created
  --city=Tallinn			- city where the signature is created
  --postalCode=12345		- postal code of the signature creation location
  --pkcs11					- signing is done via PKCS#11 module
  demo-container.asice		- container to be created
```

```
Sample: creating new ASiC-E file on Windows, adding data file and signing via CNG API
> digidoc-tool create --file=file1.txt --cng demo-container.asice

Input:
  --file=file1.txt			- a data file to be added to container
  --cng						- CNG API is used for signing
  demo-container.asice		- container to be created
```

```
Sample: creating new ASiC-E file on Windows, adding data file and signing via CNG API, dialog windows for certificate selection and PIN insertion are not displayed
> digidoc-tool create --file=file1.txt --cng --selectFirst --pin=01497 demo-container.asice

Input:
  --file=file1.txt			- a data file to be added to container
  --cng						- CNG API is used for signing
  --selectFirst				- the first signing certificate in store is used for signing
  --pin=01497				- PIN code (PIN2 in case of Estonian ID cards)
  demo-container.asice		- container to be created
```

## Creating and signing multiple documents {#createBatch}
Command "createBatch" Takes folder as argument folder/content/to/sign and sign them separate containers.
For additional options look sign command.

## Add additional files to container {#add}
Command "add" for adding additional files to existing unsigned container.
Available options are --file and --mime look "create" command for info.

## Creating and signing a document (external signing, e.g. in browser) {#websign}

Command "websign" can be used to create a new DigiDoc container, add data files, optionally some meta-info about the signer and sign the document. Documents can be created only in ASiC-E format.
External signing use case may be used when signing is done in web applications, the communication with the signer's token and signing the hash is done via a web browser's signing module (plug-in or extension). See also https://web-eid.eu for implementing signing in browser environment.

External signing process with websign command is as follows:
1. After executing the websign command, the utility program outputs the value of hash to be signed (in HEX) to console and waits until user enters the respective signature value
2. Send the hash to be signed to the signing token (e.g. by using the web signing demo page at https://open-eid.github.io/hwcrypto.js/sign.html)
3. Conduct signing, enter PIN2, retireve the signed hash (signature value) from the signing token
4. Enter the signature value (also in HEX) to the console
5. Utility program continues with signing process and outputs the signed container

General form of the command is:
```
> digidoc-tool websign --cert=<signer-certificate> --file=<data-file> <output-container-file>
```

Available options:
<table>
<tr><td>\-\-cert=	</td><td>Required</td><td>
Signer's certificate, in PEM format.</td></tr>
<tr><td>\-\-file=	</td><td>Required</td><td>
Data file(s) to be signed. The option can occur multiple times.</td></tr>
<tr><td>\-\-mime=	</td><td>Optional</td><td>
Specifies the data file's mime-type value. When used then must be written right after the "--file" parameter. If left unspecified then the default mime-type value "application/octet-stream" is used.</td></tr>
</table>

Additional options for the "websign" command are the same as for "sign" command (see \ref Adding).

Sample command for creating and external signing of ASiC-E files:

```
Sample: creating new ASiC-E file, specifying signers certificate, adding data files and other meta-data and calculating the RSA signature value in browser
> digidoc-tool websign --cert=signer.cer --file=file1.txt --file=file2.pdf --country=Estonia --state=Harjumaa --city=Tallinn --postalCode=12345 --profile=time-stamp demo-container.asice

Input:
  --cert=signer.cer		- signers certificate
  --file=file1.txt		- a data file to be added to container
  --file=file2.txt		- a data file to be added to container
  --profile=time-stamp	- profile of the signature
  --country=Estonia		- country where the signature is created
  --state=Harjumaa		- state where the signature is created
  --city=Tallinn		- city where the signature is created
  --postalCode=12345	- postal code of the signature creation location
  demo-container.asice	- container to be created
```


## Opening document, validating signatures and extracting data files {#Opening}
Command "open" reads an existing document, prints its contents and validates its signatures. The --extractAll option extracts data files to disk. Supported ASiC-E, ASiC-S and legacy BDOC 2.1 variants are handled locally. PDF, legacy DDOC and ASiC containers with CAdES signatures are sent to the SiVa Online Service for validation; --offline disables that fallback, so those service-backed formats cannot be opened offline. BDOC 1.0 is not supported.
General form of the command is:
```
> digidoc-tool open <input-container-file>
```

Available options:
<table>
<tr><td>\-\-extractAll	</td><td>Optional</td><td>
If set, then all of the input container’s data files are extracted and written to disk without validating signatures. If an output directory is not specified with the value of this parameter then the extracted files are written to the current working directory.

On Windows, reserved device names are prefixed with an underscore (CON becomes _CON). Characters that are invalid in Windows filenames, control characters, and trailing spaces or dots are replaced with underscores. Extraction fails rather than overwriting an existing output file.</td></tr>
<tr><td>--validateOnExtract	</td><td>Optional</td><td>
If set, then validates container before extracting files.</td></tr>
<tr><td>\-\-offline	</td><td>Optional</td><td>
open container offline (eg. Don't send to SiVa)</td></tr>
<tr><td>\-\-warnings=

(ignore, warning, error)	</td><td>Optional</td><td>
Enables to choose the displaying of validation warnings (if present) of the file being opened. Can be used to test the warnings system of the utility program (see also "Validation status VALID WITH WARNINGS").
The options include:
-	warning – the default value used. The minor technical errors that are considered as warnings, are printed out as warnings.
-	error – the errors that are otherwise considered as warnings (by the utility program), are printed out as errors.
-	ignore – the errors that are otherwise considered as warnings (by the utility program), are not printed out. If there are any other errors present then these are treated as usual.</td></tr>
</table>

Output of the default command contains the following data of the container:
```
  Container file: <container’s file name>
  Container type: <container’s mime-type>
  Documents (<number of data files in container>):
    Document (<data file’s mime-type>): <file’s name> (<file’s size> bytes)
  Signatures (<number of signatures in container>):
    Signature <signature’s sequence number> (<signature’s profile>):
      Validation: <signature validation result: OK/FAILED>
      EPES policy: urn:oid: <signature policy identifier OID>
      SPUri: <URL to the BDOC 2.1 specification document>
      Signature method: <signature method URI>
      Signing time: <signing time according to computer’s settings (not the official signing time)>
      Signing cert: <subject CN field’s value>
      Signed by: <subject CN field’s value>
      Produced At: <time of OCSP response’s issuance, i.e. official signing time>
      OCSP Responder: <OCSP responder certificate CN field’s value>
      Message imprint (<length in bytes>): <OCSP responses nonce field’s or TSA messageImprint value (has to correspond to the &lt;SignatureValue&gt; element’s hash)>
      TS: <TSA certificate CN field’s value>
      TS time: <time of TSA issuance, i.e. official signing time>
      TSA: <archive TSA certificate CN field’s value>
      TSA time: <time of archive TSA issuance, i.e. official signing time>
      Warnings: <possible validation related warnings (see explanation below)>
```

\note By default, if the signature validation process discovered errors that are regarded as minor technical errors in digidoc-tool.cpp utility program then the document is considered as VALID WITH WARNINGS, the errors are printed out as warnings to the end user. See also chapter \ref validation-status.

Sample commands for validating signatures and extracting data files:
```
Sample: opening ASiC-E container, listing its contents and validating signatures
> digidoc-tool open demo-container.asice

Input:
  demo-container.asice	- input DigiDoc file which contents are listed and signatures validated

Output:
  Container type: application/vnd.etsi.asic-e+zip
  Documents (2):
    Document (application/octet-stream): file1.txt (434 bytes)
    Document (application/octet-stream): file2.pdf (476841 bytes)
  Signatures (1):
    Signature 0 (EPES/time-mark):
      Validation: OK
      EPES policy: urn:oid:1.3.6.1.4.1.10015.1000.3.2.1
      SPUri: https://www.skidsolutions.eu/repository/bdoc-spec21.pdf
      Signature method: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
      Signing time: 2013-03-13T08:48:13Z
      Signing cert: MÄNNIK,MARI-LIIS,47101010033
      Signed by: MÄNNIK,MARI-LIIS,47101010033
      Produced At: 2013-05-14T23:41:20Z
      OCSP Responder: TEST of SK OCSP RESPONDER 2011
      Message imprint (51): 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 10 35 D7 45 F1 42 C1 0C 4D 96 EA 1A 13 C4 34 28 B0 8A 0A 07 47 AA 96 72 0D 3B 1C C9 02 D0 4B 15
      TS:
      TS time:
      TSA:
      TSA time:
```

```
Sample: opening ASiC-E container, listing its contents and validating signatures (warnings are displayed as SHA-1 hash function is used in a ASiC-E file)
> digidoc-tool open weak-sha.asice

Input:
  weak-sha.asice			- input file which contents are listed and signatures validated

Output:
  Container type: application/vnd.etsi.asic-e+zip
  Documents (1):
    Document (application/octet-stream): test.txt (314 bytes)
  Signatures (1):
    Signature 0 (EPES/time-mark):
      Validation: OK
      EPES policy: urn:oid:1.3.6.1.4.1.10015.1000.3.2.1
      SPUri: https://www.skidsolutions.eu/repository/bdoc-spec21.pdf
      Signature method: http://www.w3.org/2000/09/xmldsig#rsa-sha1
      Signing time: 2012-11-13T11:04:32Z
      Signing cert: MÄNNIK,MARI-LIIS,47101010033
      Signed by: MÄNNIK,MARI-LIIS,47101010033
      Produced At: 2012-11-13T11:04:45Z
      OCSP Responder: TEST of SK OCSP RESPONDER 2011
      Message imprint (51): 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 10 35 D7 45 F1 42 C1 0C 4D 96 EA 1A 13 C4 34 28 B0 8A 0A 07 47 AA 96 72 0D 3B 1C C9 02 D0 4B 15
      TS:
      TS time:
      TSA:
      TSA time:
      Warnings: RefereneceDigestWeak, SignatureDigestWeak,
```

```
Sample: opening container, extracting its data files
> digidoc-tool open --extractAll demo-container.asice

Input:
  --extractAll=demo		- Extract all files into current folder
  demo-container.asice	- input DigiDoc file that is extracted

Output:
  Extracting documents:
    Document(application/octet-stream) extracted to file1.txt (434 bytes)
    Document(application/octet-stream) extracted to file2.pdf (476841 bytes)
```

```
Sample: opening container, extracting its data files to a specific directory
> digidoc-tool open --extractAll=demo demo-container.bdoc

Input:
  --extractAll=demo		- Extract all files into folder "demo"
  demo-container.bdoc	- input DigiDoc file that is extracted

Output:
  Extracting documents:
    Document(application/octet-stream) extracted to demo/file1.txt (434 bytes)
    Document(application/octet-stream) extracted to demo/file2.pdf (476841 bytes)
```




## Adding signatures {#Adding}
Command "sign" enables adding XAdES signatures to existing ASiC-E and legacy BDOC 2.1 containers. The same signing options are used by "create" to add the initial \ref RFC3161 "RFC 3161" TimeStampToken to a new ASiC-S container; an existing ASiC-S container cannot receive another ordinary signature.
```
> digidoc-tool sign <modified-digidoc-container>
```

<table>
<tr><td>\-\-pin=	</td><td>Optional</td><td>
If PIN is not provided with this parameter value and (the default) PKCS#11 module is used for signing then the utility program asks for the user to insert PIN code to command line during the program’s execution time.</td></tr>
<tr><td>\-\-profile=	</td><td>Optional</td><td>
Profile of the signature. Possible values are:
- TS or time-stamp - a time-stamp and OCSP confirmation will be added to an XAdES signature as validation data.
- TSA or time-stamp-archive - a time-stamp and OCSP confirmation will be added to an XAdES signature as validation data, followed by an archive time-stamp over the certificate and revocation information.
- TimeStampToken or time-stamp-token - create the \ref RFC3161 "RFC 3161" token signature used by a new ASiC-S container.
</td></tr>
<tr><td>\-\-XAdESEN	</td><td>Optional</td><td>
Use XAdES EN profile.</td></tr>
<tr><td>\-\-city=	</td><td>Optional</td><td>
City where the signature is created.</td></tr>
<tr><td>\-\-street=	</td><td>Optional</td><td>
streetAddress of production place in XAdES EN profile.</td></tr>
<tr><td>\-\-state=	</td><td>Optional</td><td>
State or province where the signature is created.</td></tr>
<tr><td>\-\-postalCode=	</td><td>Optional</td><td>
Postal code of the place where the signature is created.</td></tr>
<tr><td>\-\-country=	</td><td>Optional</td><td>
Country of origin. ISO 3166-type 2-character country codes are used (e.g. EE)</td></tr>
<tr><td>\-\-role=	</td><td>Optional</td><td>
Signer’s role(s). The option can occur multiple times.</td></tr>
<tr><td>\-\-sha(224,256,384,512)	</td><td>Optional</td><td>
Used for testing purposes. Specifies the hash function that is used when calculating digest values. If not specified then SHA-256 is used by default.</td></tr>
<tr><td>\-\-sigsha(224,256,384,512)	</td><td>Optional</td><td>
Used for testing purposes. Specifies the hash function that is used for calculating the hash that is being signed. If not specified then SHA-256 is used by default.</td></tr>
<tr><td>\-\-sigpsssha(224,256,384,512)	</td><td>Optional</td><td>
Used for testing purposes. With RSA keys RSA-PSS padding is used. Specifies the hash function that is used for calculating the hash that is being signed. If not specified then SHA-256 is used by default. Same as \-\-sigsha* with \-\-rsapss</td></tr>
<tr><td>\-\-rsapkcs15	</td><td>Optional</td><td>
Option to change RSA Signature padding (RSA PKCS1.5).</td></tr>
<tr><td>\-\-rsapss	</td><td>Optional</td><td>
Option to change RSA Signature padding (RSA PSS).</td></tr>
<tr><td>\-\-tsurl=	</td><td>Optional</td><td>
Option to change TS URL.</td></tr>
<tr><td>\-\-userAgent=	</td><td>Optional</td><td>
Additional application information sent to the TSA or OCSP service.</td></tr>
<tr><td>\-\-dontValidate	</td><td>Optional</td><td>
Don't validate container on signature creation.</td></tr>
</table>


Options for specifying module used for accessing the signing token - possible alternatives are PKCS#11, CryptoAPI/CNG and PKCS#12 (for testing purposes). When signing module is not specified then PKCS#11 module is used by default.
<table>
<tr><td>\-\-pkcs11[=]	</td><td>Optional</td><td>
Signing is done via PKCS#11 module - the default module for singing with smart card in Linux and macOS. When signing via PKCS#11 module then the parameter’s value can be used to specify the path and filename of PKCS#11 driver in your file system. For example, "opensc-pkcs11.dll" in Windows environment and "opensc-pkcs11.so" in Linux and OSX.
If the parameter’s value is left unspecified then PKCS#11 driver’s location is looked up from configuration file (see also chap. \ref parameters).</td></tr>
<tr><td>\-\-cng	</td><td>Optional</td><td>
Set the parameter to sign via Microsoft CNG API (in Windows environment). If "--pin" parameter’s value is not set then PIN insertion dialog is displayed to the user. Parameter "--cng" may optionally be used along with parameter "--selectFirst" or "--thumbprint".</td></tr>
<tr><td>\-\-selectFirst	</td><td>Optional</td><td>
Additional parameter that can optionally be used along with parameter "–cng". When the parameter is set then the first certificate in Windows certificate store is chosen for signature creation. If the parameter is not set then certificate selection dialog window is displayed to user.</td></tr>
<tr><td>\-\-thumbprint	</td><td>Optional</td><td>
Additional parameter that can optionally be used along with parameter "–cng". When the parameter is set then the certificate by thumbprint in Windows certificate store is chosen for signature creation. If the parameter is not set then certificate selection dialog window is displayed to user.</td></tr>
<tr><td>\-\-pkcs12=	</td><td>Optional</td><td>
Signing is done via PKCS#12 module - can be used for testing purposes. Enables to use a PKCS#12 software token (containing the signing certificate and private key) for signature creation. Note that the created signature is not a valid signature and it is not equal to handwritten signature as the PKCS#12 software token is not considered a secure signature creation device.</td></tr>
</table>

Sample commands for adding signatures:
```
Sample: adding a signature via PKCS#11 driver
> digidoc-tool sign --pkcs11 demo-container.asice

Input:
  --pkcs11				- PKCS#11 module is used for signing
  demo-container.asice	- container to be modified
```

```
Sample: adding a signature via CNG API
> digidoc-tool sign --cng demo-container.asice

Input:
  --cng					- CNG API is used for signing
  demo-container.asice	- container to be modified
```

```
Sample: adding a signature via CNG API, no dialog windows are displayed
> digidoc-tool sign --cng --selectFirst --pin=12345 demo-container.asice

Input:
  --cng					- CNG API is used for signing
  --selectFirst			- the first signing certificate is used for signing
  --pin=12345			- PIN code (PIN2 in case of Estonian ID cards)
  demo-container.asice	- container to be modified
```


## Extending container validity {#Extending}
Command "extend" adds new validity evidence and saves the result. Without --signature, it calls the high-level digidoc::Container::extendContainerValidity workflow: eligible ASiC-E or ASiC-S signatures are extended in place, or the original container is wrapped in a new timestamped ASiC-S container when necessary.

```
> digidoc-tool extend demo-container.asice
```

When one or more --signature options are specified, only those zero-based signature indexes are extended directly with digidoc::Signature::extendSignatureProfile. In this mode --profile selects the target profile and --dontValidate skips validation after each extension.

<table>
<tr><td>\-\-signature=</td><td>Optional</td><td>
Zero-based signature index to extend directly. The option can occur multiple times.</td></tr>
<tr><td>\-\-profile=</td><td>Optional</td><td>
Target profile for direct per-signature extension: TS, TSA, time-stamp or time-stamp-archive. The high-level workflow chooses the required profile automatically when --signature is omitted.</td></tr>
<tr><td>\-\-dontValidate</td><td>Optional</td><td>
Do not validate a directly extended signature after extension.</td></tr>
</table>

```
Sample: directly extend signature 0 to the archive time-stamp profile
> digidoc-tool extend --signature=0 --profile=TSA demo-container.asice
```


## Removing signatures and data files {#Removing}
Signatures and data files can be removed from a DigiDoc container with the command "remove". Note that it is possible to remove data files only from an unsigned container (i.e all signatures must be removed before removing data files). The command is supported with DigiDoc formats BDOC 2.1 and ASiC-E.
General format of the command is:
```
> digidoc-tool remove --document=<doc-id> --signature=<sig-id> <modified-digidoc-container>
```

Available options:
<table>
<tr><td>\-\-document=	</td><td>Optional</td><td>
Specifies the sequence number of the data file that is removed from the container. The sequence numbers are counted from zero.</td></tr>
<tr><td>\-\-signature=	</td><td>Optional</td><td>
Specifies the sequence number of the signature that is removed from the container. The sequence numbers are counted from zero.</td></tr>
</table>
Sample commands for removing signatures and data files:
```
Sample: removing signature from container
> digidoc-tool remove --signature=1 demo-container.asice

Input:
  --signature=1			- sequence number of the signature that is removed
  demo-container.asice	- container to be modified
```
```
Sample: removing data files from container
> digidoc-tool remove --document=0 --document=1 demo-container.asice

Input:
  --document=0			- sequence number of the data file that is removed
  --document=1			- sequence number of the data file that is removed
  demo-container.asice	- container to be modified
```
