Libdigidocpp library [3.13.0](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.0) release notes
--------------------------------------
- Relax validation of BDOC to accept sub-elements of SignatureProductionPlace in any order
- Speed up signing large files by handling them as file stream instead of in-memory
- Improved compatability with Latvian/Lithuanian ASiC-E documents
- XAdES EN support
- Better handling of malicious zip files
- Added ASiC-S validation support
- Improve TSL parsing
- Improve compatibilty with EIDAS
- Disable External Entities parsing
- Use SiVa service for parsing PDF and DDoc (on platforms where libdigidoc backend is missing)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.12.2...v3.13.0)



Libdigidocpp library [3.12.3](https://github.com/open-eid/libdigidocpp/releases/tag/v3.12.3) release notes
--------------------------------------------
- Verify signing certificate QCSD OID-s

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.12.2...v3.12.3)



Libdigidocpp library 3.12.2 release notes
--------------------------------------
Changes compared to ver 3.12.1
- Fix issues found by coverity
- digidoc-tool improvements
- API option to verify PDF validator service SSL certificate
- Added new TSL signing certificates



Libdigidocpp library 3.12.1 release notes
--------------------------------------
Changes compared to ver 3.12.0
- Added Container::prepareWebSignature for C# bindings
- Documentation updates
- Fix crash parsing References without ID attribute
- Handle TSL v5 service status parameters



Libdigidocpp library 3.12.0 release notes
--------------------------------------
Changes compared to ver 3.11.1

- Fix download TSL-s over proxy in case of HTTPS connections
- Behaviour change, proxy tunnel SSL option is now default on
- Export PKCS12Signer class
- Update C# bindings
- Find OCSP certificate from TSL list
- On loading TSL lists, verify HTTP result is 200
- Major API changes, SO version increased to 1. Applications need to adopt new changes and recompile applications.
- Added support for signing in web browser
- Example projects for iOS and Android
- Disable SHA1 support on signature creation
- OCSP nonce compatibility with other digest info headers

List API changes https://github.com/open-eid/libdigidocpp/wiki/API-changes-(v3.12)
List of known issues: https://github.com/open-eid/libdigidocpp/wiki/Known-issues



Libdigidocpp library 3.11.1 release notes
--------------------------------------
Changes compared to ver 3.11.0

- Verify HTTP result before processing TSL lists
- Include cdigidoc.exe

List of known issues: https://github.com/open-eid/libdigidocpp/wiki/Known-issues



Libdigidocpp library 3.11.0 release notes
--------------------------------------
Changes compared to ver 3.10.3

- Improved ECDSA signature size calculation
- Optimized HTTP download speed (e.g. when updating TSL lists) by compressing the traffic (using gzip Content-Encoding)
- Added support for validating BDOC 2.1 time-stamp signatures with archive time-stamps 
- Added option to specify different digest algorithm for the signature value than the default algorithm used in case of other digest values in the signature. 
	- Added API methods Signer::setMethod(), Signer::method(), XmlConfV4::signatureDigestUri()
	- Added configuration parameters signer.digestUri and signer.signatureDigestUri 
	- Added parameter -sigsha(1,224,256,384,512) to digidoc-tool utility program
- Improved OCSPserver access certificate usage, relative pkcs12.cert configuration parameter value is now resolved to the library's installation path, instead of current working directory
- Added option to download TSL-s over proxy in case of HTTPS connections
	- Added API methods XmlConfV4::proxyForceSSL(), XmlConfV4::proxyTunnelSSL() 
	- Added configuration file parameters forceSSL and tunnelSSL
- Fixed OCSP certificate verification, the verification is now done based on the OCSP poducedAt field's time.



Libdigidocpp library 3.10.3 release notes
--------------------------------------
Changes compared to ver 3.10.0

- Updated experimental .NET C# wrapper swig configuration file to recent API
- Included C# wrapper files in Windows installer package
- Filter out CA certificates in PKCS11Signer implementation to support Finland ID-card signing in digidoc-tool
- Improved signature validation, it is now checked that at least one data file is signed
- Disabled OCSP time slot check when requesting OCSP confirmation, the local computer time difference compared to OCSP server time is not checked.



Libdigidocpp library 3.10.0 release notes
--------------------------------------
Changes compared to ver 3.9

- Changed the default BDOC signature profile to BDOC-TS (ASiC-E LT signature with time-stamp) for new signatures. To create a BDOC-TM (LT_TM, i.e. time-mark) signature, specify the "time-mark" profile value in Container::sign(Signer *signer, const string &profile) method call.
- Fixed time zone usage when validating signer certificate validity period's starting time. Previously, "Not yet valid" error message was displayed even if the certificate was actually already valid.
- Improved BDOC signatures*.xml file's XML structure validation. Transforms XML element is now allowed to enhance interoperability.
- Improved TSL functionality
	- In case of BDOC format, checking the trustworthiness of trust services (CA, OCSP, time-stamping services) is now possible only by using TSL lists. Previously used certificate store functionality is no longer supported.
	- Removed country-specific filtering of the national TSLs that are referenced in the European Commission's central TSL list.
	- Added possibility to use multiple parallel European Commission's TSL signing certificates to enable transition to a new certificate, if needed.
	- Added checking of the TSL's officially published SHA-256 digest value online to determine if a newer version of the TSL is available.
	- Added configuration parameter "tsl.onlineDigest" that enables to disable the TSL online SHA-256 digest check.
	- Removed configuration file parameters "tsl.url" and "tsl.cert". The respective values can be set directly from the library's API.
	- Added TSL downloading timeout, the value is set to 10 seconds for each TSL. Added configuration parameter "tsl.timeOut" that can be used to configure the timeout value.
	- Improved TSL loading when proxy is used, proxy settings are ignored in case of HTTPS connections.
- Changed the XmlConf class to deprecated, use XmlConfV2 instead.
- Changed the OCSP responder URL for EID-SK 2011 certificates, http://ocsp.sk.ee is now used.
- Fixed error message text that appears when data file's mime-type in BDOC manifest.xml does not conform with mime-type value in signatures*.xml file. Previously, the displayed mime-type values were interchanged between the signatures*.xml and manifest.xml files.
- The library's release notes is now also copied to the library's documentation: http://open-eid.github.io/libdigidocpp/manual.html#releasenotes 
- Development of the software can now be monitored in GitHub environment: https://github.com/open-eid/libdigidocpp



Libdigidocpp library 3.9 release notes
--------------------------------------
Changes compared to ver 3.8

- Added support for creating and validating BDOC signatures with time-stamps (BDOC-TS profile). 
	- By default, there is no time-stamping service support configured.
	- Added new parameter "ts.url" to digidocpp.conf configuration file that specifies the time-stamping service used during signature creation. 
	- Added support for "time-stamp" profile value for digidoc::Container::sign(Signer *signer, const std::string &profile) method when creating BDOC-TS signature via API.
	- Added time-stamp (TS) profile support for digidoc-tool utility program's "sign" and "create" commands. TS profile can be set with "--profile=TS" parameter.
	- The signature creation time of BDOC-TS signature is the time-stamp's creation time (in case of a signature with time-stamp, the OCSP validity confirmation's creation time is the signing time). 
	- Added validation check for difference between OCSP validity confirmation's production time and time-stamp's production time. An exception is thrown if the OCSP confirmation's time is earlier than time-stamp's time. If the OCSP confirmation's time is later than time-stamp's time by more than 15 minutes then a warning is returned. If the difference is more than 24 hours then exception is thrown. 
- Added support for using TSL (Trusted Service List) list as trust anchor when checking certificates' trustworthiness during signature creation and validation.
	- By default, European Commission TSL list is used (https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml) as source for finding country-specific TSL lists. Finnish, Estonian, Latvian and Lithuanian country-specific TSL lists are used by default.
	- Added TSL usage configuration possibilities to digidocpp.conf file. Use "tsl.autoupdate", "tsl.cache", "tsl.cert" and "tsl.url" configuration parameters to change the default TSL settings.
	- Added command "tsl" to digidoc-tool utility program, the command prints out TSL diagnostics and validates the list.
	- Added possibility to disable all TSL functionality in the library by setting CMake USE_TSL parameter to "false" when building the library.
	- Added class XmlConfV2 that should be used instead of XmlConf class if it is needed to configure time-stamp and TSL related configuration properties. 
	- Added Xalan library for processing TSL files.
- Added support for adding OCSP confirmation to signature if the signer's certificate is issued by "VRK CA for Qualified Certificates - G2" or "VRK Gov. CA for Citizen Qualified Certificates - G2".
- Improved BDOC document's validation, it is now checked that the data file mime-type value in manifest.xml file and the respective value in signatures*.xml file in <DataObjectFormat><MimeType> element are the same.
- Added "--mime=" parameter to digidoc-tool utility program's "create" command. The parameter can be used along with "--file=" parameter to set the mime-type value of a data file. If not set then the default value "application/octet-stream" is used.
- Improved BDOC document's validation, added check for weak hash algorithm (SHA-1) usage in case of ECDSA signatures.
- Improved BDOC signatures*.xml file's XML structure validation. It is now additionally checked that unsupported elements CounterSignature, CompleteCertificateRefs, CompleteRevocationRefs, AttributeCertificateRefs, AttributeRevocationRefs, SigAndRefsTimeStamp, RefsOnlyTimeStamp, AttrAuthoritiesCertValues, AttributeRevocationValues, CommitmentTypeIndicationType, AllDataObjectsTimeStamp, IndividualDataObjectsTimeStampType would not exist in the file.
- Improved processing of special characters in URI attribute values according to RFC3986. Special characters in URI are percent-encoded, except of unreserved characters and delimiters. Both percent-encoded and non-percent-encoded characters are supported during signature's validation. Note that as a result, the files that contain special characters in URI values and have been created with v3.9 might not be compatible with v3.8 of the library.
- Fixed problem that caused erroneous signatures if the data file's name contained colon character.
- Fixed digidoc-tool utility program "extract" command's "--extractAll" parameter functionality. Now, if the parameter is present but there is no extraction directory specified then the files are extracted to the working directory.
- Fixed digidoc-tool utility program's error that caused the program to exit unexpectedly when trying to create or sign a DDOC file.
- Changed Libdigidoc wrapper to fix error which occurred when parsing DDOC document's data file name that contains some specific special characters. Previously, the special characters were erroneously displayed in escaped form.
- Fixed problem in Libdigidoc wrapper when calculating data file's size in the course of parsing a DDOC file. Previously, a wrong data file size was returned occasionally.
- Added XAdESv141.xsd schema support for implementing BDOC archive time-stamp profile in the future.
- Started using libc++ library instead of libstdc++ on OSX platform. The libc++ provides full c++11 support.
- All Libdigidocpp documentation is now available in HTML format (see /documentation/html/index.html in the base directory). Updated the existing HTML-based API documentation, transformed the contents of "Libdigidocpp Programmer's Guide" PDF/Word document to HTML format. Removed the previously used PDF/Word documents.
- Used coverity.com static analysis tool to find source code defects and vulnerabilities. 

Known issues: 
- Version 3.8 of the library cannot open BDOC documents that are created with version 3.9 or higher and contain special characters in the signed data file's name due to changes in special character percent-encoding method. 

 

Libdigidocpp library 3.8 release notes
--------------------------------------


3.8 is first public release of libdigidocpp as library. API is changed and not compatible compared to 3.7.1 version when libdigidocpp was not yet public library but internal component used by Digidoc3 client.

Known issues:
- If a data file with a colon character in its name is added to a BDOC container then the created signature will be erroneous. Thus, colon characters must not be used in data file names.
