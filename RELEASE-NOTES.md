Libdigidocpp library [3.14.12](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.12) release notes
--------------------------------------
- Fix digidoc-tool file extraction

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.11...v3.14.12)

Libdigidocpp library [3.14.11](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.11) release notes
--------------------------------------
- Update libraries (#472, #495, #490, #500)
- TSL parsing improvementsa (#492, #495, #499)
- Fix memory leaks (#488)
- Prefer PSS padding with RSA key (#437)
- Code fixes and improvements (#478, #487, #513)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.10...v3.14.11)

Libdigidocpp library [3.14.10](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.10) release notes
--------------------------------------
- Trust intermediate certificates in trust store (#476)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.9...v3.14.10)

Libdigidocpp library [3.14.9](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.9) release notes
--------------------------------------
- TSL parsing improvements (#475, #451, #465, #464, #463, #439, #443)
- Allow validate signatures with TimeStampValidationData (#455)
- Build python bindings (#456)
- OpenSSL 3.0 support and minimum supported 1.1.1 (#468, #461, #453)
- Update documentation (#434)
- Fix parameter locking when false is defined (#448)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.8...v3.14.9)

Libdigidocpp library [3.14.8](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.8) release notes
--------------------------------------
- Update TSL signer certificates (#438)
- Optimize signing process (#404, #417, #430)
- Improve SiVa validation (#419, #426, #429)
- Remove SK OCSP proxy URL (#427)
- Improve signature validation (#383, #420, #432, #444)
- Updates for libraries and examples (#423, #424, #381, #425)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.7...v3.14.8)

Libdigidocpp library [3.14.7](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.7) release notes
--------------------------------------
- Remove libdigidoc support (#393)
- Build macOS arm64 (#392)
- Improve compatibility where Xerces-C is configured uint16_t (#391)
- Use same length digest as ECC key (#406)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.5...v3.14.7)

Libdigidocpp library [3.14.6](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.6) release notes
--------------------------------------
- Update TSL signer certificates

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.5...v3.14.6)

Libdigidocpp library [3.14.5](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.5) release notes
--------------------------------------
- Use nlohmann json library (#380)
- Add canonicalization algorithm to time-stamp (#369)
- Add PSS signature support (#366)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.4...v3.14.5)

Libdigidocpp library [3.14.4](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.4) release notes
--------------------------------------
- Use unique_ptr on Container::create/open (#355)
- Deprecate std::istream *is method and add std::unique_ptr<std::istream> alternative
- Fix encoding on macOS when LC_ALL is defined (#346)
- Use 64 bit stat on windows (#349)
- Implement SiVa V3 changes (#354)
- Documentation updates and code fixes

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.3...v3.14.4)

Libdigidocpp library [3.14.3](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.3) release notes
--------------------------------------
- Change SiVa URL (#335)
- Split user-agent and application name handling (#333)
- Update OpenSSL 1.1.1g and Xerces-C 3.2.3 (#347)
- Workaround OpenSSL 1.1.1f issues (#348)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.2...v3.14.3)

Libdigidocpp library [3.14.2](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.2) release notes
--------------------------------------
- Check that OCSP producedAt is later than TimeStamp (#324)
- Update documentation (#326)
- Other code and build cleanups

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.1...v3.14.2)

Libdigidocpp library [3.14.1](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.1) release notes
--------------------------------------
- Fix LGTM and Coverity warnings and errors
- Add TSUrl parameter to digidoc-tool (#293)
- Update OpenSSL to 1.1.1
- Add stricter validation rules (#317, #295)
- SiVa V3 compatibility

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.14.0...v3.14.1)

Libdigidocpp library [3.14.0](https://github.com/open-eid/libdigidocpp/releases/tag/v3.14.0) release notes
--------------------------------------
- Update LOTL URL (#304)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.9...v3.14.0)

Libdigidocpp library [3.13.9](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.9) release notes
--------------------------------------
- Update dependencies (#285, #275, #274, #268, #266, #265, #258)
- Optimize TSL loading and SiVa request (#271, #252, #280)
- Update TSL trust certificates (#287)
- Improve C# and java bindings (#282, #278, #272, #270)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.8...v3.13.9)

Libdigidocpp library [3.13.8](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.8) release notes
--------------------------------------
- Use ETag instead Last-Modified to verify cached file (#238)
- Fix signature verify with OpenSSL 1.1 (#240)
- Check OCSP TM OID (#247)
- Handle TSA error code 429 and cleanup some code (#250)
- Upload artifacts to AWS (#253)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.7...v3.13.8)

Libdigidocpp library [3.13.7](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.7) release notes
--------------------------------------
- Remove compiler warnings
- Change SiVa service URL to https://siva.eesti.ee/V2/validate
- Update Xml-Security-C 2.0.1 (#224), OpenSSL 1.0.2p (#222)
- Fix crashes #223, #228, #221 and memory leaks #224
- Code cleanups and warning fixes

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.6...v3.13.7)

Libdigidocpp library [3.13.6](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.6) release notes
--------------------------------------
- Add new OCSP access certificate and use when old is expired (#205)
- Build java bindings on desktop platforms (#204)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.5...v3.13.6)

Libdigidocpp library [3.13.5](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.5) release notes
--------------------------------------
- Add TSL cert tl-mp5 and generate headers dynamically (#174)
- Use case sensitive zip file compare (#175)
- Android build improvements (#179, #180)
- SiVa service validation improvements (#185, #184)
- Update Xerces-C to 3.2.1 (#187)
- Optimize TSL loading (#192)
- PDF Experimental backend (#57)
- Build fixes and improvements

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.3...v3.13.5)

Libdigidocpp library [3.13.4](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.4) release notes
--------------------------------------
- Add TSL cert tl-mp5 and generate headers dynamically (#174)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.3...v3.13.4)

Libdigidocpp library [3.13.3](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.3) release notes
--------------------------------------
- SiVa V2 support (#166)
- Android build fixes (#167, #164)
- Fix loading unsigned TM signatures (#161)
- Don't terminate TSL parsing when TakenOvertByType extension is found (#160)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.2...v3.13.3)

Libdigidocpp library [3.13.2](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.2) release notes
--------------------------------------
- Implement ECDSA token support (#152)
- Fix issuer name with UTF-8 characters (#146)
- Check mimetype format (#150)
- Update xerces-c to 3.2.0 (#149)
- Take OCSP URL from AIA extension (#138)

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.1...v3.13.2)



Libdigidocpp library [3.13.1](https://github.com/open-eid/libdigidocpp/releases/tag/v3.13.1) release notes
--------------------------------------
- Restore compatibility with jdigidoc 3.11

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.13.0...v3.13.1)



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
