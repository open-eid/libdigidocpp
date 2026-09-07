# Configuration guide {#configuration}

\anchor conf

This guide describes file-based and runtime configuration of Libdigidocpp,
including external services, trust lists, network access, signing devices, and
cryptographic policy.

## Loading configuration settings {#loading}

Libdigidocpp uses XML configuration file named digidocpp.conf. Configuration
file's structure is defined with XML schema "conf.xsd" - the file is included in
etc/schema/ subdirectory of Libdigidocpp package. For a sample configuration
file, see \ref sample-conf.

It is possible to use two types of configuration files: global and user's file.
Global file can be used to determine system-wide settings that cannot be altered
by a user's file – it can be done separately for each parameter in the file by
setting the parameter's "lock" attribute value to "true". User's file can be
used to determine user-specific parameter values.

It is possible to use only one configuration file (either global or user's file)
or two files in parallel. In the latter case, the matching user file's parameter
entries overwrite global file's entries, if the respective parameter is not
defined as locked in the global file.

By default, the configuration file's settings are loaded during the library's
initialization – Libdigidocpp looks for global and user configuration files from
their default locations depending on the environment:
- in case of Windows environment:
  - the global configuration file is looked up from the directory where
    digidocpp.dll library file is located. If the directory doesn't contain
    /schema subdirectory then the configuration file is looked up from the
    current working directory.
  - user configuration file is looked up from the system directory containing
    application data for the current user: `%APPDATA%\digidocpp\digidocpp.conf`
- in case of macOS:
  - the global configuration file is looked up from a location in the file
    system: `digidocpp.framework/Resources/digidocpp.conf`
  - user configuration file is looked up from `$HOME/.digidocpp/digidocpp.conf`
- in case of Linux environment:
  - the global configuration file is looked up from a location in the file
    system: `/etc/digidocpp/digidocpp.conf`
  - user configuration file is looked up from `$HOME/.digidocpp/digidocpp.conf`

It is also possible to load global configuration file from a non-default
location. In this case, call out the configuration file's initialization method
before initializing the library:

```cpp
// Initialize global configuration settings from a non-default location
digidoc::Conf::init(new digidoc::XmlConfCurrent("<file-path-and-name>"));
// then initialize the library
digidoc::initialize();
```

Local configuration settings can also be set or modified during runtime by
calling the respective setter methods of digidoc::XmlConfCurrent. Use this
alias to access all currently available configuration methods.

## Configuration parameters {#parameters}

Configuration file's elements and their attribute names are defined in conf.xsd
file.
Below is a description of the configuration file's parameters. The attribute
"lock", when set to "true" can optionally be used to determine parameter values
which should not be overwritten by another configuration file (e.g. when using
global and user's configuration files in parallel; see also the previous section
for more information).

### Logging settings {#logging-settings}

- `log.file` – Location of the log file where the logging output is written,
  e.g. `/tmp/digidocpp.log` or `C:\Temp\digidocpp.log`

  If left unspecified then the logging output is written to standard output
  stream.
- `log.level` – Used for controlling the level of detail of the logging output
  messages, higher number value indicates higher level of detail. Possible
  values are:
  - 1 – error messages,
  - 2 – warning messages,
  - 3 – info messages,
  - 4 – debug messages.

### Time-stamping service settings {#TS-settings}

- `ts.url` – Specifies the URL of the time-stamping service used for signature
  time-stamps in the TS and TSA profiles and the initial ASiC-S TimeStampToken.
  By default, the RIA's time-stamping service is used by the library
  (https://eid-dd.ria.ee/ts)
- `ts.url.archive` – Specifies the URL of the time-stamping service that is used
  for archive time-stamps: the ArchiveTimeStamp of the TSA (time-stamp-archive)
  signature profile, the archive-manifest time-stamps of ASiC-S containers and
  the time-stamp of a container wrapped into a new ASiC-S container by
  digidoc::Container::extendContainerValidity. If left unspecified then the
  `ts.url` value is used. Since v4.6.0.

> [!NOTE]
> For testing purposes, the SK's test time-stamping service can be used. The
> service is available at http://demo.sk.ee/tsa/ additional information can be
> found at https://www.id.ee/en/article/trust-services-timestamping-service/.

### Signature Verify Service settings {#VerifyService-settings}

- `verify.serivceUri` – Specifies the URL of the signature-verify service that
  is used during signature validation. By default, the RIA's signature-verify
  service is used by the library (https://siva.eesti.ee/V3/validate)

### PKCS#11 settings {#pkcs11-settings}

- `pkcs11.driver.path` – PKCS#11 driver library to be used when communicating
  with the smart card.

  With Estonian ID cards for example, the following PKCS#11 libraries are used:
  - `opensc-pkcs11.so` (used in Linux environment)
  - `opensc-pkcs11.dll` (used in Windows environment)

### Trust anchor/TSL settings {#CA-settings}

Information of trusted CA certificates (trust anchors) is used to validate the
trustworthiness of certificates used in the signature during signing and
signature validation processes. The signer certificate's CA, OCSP responder
certificate and time-stamping service's certificate (also referred to as
time-stamping authority, TSA) must be trusted.

Libdigidocpp library uses Trust Service Status List (TSL) as a source of trust
anchor information (see also \ref TSL-overview and \ref TSL "TSL standard" for
more information). A TSL list is a signed XML file that contains data of trusted
CA certificates, OCSP responder service and time-stamping service certificates.
Note that since v3.10, only TSL lists' based trust anchors are supported by the
library.

By default, the trusted certificates' information is obtained from European
Commission's official TSL list (https://ec.europa.eu/tools/lotl/eu-lotl.xml).
The default TSL behaviour can be changed by altering the configuration
parameters listed below.

- `tsl.autoupdate` – Determines if TSL validity is checked during every
  initialization of the library and if new TSL lists are downloaded if the
  existing list is expired. By default, the automatic update functionality is
  enabled and can be disabled by setting the parameter's value to "false". Note
  that when setting the parameter to "false" then you should copy the necessary
  TSL files to the "tsl.cache" location manually.
- `tsl.cache` – Directory in the file system where the TSL lists are saved and
  read in by the library. Set this parameter with your own value to change the
  default directories:
  - in Windows environment: `%APPDATA%\digidocpp\tsl`,
  - in Linux ja OSX environments: `$HOME/.digidocpp/tsl`
- `tsl.onlineDigest` – Additional feature to optimize TSL updating process. By
  default, the value is "true", meaning that during each initialization of the
  library, it is checked if there is a newer TSL list published, even if the
  existing TSL list is not yet expired.

  The check is based on the TSL list's HTTP HEAD request ETag field or SHA-256
  digest value.
  - HTTP HEAD request is made to TSL's URL to get remote ETag and if the value
    doesn't correspond with the existing local TSL's ETag value then a newer
    version of the TSL list is downloaded. Otherwise, the existing TSL is used.
  - SHA-256 digest that is (optionally) published online by the TSL's
    owner/manager. The URL of the digest matches the TSL's URL, but extension
    .sha2 is used instead of .xml. If the digest can be read and the value
    doesn't correspond with the existing local TSL's SHA-256 digest then a newer
    version of the TSL list is downloaded. Otherwise, the existing TSL is used.
- `tsl.timeOut` – TSL downloading timeout for each TSL list. The default value
  is 10 seconds.

> [!NOTE]
> - The TSL URL and TSL signing certificate values are not configurable via the
>   digidocpp.conf configuration file. The default values are fixed in source
>   code and can be accessed via methods digidoc::Conf::TSLCerts() and
>   digidoc::Conf::TSLUrl(). The library's user has to create a subclass and
>   override the methods in order to define other values. See also
>   \ref initialization.
> - When using digidoc-tool utility program then it is possible to specify
>   necessary TSL parameters on the command line. See also \ref digidoc-tool.
> - For information about using test TSL lists with Libdigidocpp library, please
>   refer to https://github.com/open-eid/libdigidocpp/wiki/Using-test-TSL-lists

### HTTP proxy settings {#proxy-settings}

- `proxy.host` – Specifies the proxy hostname, e.g. proxy.example.net
- `proxy.port` – Specifies the proxy port, e.g. 8080
- `proxy.user` – Specifies the proxy username.
- `proxy.pass` – Specifies the proxy password.
- `proxy.tunnelSSL` – May be used to enable downloading TSL-s in case of HTTPS
  connections and proxy. If enabled, the library tries to download use the proxy
  tunnel also for the HTTPS session.
- `proxy.forceSSL` – May be used to enable downloading TSL-s in case of HTTPS
  connections and proxy. If enabled then the library tries to pass by the proxy
  connection in case of HTTPS sessions.

### Digest type settings {#digest-settings}

- `signer.signatureDigestUri` – Specifies the digest algorithm that is used when
  calculating the hash that is being signed. By default, the SHA-256 algorithm
  (with URI http://www.w3.org/2001/04/xmlenc#sha256) is used
- `signer.digestUri` – Specifies the digest algorithm that is used for
  calculating all the hash values in the signature. By default, the SHA-256
  algorithm is used

### OCSP responder settings {#ocspresponder-settings}

The default OCSP responder that the library uses for retrieving the OCSP
confirmation during signature creation depends on the signer's certificate
chain.
In case of no issuer is configured AIA extension is used for OCSP responder
settings

You change the default behaviour in the configuration file with the following
parameter.

- `ocsp issuer` – The "issuer" parameter's name stands for the signer
  certificate issuer's Common Name (CN) value, e.g. ESTEID-SK 2015. The
  element's value specifies OCSP responder server's URL address that is used for
  certificates issued from the respective CA chain.

## Sample configuration file {#sample-conf}

\includelineno src/digidocpp.conf

## TSL list usage in Libdigidocpp {#TSL-overview}

Libdigidocpp library uses Trust Service status Lists (TSL) as trust anchors. TSL
lists are a standardized way to add support for cross-border trust-service
providers, e.g. CA's that issue qualified certificates, OCSP service and
time-stamping service providers (see also \ref TSL "TSL specification"). TSL
list is a digitally signed a document in XML format, the list is accompanied
with a TSL signing certificate that is used to validate the list's signature.

Libdigidocpp library uses the **European Commission’s TSL list** as the basis of
retrieving data of trusted certificates. The European Commission's TSL list is
also referred to as List of Trusted Lists (LOTL), meaning that it is central
list that contains references to other TSL lists, in this case the national TSL
lists of the European Union's member states.

> [!NOTE]
> The European Commission's TSL that contains URL's and certificates of the
> national TSL lists can be downloaded here:
> https://ec.europa.eu/tools/lotl/eu-lotl.xml

Each of the national TSL list contains data (including the certificates) of the
trust service providers that are approved in this particular country.
Libdigidocpp supports **all national TSL lists that are referred to in the LOTL
(more than 30 countries).**

> [!NOTE]
> For information about using test TSL lists with Libdigidocpp library, please
> refer to https://github.com/open-eid/libdigidocpp/wiki/Using-test-TSL-lists

### TSL initialization process {#TSL-init}

TSL lists' initialization process is done during each initialization of the
library. By default, the TSL itself and its freshness is checked on-line:
1. It is checked if LOTL (the master TSL list, tl-mp.xml) is present at the
   tsl.cache location
2. If there is no such list present in the cache directory and the online
   updating mechanism is enabled (see \ref CA-settings, "tsl.autoupdate") then
   the TSL list is downloaded from the list's URL
   (https://ec.europa.eu/tools/lotl/eu-lotl.xml) and saved to tsl.cache
   directory

   **Note:** tsl.autoupdate can be disabled but then the TSL list(s) must be
   manually saved to the tsl.cache location.

   **Note:** the TSL lists are not distributed along with the library's
   installation package, meaning that during the first initialization of the
   library, the TSL lists need to be downloaded on-line or must be manually
   copied to the tsl.cache location.
3. If there is an existing LOTL in the tsl.cache location and the
   tsl.onlineDigest check is enabled (see \ref CA-settings, "tsl.onlineDigest")
   then the freshness of the TSL list is checked based on the list's SHA-256
   hash value:
   - The existing TSL list’s hash is calculated over the binary representation
     of the list
   - The officially published hash value is downloaded (from the same address as
     the TSL's URL but with .sha2 extension)
   - The hash of existing TSL and the value downloaded on-line are compared
     - If values are different then a new version of the TSL list is downloaded
     - If the hash values are the same or it was not possible to download the
       hash value from external URL then new version of the TSL is not
       downloaded. TSL parsing/validation process is continued.
4. The LOTL is validated:
   - the list's validity is checked in by comparing the user's computer time
     with the list's `<NextUpdate>` value.
     - if the list is not valid then the library attempts to download a new list
       from the list's URL
   - the list's signature is validated by using its signing certificate
5. National TSLs' data (URLs and certificates) are read from the LOTL.
6. For each of the national TSL list, the following is done:
   - step 1-3 of the current process is repeated with the national TSL list
   - appropriate trust services are found from the national TSL lists, their
     certificates are added to the library's internal trusted certificates'
     store.
