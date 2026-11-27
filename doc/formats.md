# Supported container formats {#formats}

Actively used digitally signed file formats in DigiDoc system are:
- ASiC-E - default format for files in Libdigidocpp library, described in \ref ASiC "The ETSI standard ETSI EN 319 162-1";
- BDOC 2.1 - legacy format, described in \ref BDOC "BDOC2.1:2013", The library implements only read-only support for the format;
- Lithuanian ADOC V1.0 - legacy format, described in \ref ADOC "ADOC-V1.0". The library implements only read-only compatibility for opening and locally validating XAdES signatures;
- ASiC-S - simple signature container, described in \ref ASiC "The ETSI standard ETSI EN 319 162-1". The library supports opening and validating containers with XAdES signatures. For containers with \ref RFC3161 "RFC 3161" time-stamp tokens, creating, saving, reading, validating, and archive-manifest time-stamp extension are supported.

The following chapters provide an overview of the ASiC-E (XAdES) digitally signed file format, which is the preferred format for creating signed documents with Libdigidocpp.

## ASiC-E (XAdES) container format {#container}

The ETSI standard \ref ASiC "EN 319 162-1" defines a container format for encapsulating signed files, signatures, and supporting information. ASiC-E documents use the Extended form and contain signatures conforming to \ref XAdES "XAdES EN 319 132-1".

ASiC-E container is a ZIP file consisting of the following objects:
- a file named "mimetype", containing only the following value: `application/vnd.etsi.asic-e+zip`
- data files in original format.
- META-INF subdirectory, consisting of:
  - `manifest.xml` – a file containing list of all files in the container. The list does not contain the "mimetype" file and files in META-INF subdirectory.
  - `signatures*.xml` – one file for each signature, ‘`*`’ in the file’s name denotes the sequence number of a signature (counting starts from zero). The `signatures*.xml` file also incorporates certificates, validity confirmation and meta-data about the signer.

Reading deliberately accepts a DEFLATE-compressed `mimetype` entry for backward
compatibility with existing documents, including older jdigidoc files. This is
an exception to [ETSI EN 319 162-1](#ASiC), Annex A.1, which requires it to
be uncompressed. The library writes it uncompressed; see "Mimetype
compatibility" in the [implementation notes](implementation.md).

When ASiC-E container is signed then all files in the container are signed, except of the mimetype file and files in META-INF subdirectory.

Original files (which were signed) along with the signature(s), timestamp(s), validation confirmation(s) and certificates are encapsulated within the container. As a result, it is possible to verify signature validity without any additional external information – the verifier should trust the issuer of signer’s certificate, TS Authority and the OCSP responder’s certificate.

![ASiC-E container's contents](images/asic.svg)

## ASiC-E XAdES signature profiles {#profiles}

The [XAdES EN 319 132-1](#XAdES) standard defines formats for advanced
electronic signatures that remain valid over long periods of time. XAdES
Baseline profiles further constrain the signature syntax and the validation
material included with a signature.

### ASiC-E signature with time-stamp {#ASiC-E-TS}

The default libdigidocpp signature profile for ASiC-E is an XAdES signature
with a time-stamp. It incorporates the validation material needed for
long-term validation.

In order to provide long-term validation, proof is needed that the signer's
X.509 certificate was valid at the time of signature creation. For the
time-stamp profile, the proof is provided as follows:
1. A time-stamp compliant with [RFC 3161](#RFC3161) is obtained from a
   time-stamping service. The hash of the created signature
   (`<SignatureValue>` element) is sent to the service. The returned
   time-stamp token contains the same hash and proves that the signature value
   existed at the token's issuance time.
2. An [RFC 6960](#RFC6960) compliant OCSP confirmation is obtained from an
   OCSP service. The response confirms the status of the signer's certificate
   at its production time.
3. The verifier checks the difference between the time-stamp token's issuance
   time and the OCSP response's production time.

> [!NOTE]
> The [RFC 3161 TSTInfo.genTime](#RFC3161) field records when the TSA
> issued the time-stamp token. A valid token proves that the signature value
> existed by that time. Libdigidocpp reports this value as the trusted signing
> time when a signature time-stamp is available.

## Legacy BDOC 2.1 profiles {#bdoc}

BDOC 2.1 is a legacy profile based on the older ETSI
[XAdES TS 101 903](#XAdES) specification. It defines the BDOC-TS and
BDOC-TM profiles. Both incorporate material for long-term validation.

### BDOC signature with time-stamp {#BDOC-TS}

BDOC-TS uses the same time-stamp and OCSP mechanism as the
[ASiC-E signature with time-stamp](#ASiC-E-TS).

### BDOC signature with time-mark {#BDOC-TM}

The BDOC signature with time-mark is based on an XAdES-EPES signature
(Explicit Policy-based Electronic Signature, see [XAdES](#XAdES)).

For the time-mark profile, proof of certificate validity and signing time is
obtained with a single OCSP response whose `nonce` contains the signature
digest. This OCSP response is referred to as the time-mark.

The hash of the created signature (the `<SignatureValue>` element's contents)
is sent in the OCSP request and returned in the response's `nonce`. The
request's and response's `nonce` is a DER encoding of the following ASN.1 data
structure:

```
TBSDocumentDigest ::= SEQUENCE {
    algorithm AlgorithmIdentifier,
    digest OCTET STRING
}
```

The element digest is a hash value of the binary value of the `<SignatureValue>` element’s contents, element algorithm determines the used hash algorithm as defined in \ref RFC5280 "RFC 5280" clause 4.1.1.2.

**The time-mark provides proof of the following:**
1. The signature value existed at a certain point of time (issuance time of the OCSP confirmation) – the verifier can calculate the hash of the signature and check its conformance to the OCSP response’s "nonce" field.
2. The signer’s certificate was valid (provided that the OCSP response is positive and does indeed confirm the certificate’s validity) at a certain point of time

It is important to notice that additional time-stamps are not necessary as time of signing and time of obtaining validity information is indicated in the OCSP response (i.e. the time-mark).

> [!NOTE]
> The issuance time (producedAt field’s value) of the OCSP response (the time-mark) is regarded as the time of signature creation.

To achieve long-time validity of digital signatures, a secure log system is employed within the model. All OCSP responses and changes in certificate validity are securely logged to preserve digital signature validity even after private key compromise of CA or OCSP responder.

![Security model of time-marking mechanism](images/security.svg)

## Lithuanian ADOC V1.0 compatibility {#adoc}

The Lithuanian \ref ADOC "ADOC-V1.0" format is an OpenDocument-based ZIP
package identified by the media type
`application/vnd.lt.archyvai.adoc-2008`. In addition to signed data files, an
ADOC package can contain format-specific metadata referenced by its XAdES
signatures.

Clause 25 of ADOC V1.0 requires file and directory references to be relative
to the package root. The reference `/` identifies the package itself. File
and directory references must not begin with `/`.

Since version 3.13.0, libdigidocpp provides legacy read-only compatibility for
ADOC V1.0. The library can open the package, expose its data files, and locally
validate its XAdES signatures, including signatures using the OpenDocument
`document-signatures` root element and references to ADOC metadata.

Creating ADOC containers, adding data files or signatures, signing, and saving
changes are not supported. This compatibility statement is limited to ADOC
V1.0 and does not claim full support for later ADOC specifications or the
complete Lithuanian ADOC format family.

## ASiC-S container format {#asics}

In addition to the Associated Signature Extended form (ASiC-E), the \ref ASiC "ETSI standard EN 319 162-1" defines a Simple form which is used for encapsulating a single data file and a signature or time-stamp token associated with it.

An ASiC-S container is a ZIP file consisting of the following objects:
- an optional file named "mimetype", containing only the following value: `application/vnd.etsi.asic-s+zip`
- data object (file) in original format.
- one signature form:
  - `META-INF/signatures.xml` containing XAdES signatures; or
  - `META-INF/timestamp.tst` containing the initial \ref RFC3161 "RFC 3161" time-stamp token.
- for the time-stamp-token form, optional `META-INF/ASiCArchiveManifest*.xml` and `META-INF/timestamp*.tst` files containing additional archive-manifest time-stamp layers.

Since version 3.17.0, libdigidocpp can open and locally validate ASiC-S containers containing XAdES signatures in `META-INF/signatures.xml`. This variant is read-only: creating, adding signatures to, and saving ASiC-S/XAdES containers are not supported.

The library also supports local creation and validation of ASiC-S containers with a time-stamp token (the container includes `META-INF/timestamp.tst`). The time-stamp token is a binary representation of TimeStampToken as defined in \ref RFC3161 "RFC 3161". The time-stamp is obtained from a time-stamping service and is calculated over the entire binary content of the data object.
Since both the original file and time-stamp are included in the container, it is possible to verify that the timestamped file existed at a certain point of time.

An existing time-stamp token can be extended by adding an ASiC archive manifest and a new time-stamp token. Each new layer protects the data object and the preceding time-stamp information. See \ref extend-validity for the high-level validity-extension workflow.

When opening the container, the layers are read from
`META-INF/ASiCArchiveManifest.xml` through the reference marked
`Rootfile="true"` (or `"1"`, the other `xsd:boolean` true value) in each
manifest, as described in ETSI EN 319 162-1 clause 4.4.3. Opening fails if a
manifest marks more than one reference as a root file or if a root file
reference has an empty URI. Opening also fails if the chain references the
same manifest or time-stamp token more than once.

Since version 4.6.0, an ASiC-S container whose data object is a legacy DDoc file
(`.ddoc`) and whose signature is a time-stamp token is opened together with the
enclosed DDoc when the application passes a digidoc::ContainerOpenCB that allows
online validation. The DDoc's signatures are validated by the \ref SiVa service:
digidoc::Container::dataFiles returns the DDoc's data files and
digidoc::Container::signatures returns the time-stamp token followed by the
DDoc's signatures. The time-stamp token is still validated locally, and saving
and archive-manifest time-stamp extension apply to the ASiC-S container.
Signatures cannot be removed while the enclosed DDoc is exposed. Without the
callback, when online validation is not allowed, or when DDoc parsing or the
SiVa request fails, the container is opened as a plain time-stamped ASiC-S
container. A SiVa report that marks a DDoc signature invalid still exposes
that signature and its validation errors. See \ref siva-requests for the data
sent to SiVa.

## Format compatibility notes {#implementation-notes}

These notes document signature-validation and container-serialization choices that supplement the referenced format specifications.

### Digital signature related notes {#signature-notes}

1. The supported BDOC 2.1 signature profiles are BDOC-TM (XAdES-EPES signature with time-mark) and BDOC-TS (XAdES-BES signature with time-stamp and OCSP confirmation).
   The basic BDOC-TM profile is XAdES-EPES as BDOC 2.1 specification requires that `<SignaturePolicyIdentifier>` element is present (\ref BDOC "BDOC2.1:2013", chap. 5.2). The basic BDOC-TS profile is XAdES-BES as the `<SignaturePolicyIdentifier>` element is not supported in case of BDOC 2.1 signatures with time-stamps.
   It is expected that either a time-mark or time-stamp and OCSP confirmation have been added to the signature as according to BDOC 2.1 specification (\ref BDOC "BDOC2.1:2013", chap. 6) a signature is not considered complete or valid without validation data from external services (i.e. a time-mark or time-stamp).
2. For better international compatibility reasons, the library also accepts BDOC-TS signatures that are based on XAdES-EPES basic profile during validation time (i.e. the signature contains `<SignaturePolicyIdentifier>` element and a time-stamp).
3. One time-mark is allowed for each signature in case of TM profile; one time-stamp and one OCSP confirmation are allowed for each signature in case of TS profile (due to security reasons and in order to maintain testing efficiency).
4. In case of BDOC signature with time-mark, the OCSP confirmation's (i.e. time-mark's) nonce field’s value is calculated as follows:
   - the contents of `<SignatureValue>` element (i.e. the value without XML tags) is taken and decoded from base64 encoding;
   - digest of the value found in the previous step is calculated by using SHA-256 algorithm.;
   - the digest value found in the previous step and the digest algorithm that was used are transformed as defined by the following ASN.1 structure:
     ```
     TBSDocumentDigest ::= SEQUENCE {
         algorithm AlgorithmIdentifier,
         digest OCTET STRING
     }
     ```
   - the ASN.1 block value produced in the previous step is included in the OCSP request’s "nonce" field and must be present in the respective field of the OCSP response.
5. In case of signing with ECC keys (by using ECDSA algorithm), concatenation method is used for creating signature value.
6. By default, data file digests use `signer.digestUri` and RSA signatures use `signer.signatureDigestUri`, both configured as SHA-256 by default. Unless a signature method is set explicitly, ECDSA uses SHA-224 for 224-bit keys, SHA-256 for 256-bit keys, SHA-384 for 384-bit keys, and SHA-512 for other key sizes (including 521-bit keys).
7. When SHA-1, SHA-224 or SHA3-224 has been used then a warning message about weak digest method is produced to the user. SHA-224 is discontinued by \ref CryptoSuites "ETSI TS 119 312 V2.1.1" Annex D and SHA3-224 is not listed there at all, so ECDSA with SHA3-224 is not supported. It is recommended to regard the error as a validation warning (identically to DigiDoc desktop application and digidoc-tool.cpp utility program).
8. During signature creation, it is checked that there is only one `<ClaimedRole>` element in the signature, which contains the signer’s role and optionally the signer’s resolution. If the `<ClaimedRole>` element contains both role and resolution then they must be separated with a slash mark, e.g. "role / resolution". Note that when setting the resolution value then role must also be specified.
9. XML namespace prefixes are used in case of all XML elements (e.g. "asic:", "ds:", "xades:").
10. The data file’s MIME type that is used in case of Libdigidocpp’s utility program is always "application/octet-stream" for testing purposes.
11. The `<ds:Signature>` element’s Id attribute value is set to `"S<seq_no>"` during signature creation where sequence numbers are counted from zero. Other Id values that are used in the sub-elements of the `<ds:Signature>` element contain the signature’s Id value as a prefix. During verification, different Id attribute values are also supported but are not tested periodically.
12. `signatures*.xml` file's XML structure validation is done on the basis of XAdES XML Schema (\ref XAdES), however, there are additional checks to determine any unsupported elements that are allowed by the XAdES specification. The unsupported elements are CounterSignature, AttributeCertificateRefs, AttributeRevocationRefs, RefsOnlyTimeStamp, AttrAuthoritiesCertValues, AttributeRevocationValues, CommitmentTypeIndicationType, AllDataObjectsTimeStamp, IndividualDataObjectsTimeStampType.
13. Special characters in URI attribute values are handled according to \ref RFC3986 "RFC 3986" (since v3.9 of the library): the characters are percent-encoded, except of unreserved characters and delimiters. Both percent-encoded and non-percent-encoded characters are supported during signature's validation.
14. When validating a BDOC-TS document then the difference between the OCSP validity confirmation's production time (producedAt field) and the time-stamp token's creation time (\ref RFC3161 "RFC 3161 TSTInfo.genTime") is checked. An exception (`OCSPBeforeTimeStamp`) is thrown if the OCSP confirmation's time is earlier than the time-stamp's time. If the OCSP confirmation's time is later than the time-stamp's time by more than 15 minutes then a warning (`ProducedATLateWarning`) is returned. There is no upper limit on the difference.
15. When an OCSP response is requested (signing or extending to LT), the validity period of the OCSP response is checked against the signer's computer time: the response's thisUpdate time must not be more than 15 minutes later or more than 2 minutes earlier than the computer time, and its nextUpdate time, if present, must not be more than 15 minutes earlier than the computer time. Otherwise an exception (`OCSPTimeSlot`) is thrown and the signing or extension is cancelled.

### Container related notes {#container-notes}

1. ASiC-E files are created with .asice or .sce file extension.
2. Signatures are stored in `META-INF/signatures*.xml` files where ‘`*`’ is a sequence number, counting is started from zero.
3. It is not allowed to add two data files with the same name to the container as the signed data file must be uniquely identifiable in the container.
4. All data files in the container must be signed. All signatures in the container must sign all of the data files.
