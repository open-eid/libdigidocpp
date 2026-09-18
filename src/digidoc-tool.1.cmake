.\" Manpage for digidoc-tool
.TH DIGIDOC-TOOL 1 "${BUILD_DATE}" "${VERSION}" "User Commands"
.SH NAME
digidoc-tool \- create, sign, open, validate, and extend ASiC containers
.SH SYNOPSIS
.B digidoc-tool
.I COMMAND
.RI [ OPTIONS ]
.I FILE
.SH DESCRIPTION
.B digidoc-tool
is a command-line utility for working with digital signature containers.
Supported ASiC-E, ASiC-S, and legacy BDOC 2.1 variants are handled locally.
PDF, legacy DDOC, and ASiC containers with CAdES signatures are validated
through the SiVa Online Service. The
.B \-\-offline
option disables this service fallback.
.PP
The interface is intended for testing and as an API usage example. Its
command-line compatibility is not guaranteed between releases.
.SH COMMANDS
.SS create
Create and normally sign a container. The output extension selects ASiC-E
(.asice or .sce) or ASiC-S (.asics or .scs).
.PP
An ASiC-S TimeStampToken container requires exactly one
.B \-\-file
and
.BR "\-\-profile=TimeStampToken" .
The profile alias
.B time-stamp-token
is also accepted.
.PP
Example:
.PP
.EX
digidoc-tool create --file=document.txt signed-document.asice
digidoc-tool create --file=document.txt --profile=TimeStampToken timestamped-document.asics
.EE
.TP
.BI \-\-file= path
Add a data file. This option may occur multiple times for ASiC-E.
.TP
.BI \-\-mime= type/subtype
Set the MIME type for the preceding
.B \-\-file
option. The default is application/octet-stream.
.TP
.B \-\-dontsign
Create the container without signing it. This is intended for ASiC-E.
.PP
The signing options described under
.B sign
are also accepted.
.SS createBatch
Create and sign a separate ASiC-E container for each regular file in a
directory.
.PP
Example:
.PP
.EX
digidoc-tool createBatch folder/content/to/sign
.EE
.SS open
Open a document, list its contents, and validate its signatures.
.PP
Example:
.PP
.EX
digidoc-tool open container-file.asice
.EE
.TP
.BR \-\-warnings= "ignore|warning|error"
Select how validation warnings affect output. The default is warning.
.TP
.BR \-\-extractAll [=directory]
Extract all data files without validating signatures. Without a directory,
files are written to the current directory.
.TP
.B \-\-validateOnExtract
Validate the container before extracting data files.
.TP
.B \-\-offline
Do not send unsupported local formats to SiVa. Service-backed formats cannot
be opened in this mode.
.SS add
Add data files to an unsigned ASiC-E container. The
.B \-\-file
and
.B \-\-mime
options have the same meaning as for
.BR create .
.PP
Example:
.PP
.EX
digidoc-tool add --file=file1.txt container-file.asice
.EE
.SS remove
Remove data files or signatures by their zero-based indexes. Data files can
only be removed after all signatures have been removed.
.PP
Example:
.PP
.EX
digidoc-tool remove --document=0 --signature=1 container-file.asice
.EE
.TP
.BI \-\-document= index
Data file to remove. This option may occur multiple times.
.TP
.BI \-\-signature= index
Signature to remove. This option may occur multiple times.
.SS websign
Create an ASiC-E container using external two-step XAdES signing.
.TP
.BI \-\-cert= file
PEM signer certificate.
.PP
The data-file and signing metadata options described under
.B create
and
.B sign
are also accepted.
.SS sign
Add an XAdES signature to an existing ASiC-E or legacy BDOC 2.1 container.
The signing options are also used by
.B create
to add the initial RFC 3161 TimeStampToken to a new ASiC-S container. An
existing ASiC-S container cannot receive another ordinary signature.
.PP
Example:
.PP
.EX
digidoc-tool sign --pkcs11 container-file.asice
.EE
.TP
.BI \-\-profile= profile
Signature profile. Accepted values are TS, TSA, time-stamp,
time-stamp-archive, TimeStampToken, and time-stamp-token. The TimeStampToken
profiles are used when creating ASiC-S.
.TP
.B \-\-XAdESEN
Use the XAdES EN profile.
.TP
.BI \-\-city= value
City of the signature production place.
.TP
.BI \-\-street= value
Street address of the signature production place for the XAdES EN profile.
.TP
.BI \-\-state= value
State or province of the signature production place.
.TP
.BI \-\-postalCode= value
Postal code of the signature production place.
.TP
.BI \-\-country= code
Two-character country code of the signature production place.
.TP
.BI \-\-role= value
Signer role. This option may occur multiple times.
.TP
.BR \-\-pkcs11 [=driver]
Use PKCS#11. If no driver is given, the configured default is
${PKCS11_MODULE}.
.TP
.BI \-\-pkcs12= file
Use a PKCS#12 software token. The
.B \-\-pin
value is used as its password.
.TP
.BI \-\-pin= value
PIN or PKCS#12 password. PKCS#11 prompts for a PIN when this is omitted.
.TP
.B \-\-cng
On Windows, use the Microsoft CNG signing API.
.TP
.B \-\-selectFirst
On Windows, select the first suitable certificate instead of showing a
selection dialog.
.TP
.BI \-\-thumbprint= hex
On Windows, select a certificate by its hexadecimal thumbprint.
.TP
.BR \-\-sha224 | \-\-sha256 | \-\-sha384 | \-\-sha512
Select the data digest algorithm. The default is SHA-256.
.TP
.BR \-\-sigsha224 | \-\-sigsha256 | \-\-sigsha384 | \-\-sigsha512
Select the signature digest algorithm. The default is SHA-256.
.TP
.BR \-\-sigpsssha224 | \-\-sigpsssha256 | \-\-sigpsssha384 | \-\-sigpsssha512
Select the signature digest algorithm and RSA-PSS padding.
.TP
.B \-\-rsapkcs15
Use RSA PKCS#1 v1.5 padding.
.TP
.B \-\-rsapss
Use RSA-PSS padding.
.TP
.BI \-\-tsurl= url
Override the configured time-stamping service URL.
.TP
.BI \-\-userAgent= value
Send additional application information to the TSA or OCSP service.
.TP
.B \-\-dontValidate
Do not validate the newly created signature.
.SS extend
Add new validity evidence and save the result.
.PP
Without
.BR \-\-signature ,
the high-level validity-extension workflow chooses the required profile. It
extends eligible ASiC-E or ASiC-S signatures in place, or wraps the original
container in a new timestamped ASiC-S container when necessary.
.PP
With one or more
.B \-\-signature
options, only the selected signatures are extended directly.
.PP
Examples:
.PP
.EX
digidoc-tool extend container-file.asice
digidoc-tool extend --signature=0 --profile=TSA container-file.asice
.EE
.TP
.BI \-\-signature= index
Zero-based signature index to extend directly. This option may occur multiple
times.
.TP
.BI \-\-profile= profile
Direct extension profile: TS, TSA, time-stamp, or time-stamp-archive. This is
chosen automatically when
.B \-\-signature
is omitted.
.TP
.B \-\-dontValidate
Do not validate a directly extended signature after extension.
.SS version
Print the digidoc-tool and libdigidocpp versions.
.SH GLOBAL OPTIONS
.TP
.B \-\-nocolor
Disable terminal colors.
.TP
.BR \-\-loglevel= 0|1|2|3|4
Set logging to none, error, warning, info, or debug respectively.
.TP
.BI \-\-logfile= file
Write logs to a file. An empty value writes logs to the console.
.SH SEE ALSO
.BR qdigidoc4 (1)
