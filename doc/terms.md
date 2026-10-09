# Terms and acronyms {#terms}

<table><tr><td>ASiC</td><td>
Associated Signature Containers
</td></tr><tr><td>ASiC-E</td><td>
Extended Associated Signature Containers. A type of ASiC container.
</td></tr><tr><td>ASiC-S</td><td>
Associated Signature Container Simple form. A type of ASiC container.
</td></tr><tr><td>BDOC 2.1 (.bdoc)</td><td>
Term is used to denote a digitally signed file format which is a profile of XAdES and follows container packaging rules based on OpenDocument and ASiC standards. The document format has been defined in \ref BDOC "BDOC2.1:2013"; an overview is provided on the \ref format "Format of digitally signed file" page.
</td></tr><tr><td>CRL</td><td>
Certificate Revocation List, a list of certificates (or more specifically, a list of serial numbers for certificates) that have been revoked, and therefore should not be relied upon.
</td></tr><tr><td>DIGIDOC-XML (.ddoc)</td><td>
The term is used to denote a DigiDoc document format that is based on the XAdES standard and is a profile of that standard. The current version is 1.3 which has been described in \ref DDOC "DigiDoc format".
</td></tr><tr><td>ECDSA</td><td>
Elliptic Curve Digital Signature Algorithm. Digital Signature Algorithm (DSA) which uses elliptic curve cryptography. Used as an alternative to RSA algorithm.
</td></tr><tr><td>OCSP</td><td>
Online Certificate Status Protocol, an Internet protocol used for obtaining the revocation status of an X.509 digital certificate
</td></tr><tr><td>OCSP Responder</td><td>
OCSP Server, maintains a store of CA-published CRLs and an up-to-date list of valid and invalid certificates. After the OCSP responder receives a validation request (typically an HTTP or HTTPS transmission), the OCSP responder either validates the status of the certificate using its own authentication database or calls upon the OCSP responder that originally issued the certificate to validate the request. After formulating a response, the OCSP responder returns the signed response, and the original certificate is either approved or rejected, based on whether or not the OCSP responder validates the certificate.
</td></tr><tr><td>PAdES (.pdf)</td><td>
Term is used to denote a digitally signed PDF file format which is based on \ref PAdES standards.
</td></tr><tr><td>SK</td><td>
SK ID Solutions AS. Certificate Authority in Estonia
</td></tr><tr><td>time-mark</td><td>
Mechanism used for adding certificate validity and signing time information with the signature.
The information is provided with a special OCSP confirmation (also referred to as time-mark) - hash value of the binary value of the signature (along with hash algorithm identifier in case of BDOC 2.1 document format) must be present in the "nonce" field of the OCSP confirmation. In this case, signature creation time is the issuance time of the OCSP confirmation (producedAt value in the confirmation), additional time-stamp service is not required. The respective signature profile is TM profile (supported in case of DIGIDOC-XML 1.3 and BDOC 2.1 document formats).
</td></tr><tr><td>time-stamp</td><td>
Mechanism used for adding certificate validity and signing time information with the signature. The certificate validity information is added to the signature with an OCSP confirmation; the signing time information is added with a time-stamp token retrieved form a time-stamping service. In this case, signature creation time is the issuance time (\ref RFC3161 "RFC 3161 TSTInfo.genTime") of the time-stamp token. The respective signature profile is TS profile.
</td></tr><tr><td>archive time-stamp</td><td>
Mechanism used for providing long term validity of a XAdES signature. The signature and validation data values are time-stamped. The respective signature profile is TSA profile.
</td></tr><tr><td>TSA</td><td>
Time-Stamping Authority. Time-stamping service provider.
</td></tr><tr><td>TSL</td><td>
Trust Service status List. Signed list that provides information about the status and the status history of the trust services (including certification, OCSP confirmation and time-stamping services). Used as a trust anchor in case of signature creation and validation to check the trustworthiness of the certificates that are included in the signature. See also \ref TSL "Trusted Lists"
</td></tr><tr><td>X.509</td><td>
an ITU-T standard for a public key infrastructure (PKI) and Privilege Management Infrastructure (PMI) which specifies standard formats for public key certificates, certificate revocation lists, attribute certificates, and a certification path validation algorithm
</td></tr><tr><td>XAdES</td><td>
XML Advanced Electronic Signatures, a set of extensions to XML-DSIG recommendation making it suitable for advanced electronic signature. Specifies precise profiles of XML-DSIG for use with advanced electronic signature in the meaning of European Union Directive 1999/93/EC.
</td></tr><tr><td>XML-DSIG</td><td>
a general framework for digitally signing documents, defines an XML syntax for digital signatures and is defined in the W3C recommendation XML Signature Syntax and Processing
</td></tr></table>