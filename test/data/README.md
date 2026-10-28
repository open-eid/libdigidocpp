# Test data

## Container tests
* [47101010033.cer](47101010033.cer) - Used in X509Crypto test suite. Its RSA modulus is encoded as a negative
  INTEGER, like the Estonian ID-card certificates issued 2014-2015; OpenSSL 4.0 refuses to decode the key.
* [sha1-cert-ocsp.bdoc](sha1-cert-ocsp.bdoc) - Contains signature S1 with a correctly
  encoded RSA modulus, a SHA-1-signed certificate, and a SHA-1 OCSP response.
  The general unit suite validates S1 and checks that initialization and signature validation
  preserve the caller's default OpenSSL SHA-1 verification policy.

* `keyinfo-empty-cert.asice`, `certvalues-empty-cert.asice`, and
  `keyinfo-whitespace-cert.asice` - LT signatures with empty or whitespace-only supplemental
  certificate elements in KeyInfo or CertificateValues. The empty elements must
  be ignored without introducing signer or OCSP validation failures. These samples
  use a TSA not trusted by the test TSL, which the regression test allows separately.

## Certificate fixtures

[gencerts.sh](gencerts.sh) creates the general-purpose test certificates and signing keys using
[openssl.conf](openssl.conf). It requires Bash, `seq`, and the `openssl` command on `PATH`.

| Output         | Purpose                                    | Parent      | PKCS#12 password |
| -------------- | ------------------------------------------ | ----------- | ---------------- |
| `ca.crt`       | RSA-2048 root CA                           | Self-signed |                  |
| `inter.crt`    | RSA-2048 intermediate CA                   | `ca.crt`    |                  |
| `ocsp.crt`     | RSA-2048 OCSP responder                    | `ca.crt`    |                  |
| `signer1.p12`  | RSA-2048 signing key and certificate       | `inter.crt` | `signer1`        |
| `signer2.p12`  | RSA-2048 signing key and certificate       | `inter.crt` | `signer2`        |
| `signer3.p12`  | RSA-2048 signing key and certificate       | `inter.crt` | `signer3`        |
| `signerEC.p12` | P-384 EC signing key and certificate       | `inter.crt` | `signerEC`       |
| `unicode.crt`  | P-384 EC certificate with `CN=unicodeöäüõ` | Self-signed |                  |

The configuration defines the `v3_ca`, `v3_inter`, `v3_ocsp`, and `v3_usr` extension profiles:
CA constraints, key usages, subject/authority key identifiers, certificate policies, and the
`http://demo.sk.ee/ocsp` responder URL. Its CA database and serial-file paths are relative to the
working directory. The Unicode certificate is self-signed without these extension profiles.

The script prompts for confirmation when issuing the root CA. It writes certificates, unencrypted
private keys (`*.key`), requests (`*.req`), PKCS#12 bundles, and CA database/serial files into the
working directory, overwriting existing outputs. To inspect newly generated fixtures without
replacing the checked-in files, run from the repository root:

```sh
certdir="$(mktemp -d)"
cp test/data/gencerts.sh test/data/openssl.conf "$certdir/"
(
    cd "$certdir" || exit
    bash gencerts.sh
)
```

The certificates are valid for 3650 days from generation, except `unicode.crt`, which is valid for
365 days. Regeneration creates new keys and certificates; existing signed containers and trust
lists still refer to the old certificates and need separate updates if those fixtures are replaced.
The script does not regenerate `tsl.asice` or the `EE_T-*.xml` lists described below.

## TSL tests

[tsl.asice](tsl.asice) is signed by `CN=libdigidocpp TSL test signer` with an LT-level signature.
Each `EE_T-*.xml` is the [open-eid test-TL EE_T.xml](https://github.com/open-eid/test-TL/blob/master/EE_T.xml) with an extra `libdigidocpp TSL test` provider whose CA, OCSP and TSA services list the throw-away PKI that signed the container.
All other services are unchanged.
A list is `good` when the signature must validate with it, `bad` when validation must fail.

| Time | Value                | Meaning                                     |
| ---- | -------------------- | ------------------------------------------- |
| H    | 2026-06-11T11:20:27Z | Service history starts (`undersupervision`) |
| C    | 2026-08-10T11:20:27Z | Signing certificate issued (`notBefore`)    |
| G    | 2026-09-09T11:20:27Z | Services `granted`                          |
| T    | 2026-10-09T11:20:27Z | Signature time-stamp and OCSP response      |

### CA service

The signing certificate is checked against the CA service at C and again at T.
The `CA-signtime-*` lists keep the service valid at C and change its history between C and T.

| File                                            | Expected | Change                                                   |
| ----------------------------------------------- | -------- | -------------------------------------------------------- |
| `EE_T-CA-invalid-type.xml`                      | bad      | Service type changed to TSA/QTST                         |
| `EE_T-CA-non-qa.xml`                            | bad      | Service type changed to CA/PKC (non-qualified)           |
| `EE_T-CA-withdrawn.xml`                         | bad      | Revoked at C - 24h                                       |
| `EE_T-CA-withdrawn-granted-before.xml`          | good     | Revoked at C - 24h, granted again at C - 12h             |
| `EE_T-CA-withdrawn-granted-later.xml`           | bad      | Revoked at C - 24h, granted again at C + 12h             |
| `EE_T-CA-granted-later.xml`                     | bad      | History starts at C + 12h                                |
| `EE_T-CA-noqscd-granted-before.xml`             | good     | Non-qualified (CA/PKC) until C - 12h                     |
| `EE_T-CA-noqscd-granted-later.xml`              | bad      | Non-qualified (CA/PKC) until C + 12h                     |
| `EE_T-CA-signtime-withdrawn.xml`                | bad      | Withdrawn at G                                           |
| `EE_T-CA-signtime-withdrawn-granted-before.xml` | good     | Withdrawn at G, granted again at T - 12h                 |
| `EE_T-CA-signtime-withdrawn-granted-later.xml`  | bad      | Withdrawn at G, granted again at T + 12h                 |
| `EE_T-CA-signtime-granted-later.xml`            | bad      | Granted only from T + 12h, no history                    |
| `EE_T-CA-signtime-noqscd-granted-before.xml`    | good     | Non-qualified (CA/PKC) from G until T - 12h              |
| `EE_T-CA-signtime-noqscd-granted-later.xml`     | bad      | Non-qualified (CA/PKC) from G until T + 12h              |
| `EE_T-no_QCStatement.xml`                       | bad      | Current qualifier QCStatement replaced with NotQualified |
| `EE_T-no_QCSD.xml`                              | bad      | Qualifiers QCWithQSCD/QCWithSSCD replaced with QCNoQSCD  |

### OCSP service

The OCSP responder certificate is checked against the OCSP service at T.

| File                                     | Expected | Change                                        |
| ---------------------------------------- | -------- | --------------------------------------------- |
| `EE_T-OCSP-invalid-type.xml`             | bad      | Service type changed to TSA/QTST              |
| `EE_T-OCSP-withdrawn.xml`                | bad      | Withdrawn at G                                |
| `EE_T-OCSP-withdrawn-granted-before.xml` | good     | Withdrawn at G, granted again at T - 12h      |
| `EE_T-OCSP-withdrawn-granted-later.xml`  | bad      | Withdrawn at G, granted again at T + 12h      |
| `EE_T-OCSP-granted-later.xml`            | bad      | Granted only from T + 12h, no history         |
| `EE_T-OCSP-noqscd-granted-before.xml`    | good     | Non-qualified (Certstatus/OCSP) until T - 12h |
| `EE_T-OCSP-noqscd-granted-later.xml`     | bad      | Non-qualified (Certstatus/OCSP) until T + 12h |

### TSA service

The time-stamping unit certificate is checked against the TSA service at T.

| File                                    | Expected | Change                                   |
| --------------------------------------- | -------- | ---------------------------------------- |
| `EE_T-TSA-invalid-type.xml`             | bad      | Service type changed to CA/QC            |
| `EE_T-TSA-withdrawn.xml`                | bad      | Withdrawn at T - 24h                     |
| `EE_T-TSA-withdrawn-granted-before.xml` | good     | Withdrawn at G, granted again at T - 12h |
| `EE_T-TSA-withdrawn-granted-later.xml`  | bad      | Withdrawn at G, granted again at T + 12h |
| `EE_T-TSA-granted-later.xml`            | bad      | Granted only from T + 12h, no history    |
| `EE_T-TSA-noqscd-granted-before.xml`    | good     | Non-qualified (TSA) until T - 12h        |
| `EE_T-TSA-noqscd-granted-later.xml`     | bad      | Non-qualified (TSA) until T + 12h        |

The expected results must match the good and bad lists in [test/CMakeLists.txt](../CMakeLists.txt).
