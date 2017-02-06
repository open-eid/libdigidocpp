# Test data

## Container tests
* [47101010033.cer](47101010033.cer) - Used in X509Crypto test suite

## TSL tests
Validates [tsl.asice](tsl.asice) (signing time 2016-11-28T13:46:41Z) file with given TSL-s.

* [EE_T-CA-invalid-type.xml](EE_T-CA-invalid-type.xml) - CA service type altered
* [EE_T-CA-non-qa.xml](EE_T-CA-non-qa.xml) - CA service non-qualified
* [EE_T-CA-withdrawn.xml](EE_T-CA-withdrawn.xml) - CA service revoked at 2016-11-27T21:00:00Z
* [EE_T-CA-withdrawn-granted-before.xml](EE_T-CA-withdrawn-granted-before.xml) - CA service revoked at 2016-11-27T22:00:00Z and granted at 2016-11-28T01:00:00Z
* [EE_T-CA-withdrawn-granted-later.xml](EE_T-CA-withdrawn-granted-later.xml) - CA service revoked at 2016-11-27T22:00:00Z and granted at 2016-11-29T01:00:00Z
* [EE_T-OCSP-invalid-type.xml](EE_T-OCSP-invalid-type.xml) - OCSP service type altered
* [EE_T-OCSP-withdrawn.xml](EE_T-OCSP-withdrawn.xml) - OCSP service revoked at 2016-11-27T22:00:00Z
* [EE_T-OCSP-withdrawn-granted-before.xml](EE_T-OCSP-withdrawn-granted-before.xml) - OCSP service revoked at 2016-11-27T22:00:00Z and granted at 2016-11-28T01:00:00Z
* [EE_T-OCSP-withdrawn-granted-later.xml](EE_T-OCSP-withdrawn-granted-later.xml) - OCSP service revoked at 2016-11-27T22:00:00Z and granted at 2016-11-29T01:00:00Z
* [EE_T-TSA-invalid-type.xml](EE_T-TSA-invalid-type.xml) - TSA service type altered
* [EE_T-TSA-withdrawn.xml](EE_T-TSA-withdrawn.xml) - TSA service revoked at 2016-11-27T21:00:00Z
* [EE_T-TSA-withdrawn-granted-before.xml](EE_T-TSA-withdrawn-granted-before.xml) - TSA service revoked at 2016-05-31T21:00:00Z and granted at 2016-11-28T01:00:00Z
* [EE_T-TSA-withdrawn-granted-later.xml](EE_T-TSA-withdrawn-granted-later.xml) - TSA service revoked at 2014-11-27T21:00:00Z and granted at 2016-11-29T01:00:00Z
* [EE_T-no_QCStatement.xml](EE_T-no_QCStatement.xml) - Signer certificate QCStatement revoked
* [EE_T-no_QCSD.xml](EE_T-no_QCSD.xml) - Signer certificate QCSD revoked