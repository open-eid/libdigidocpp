.\" Manpage for digidoc-tool
.TH digidoc-tool 1 "${BUILD_DATE}" "${VERSION}" "digidoc-tool man page"
.SH NAME
digidoc-tool \- open/create/verify ASiC-E/ASiC-S/BDoc format files
.SH SYNOPSIS
digidoc-tool COMMAND [OPTIONS] FILE
.SH OPTIONS
Command create:
  Example: digidoc-tool create --file=file1.txt --file=file2.txt demo-container.asice
  Available options:
    --file=        - File(s) to be signed. The option can occur multiple times.
    --mime=        - Specifies the file's mime-type value. When used then must be written right
                     after the "-file" parameter. Default value is application/octet-stream
    --dontsign     - Don't sign the newly created container.
    for additional options look sign command

Command createBatch:
  Example: digidoc-tool createBatch folder/content/to/sign
  Available options:
    for additional options look sign command

Command open:
  Example: digidoc-tool open container-file.asice
  Available options:
    --warnings=(ignore,warning,error) - warning handling (default warning)
    --policy=(POLv1,POLv2) - Signature Validation Policy (default POLv2)
                             http://open-eid.github.io/SiVa/siva/appendix/validation_policy/
    --extractAll[=path]    - extracts documents without validating signatures (to path when provided)
    --validateOnExtract    - validates container before extracting files

Command add:
  Example: digidoc-tool add --file=file1.txt container-file.asice
  Available options:
    --file and --mime look create command for info

Command remove:
  Example: digidoc-tool remove --document=0 --document=1 --signature=1 container-file.asice
  Available options:
    --document=    - documents to remove
    --signature=   - signatures to remove

Command websign:
  Example: digidoc-tool sign --cert=signer.crt demo-container.asice
  Available options:
    --cert=        - signer token certificate
    for additional options look sign command

Command sign:
  Example: digidoc-tool sign demo-container.asice
  Available options:
    --profile=     - signature profile, TM, time-mark, TS, time-stamp
    --XAdESEN      - use XAdES EN profile
    --city=        - city of production place
    --street=      - streetAddress of production place in XAdES profile
    --state=       - state of production place
    --postalCode=  - postalCode of production place
    --country=     - country of production place
    --role=        - option can occur multiple times. Signer role(s)
    --pkcs11[=]    - default is ${PKCS11_MODULE}. Path of PKCS11 driver.
    --pkcs12=      - pkcs12 signer certificate (use --pin for password)
    --pin=         - default asks pin from prompt
    --sha(224,256,384,512) - set default digest method (default sha256)
    --sigsha(224,256,384,512) - set default digest method (default sha256)
    --tsurl         - option to change TS URL (default http://demo.sk.ee/tsa)
    --dontValidate  - Don't validate container on signature creation

All commands:
    --nocolor       - Disable terminal colors
    --loglevel=[0,1,2,3,4] - Log level 0 - none, 1 - error, 2 - warning, 3 - info, 4 - debug
    --logfile=      - File to log, empty to console
.SH SEE ALSO
cdigidoc(1), qdigidoc4(1)
