.\" Manpage for digidoc-tool
.TH digidoc-tool 1 "${BUILD_DATE}" "${VERSION}" "digidoc-tool man page"
.SH NAME
digidoc-tool \- open/create/verify BDoc format files
.SH SYNOPSIS
digidoc-tool COMMAND [OPTIONS] FILE
.SH OPTIONS
Command create:
  Example: digidoc-tool create --file=file1.txt --file=file2.txt demo-container.bdoc
  Available options:
    --file=        - The option can occur multiple times. File(s) to be signed
    --mime=        - can be after --file parameter. Default value is application/octet-stream
    --dontsign     - Don't sign the newly created container.
    for additional options look sign command

Command createBatch:
  Example: digidoc-tool createBatch folder/content/to/sign
  Available options:
    for additional options look sign command

Command open:
  Example: digidoc-tool open container-file.bdoc
  Available options:
    --warnings=(ignore,warning,error) - warning handling
    --policy=(POLv1,POLv2) - Signature Validation Policy (default POLv2)
                             http://open-eid.github.io/SiVa/siva/appendix/validation_policy/
    --extractAll[=path] - extracts documents (to path when provided)

Command add:
  Example: digidoc-tool add --file=file1.txt container-file.bdoc
  Available options:
    --file=        - The option can occur multiple times. File(s) to be added to the container
    --mime=        - can be after --file parameter. Default value is application/octet-stream

Command remove:
  Example: digidoc-tool remove --document=0 --document=1 --signature=1 container-file.bdoc
  Available options:
    --document=    - documents to remove
    --signature=   - signatures to remove

Command websign:
  Example: digidoc-tool sign --cert=signer.crt demo-container.bdoc
  Available options:
    --cert=        - signer token certificate
    for additional options look sign command

Command sign:
  Example: digidoc-tool sign demo-container.bdoc
  Available options:
    --profile=     - signature profile, TM, time-mark, TS, time-stamp
    --XAdESEN      - use XAdES EN profile
    --city=        - city of production place
    --street=      - streetAddress of production place in XAdES profile
    --state=       - state of production place
    --postalCode=  - postalCode of production place
    --country=     - country of production place
    --role=        - option can occur multiple times. Signer role(s)
    --pkcs11[=]    - default is /Library/OpenSC/lib/opensc-pkcs11.so. Path of PKCS11 driver.
    --pkcs12=      - pkcs12 signer certificate (use --pin for password)
    --pin=         - default asks pin from prompt
    --sha(224,256,384,512) - set default digest method (default sha256)
    --sigsha(224,256,384,512) - set default digest method (default sha256)
    --dontValidate= - Don't validate container

All commands:
    --nocolor       - Disable terminal colors
.SH SEE ALSO
cdigidoc(1), qdigidocclient(1), qesteidutil(1)
