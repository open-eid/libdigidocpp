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
    for additional options look sign command

Command open:
  Example: digidoc-tool open container-file.bdoc
  Available options:
    --warnings=(ignore,warning,error) - warning handling
    --extractAll   - extracts documents (to path when provided)

Command remove:
  Example: digidoc-tool remove --document=0 --document=1 --signature=1 container-file.bdoc
  Available options:
    --document=    - documents to remove
    --signature=   - signatures to remove

Command sign:
  Example: digidoc-tool sign demo-container.bdoc
  Available options:
    --profile=     - signature profile, TM, time-mark, TS, time-stamp
    --city=        - city of production place
    --state=       - state of production place
    --postalCode=  - postalCode of production place
    --country=     - country of production place
    --role=        - option can occur multiple times. Signer role(s)
    --pkcs11[=]    - default is /Library/OpenSC/lib/opensc-pkcs11.so. Path of PKCS11 driver.
    --pkcs12=      - pkcs12 signer certificate (use --pin for password)
    --pin=         - default asks pin from prompt
    --sha(1,224,256,384,512) - set default digest method (default sha256)
.SH SEE ALSO
cdigidoc(1), qdigidocclient(1), qesteidutil(1)
