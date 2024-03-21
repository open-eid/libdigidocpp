#!/bin/bash

echo '01' > caserial.txt
echo '01' > interserial.txt
touch index
openssl req -out ca.req -new -newkey rsa:2048 -nodes -keyout ca.key -subj "/CN=libdigidocpp CA/C=EE"
openssl ca -create_serial -out ca.crt -days 3650 -keyfile ca.key -selfsign -extensions v3_ca -config ./openssl.conf -infiles ca.req

openssl req -out inter.req -new -newkey rsa:2048 -nodes -keyout inter.key -subj "/C=EE/CN=libdigidocpp Inter"
openssl x509 -req -in inter.req -out inter.crt -CA ca.crt -CAkey ca.key -CAserial caserial.txt -extfile openssl.conf -extensions v3_inter -days 3650 -sha512

openssl req -out ocsp.req -new -newkey rsa:2048 -nodes -keyout ocsp.key -subj "/C=EE/CN=libdigidocpp OCSP"
openssl x509 -req -in ocsp.req -out ocsp.crt -CA ca.crt -CAkey ca.key -CAserial caserial.txt -extfile openssl.conf -extensions v3_ocsp -days 3650 -sha512
# Server: openssl ocsp -index index.txt -CA ca.crt -rsigner ocsp.crt -rkey ocsp.key -port 8080
# Client: openssl ocsp -issuer inter.crt -cert signer1.crt -url http://localhost:8080 -VAfile ocsp.crt -text

for i in $(seq 1 3); do
	openssl req -out signer$i.req -new -newkey rsa:2048 -nodes -keyout signer$i.key -subj "/C=EE/CN=signer$i"
	openssl x509 -req -in signer$i.req -out signer$i.crt -CA inter.crt -CAkey inter.key -CAserial interserial.txt -extfile openssl.conf -extensions v3_usr -days 3650 -sha512
	openssl pkcs12 -export -in signer$i.crt -inkey signer$i.key -out signer$i.p12 -password pass:signer$i
done

openssl req -out signerEC.req -new -newkey ec:<(openssl ecparam -name secp384r1) -nodes -keyout signerEC.key -subj "/C=EE/CN=signer EC"
openssl x509 -req -in signerEC.req -out signerEC.crt -CA inter.crt -CAkey inter.key -CAserial interserial.txt -extfile openssl.conf -extensions v3_usr -days 3650 -sha512
openssl pkcs12 -export -in signerEC.crt -inkey signerEC.key -out signerEC.p12 -password pass:signerEC

openssl req -out unicode.req -new -newkey ec:<(openssl ecparam -name secp384r1) -nodes -keyout unicode.key -subj "/C=EE/CN=unicodeöäüõ" -utf8
openssl x509 -req -in unicode.req -out unicode.crt -signkey unicode.key -days 365 -sha512
