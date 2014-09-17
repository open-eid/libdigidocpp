#!/bin/bash

echo '01' > caserial.txt
echo '01' > interserial.txt
touch index
openssl genrsa -out cakey.pem 2048
openssl req -out careq.pem -new -key cakey.pem -subj "/CN=libdigidocpp CA/C=EE"
openssl ca -create_serial -out cacert.pem -days 3650 -keyfile cakey.pem -selfsign -extensions v3_ca -config ./openssl.conf -infiles careq.pem

openssl genrsa -out interkey.pem 2048
openssl req -out req.pem -new -key interkey.pem -subj "/C=EE/CN=libdigidocpp Inter"
openssl x509 -req -in req.pem -out intercert.pem -CA cacert.pem -CAkey cakey.pem -CAserial caserial.txt  -extfile openssl.conf -extensions v3_inter -days 3650

openssl genrsa -out ocspkey.pem 2048
openssl req -out req.pem -new -key ocspkey.pem -subj "/C=EE/CN=libdigidocpp OCSP"
openssl x509 -req -in req.pem -out ocspcert.pem -CA cacert.pem -CAkey cakey.pem -CAserial caserial.txt  -extfile openssl.conf -extensions v3_ocsp -days 3650

for i in $(seq 1 3); do
	openssl genrsa -out key.pem 2048
	openssl req -out req.pem -new -key key.pem -subj "/C=EE/CN=signer$i"
	openssl x509 -req -in req.pem -out cert.pem -CA intercert.pem -CAkey interkey.pem -CAserial interserial.txt  -extfile openssl.conf -extensions v3_usr -days 3650
	openssl pkcs12 -export -nodes -in cert.pem -inkey key.pem -out signer$i.p12 -password pass:signer$i
done

openssl ecparam -genkey -name secp256r1 -out key.pem
openssl req -out req.pem -new -key key.pem -subj "/C=EE/CN=signer EC"
openssl x509 -req -in req.pem -out cert.pem -CA intercert.pem -CAkey interkey.pem -CAserial interserial.txt  -extfile openssl.conf -extensions v3_usr -days 3650
openssl pkcs12 -export -nodes -in cert.pem -inkey key.pem -out signerEC.p12 -password pass:signerEC
