@ECHO OFF
SET mypath=%~dp0
cd %mypath:~0,-1%

ECHO === GENERATE PRIVATE KEY --- Format: PKCS#1 --- File: private.txt===
openssl genrsa -f4 -out private.txt 4096 

ECHO === GENERATE PRIVATE KEY --- Format: PKCS#8 --- File: private8.txt===
openssl pkcs8 -topk8 -inform pem -in private.txt -outform PEM -nocrypt -out private8.txt

ECHO === GENERATE PUBLIC KEY --- Format: X.509 --- File: public.txt===
openssl rsa -in private.txt -outform PEM -pubout -out public.txt
PAUSE

