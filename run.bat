@echo off
REM Code to accompany the article: 
REM Exporting a non-exportable certificate - a reverse engineering demonstration
REM	Published in Hakin9, 2009
REM	Author: Thomas Cannon - http://thomascannon.net

REM To start with you need:
REM 	pub.pem - public key exported from Certificates MMC Snap-in
REM	priv.enc - encrypted private key extracted from keyfile in the keystore

REM Batch script will then do the following:
REM 1) Decrypts priv.enc and outputs as priv.dec
REM 2) Converts priv.dec to PKCS8 format as priv.pkcs8
REM 3) Converts priv.pkcs8 to PEM format as priv.pem
REM 4) Combines priv.pem & pub.pem as a complete certificate thomascannon.pfx

python unprotect.py
java MSPrivKeytoPKCS priv.dec priv.pkcs8
openssl pkcs8 -in priv.pkcs8 -inform DER -nocrypt -out priv.pem
openssl pkcs12 -in pub.pem -inkey priv.pem -export -out thomascannon.pfx

pause