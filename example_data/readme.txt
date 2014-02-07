****************************************************
Example data to accompany the article: 
	Exporting a non-exportable certificate - a reverse engineering demonstration
	Published in Hakin9, 2009
	Author: Thomas Cannon - http://thomascannon.net
****************************************************

Warning: You would have to run unprotect.py as the original user otherwise it won't
decrypt the key. Therefore the input files are provided for reference only and not as 
working examples.

****************************************************

This directory contains 2 input files:
-priv.enc		Encrypted private key extracted from keyfile in the keystore
-pub.pem		Public key exported from Certificates MMC Snap-in

and 4 output files:
-priv.dec		Private key decrypted by unprotect.py
-priv.pkcs8		Private key in PKCS8 format after running through MSPrivKeytoPKCS8
-priv.pem		Private key in pem format after running through openssl
-thomascannon.pfx	Complete certificate after combining priv.pem & pub.pem with openssl
	