Source code to accompany the article:

*Exporting a non-exportable certificate - a reverse engineering demonstration*

Published in Hakin9, 2009

Original blog [here](http://thomascannon.net/blog/2009/05/exporting-non-exportable-certificates/)

-----

File | Description
------------------
`run.bat` | Batch file to automate the whole process
`unprotect.py` | Decrypts private key extracted from keyfile in keystore. Expects input file `priv.enc` to be in the same directory. Outputs `priv.dec`
`MSPrivKeytoPKCS8.java` | Source code for *MSPrivKeytoPKCS8*
`MSPrivKeytoPKCS8.class` | Compiled *MSPrivKeytoPKCS8* which converts `priv.dec` into PKCS8 format. Expects name of input & output files as parameters.
