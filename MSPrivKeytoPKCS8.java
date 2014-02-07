//**************************************************************
// 
// MSPrivKeytoPKCS8.java
// Release: 2008-05-15_01
//
// Code to accompany the article: 
// 	Exporting a non-exportable certificate - a reverse engineering demonstration
//	Published in Hakin9, 2009
//	Author: Thomas Cannon - http://thomascannon.net
//
// Compile: javac MSPrivKeytoPKCS8.java
// Usage: java MSPrivKeytoPKCS8 <infile.dec> <outfile.pkcs8>
//
// Input is a file containing a private key which has been
// extracted from a Windows keyfile and decrypted with
// CryptUnprotectData.
//
// Output is the private key in a standard PKCS8 format
//
// Changes were made to handle the format and decoding of the input file
// as well as some debug messages, but otherwise the code is entirely  
// based on:
//	CryptoAPI PRIVATEKEYBLOB to Java PrivateKey Bridge
//	Copyright (C) 2005  Michel I. Gallant
//
//***************************************************************

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;

// ---  Utility class to convert CryptoAPI PRIVATEKEYBLOB file to Java PrivateKey object
// ---  Optionally writes ASN.1 encoded pkcs#8  PrivateKeyInfo  private key output file.
// ---  Optionially writes ANS.1 encoded SubjectPublicKeyInfo public key output file.
// ---  Note that Java reads multi-byte data as BIG-endian (compare to little-endian for C, C# etc..)  -----
// -- See  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/seccrypto/security/private_key_blobs.asp

class MSPrivKeytoJKey {

private static final byte PRIVATEKEYBLOB	= 	0x07;
private static final byte CUR_BLOB_VERSION 	= 	0x02;
private static final short RESERVED		= 	0x0000;
private static final int CALG_RSA_KEYX		= 	0x0000a400;
private static final int CALG_RSA_SIGN		= 	0x00002400;
private static final String MAGIC		=	"RSA2"	; 	// 0x32415352


  public static void main(String[] args) {
   if (args.length != 1 && args.length !=2 &&  args.length !=3) {
	System.out.println("Usage: java MSPrivKeytoJkey <PRIVATEKEYBLOB file>  [pkcs#8encodedfile]   [SubjectPublicKeyInfo_pubkey]");
	return; 
	}

	RSAPrivateKey pvkKey = (RSAPrivateKey) MSPrivKeytoJKey.getPrivateKey(args[0]);
	if(pvkKey == null)
	{
		System.out.println("FAILED to get PrivateKey") ;
		System.exit(0) ;
	}
	System.out.println("Converted  PRIVATEKEYBLOB  '" + args[0] + "' to Java RSA PrivateKey\n") ;
	dumpRSAPrivatekey(pvkKey) ;
	byte[] pkcs8encoded = pvkKey.getEncoded() ;
	FileOutputStream fos = null;

	// ----------  Optionally write out encoded pkcs#8 PrivateKeyInfo file  -------------
	if(args.length > 1) {
		try{
		fos = new FileOutputStream(args[1]);
		fos.write(pkcs8encoded);
		fos.close();
		System.out.println("Wrote pkcs#8 PrivateKeyInfo file '" + args[1] + "'") ;
		}
		catch(IOException ioe) {System.err.println(ioe);}
	}


	// ----------  Optionally write out encoded SubjectPublicKeyInfo public-key file  -------------
	if(args.length > 2) {
		try{
		RSAPrivateCrtKey pKey = (RSAPrivateCrtKey)pvkKey;
		BigInteger modulus = pKey.getModulus() ;
		BigInteger pubexp   = pKey.getPublicExponent() ;

		RSAPublicKeySpec pubkeyspec = new RSAPublicKeySpec(modulus, pubexp);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubkey = keyFactory.generatePublic(pubkeyspec);
		fos = new FileOutputStream(args[2]);
		fos.write(pubkey.getEncoded());	//write the ANS.1 SubjecPublickeyInfo
		fos.close();
		System.out.println("Wrote SubjectPublicKeyInfo file '" + args[2] + "'") ;
		}
		catch(Exception ex) {System.err.println(ex);}
	}

  }



 public static PrivateKey getPrivateKey (String msprivatekeyblobfile)
 {
	System.out.println("Getting PrivateKey: " + msprivatekeyblobfile);
	File blobfile = new File(msprivatekeyblobfile) ;
	System.out.println("Blobfile length:" + blobfile.length());
	if (!blobfile.exists())
		return null;	
	int blobsize = ((int) blobfile.length());
	byte[] blobdata = new byte[blobsize];
	try 
	{
	 FileInputStream freader = new FileInputStream(blobfile);
	 freader.read(blobdata, 0, blobsize) ;
	 freader.close();
	 System.out.println("Passing blob to getprivkey");
	 return getPrivateKey(blobdata);
	}
	catch(IOException ioe)
	 {
	 return null;
	}
 }


 public static PrivateKey getPrivateKey (byte[] msprivatekeyblob)
 {
   System.out.println("Blob length:" + msprivatekeyblob.length);
   if(msprivatekeyblob == null ||  msprivatekeyblob.length == 0)
	return null;
   System.out.println("Now in getprivkey");
   DataInputStream dis = null;
   int jint = 0 ; // int to build Java int from little-endian ordered byte data
   int bitlen = 0;
   int bytelen = 0;
   int pubexp = 0;
   int x = 0; // Variable to store extra bytes which are ignored. - Thomas.

	try
	{
	//------ Read the "BLOBHEADER" fields -------------
	 displayData(msprivatekeyblob) ;
	 ByteArrayInputStream bis = new ByteArrayInputStream(msprivatekeyblob);
	 dis = new DataInputStream(bis);

//Don't need this for our input file. - Thomas.
	 //if(dis.readByte()  != PRIVATEKEYBLOB
	 //|| dis.readByte()  != CUR_BLOB_VERSION 
	 //|| dis.readShort() != RESERVED)
	//	return null;

	System.out.println("BLOB Read");

//Don't need this for our input key. - Thomas.
	//jint = 0;
	//for (int i=0; i<4; i++) 
	//  jint += dis.readUnsignedByte() *(int)Math.pow(256,i) ;
	//if(jint != CALG_RSA_KEYX  &&  jint != CALG_RSA_SIGN)
	//	return null;

	//------ Read the RSAPUBKEY struct members ---------
	StringBuffer magic = new StringBuffer(4);
	for (int i=1; i<=4; i++) 
	  magic.append((char)dis.readByte()) ;
	if(!magic.toString().equals(MAGIC))
		return null;

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	for (int i=0; i<4; i++) 
	  bitlen += dis.readUnsignedByte() *(int)Math.pow(256,i) ;
	bytelen = bitlen/8 ;  //byte size of this RSA key
	System.out.println("Key length:" + bytelen);

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	for (int i=0; i<4; i++) 
	  pubexp += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	//----- Read the PRIVATEKEYBLOB private key components, and reverse bytes to get big-endian ordering --------
	System.out.println("Read the PRIVATEKEYBLOB private key");

	int bytesread = 0;

	byte[] modulus = new byte[bytelen] ;
	bytesread = dis.read(modulus) ;
	if(bytesread != (bytelen))  //if not enough modulus bytes
	  return null;

	displayData(modulus);

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<8; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	byte[] primeP = new byte[bytelen/2];
	bytesread = dis.read(primeP);
	if(bytesread != (bytelen/2)) 
	  return null;

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	byte[] primeQ = new byte[bytelen/2];
	bytesread = dis.read(primeQ);
	if(bytesread != (bytelen/2))
	  return null;

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	byte[] expP = new byte[bytelen/2];
	bytesread = dis.read(expP);
	if(bytesread != (bytelen/2))
	  return null;
	
//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	byte[] expQ = new byte[bytelen/2];
	bytesread = dis.read(expQ);
	if(bytesread != (bytelen/2))
	  return null;

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	byte[] coeff = new byte[bytelen/2];
	bytesread = dis.read(coeff);
	if(bytesread != (bytelen/2))
	  return null;

//Our input key has some extra bytes, read and ignore them - Thomas.
	for (int i=0; i<4; i++) 
	  x += dis.readUnsignedByte() *(int)Math.pow(256,i) ;

	byte[] privExp = new byte[bytelen];
	bytesread = dis.read(privExp);
	if(bytesread != (bytelen))
	  return null;


	// Reverse arrays to create big-endian order
	ReverseMemory(modulus) ;
	ReverseMemory(primeP) ;
	ReverseMemory(primeQ) ;
	ReverseMemory(expP) ;
	ReverseMemory(expQ) ;
	ReverseMemory(coeff) ;
	ReverseMemory(privExp) ;


	//----- Create the PrivateKey from private key components Spec --------
	System.out.println("Create the PrivateKey");

	 RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
		new BigInteger(1, modulus), BigInteger.valueOf(pubexp), new BigInteger(1, privExp),
		new BigInteger(1, primeP), new BigInteger(1, primeQ), new BigInteger(1, expP), 
		new BigInteger(1, expQ), new BigInteger(1, coeff) );

	 KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	 PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
	 System.out.println("Private key created!");

	 return privKey;
	}
	catch(Exception exc)
	{
	 return null;
	}
	finally
	{
	 try {dis.close();}
	 catch(Exception exc) {System.err.println(exc); }
	}
 }
 


 private static void dumpRSAPrivatekey(PrivateKey pkey) {

	try{
	 RSAPrivateCrtKey pvkKey = (RSAPrivateCrtKey)pkey;
	 System.out.println("\nModulus:\n" + pvkKey.getModulus().toString());
	displayData(pvkKey.getModulus().toByteArray()) ;

	 System.out.println("\n\nPublic Exponent:\n" + pvkKey.getPublicExponent().toString());
	displayData(pvkKey.getPublicExponent().toByteArray()) ;

	 System.out.println("\n\nPrivate Exponent:\n" + pvkKey.getPrivateExponent().toString());
	displayData(pvkKey.getPrivateExponent().toByteArray()) ;

	 System.out.println("\n\nPrime Exponent P:\n" + pvkKey.getPrimeExponentP().toString());
	displayData( pvkKey.getPrimeExponentP().toByteArray()) ;

	 System.out.println("\n\nPrime Exponent Q:\n" + pvkKey.getPrimeExponentQ().toString());
	displayData( pvkKey.getPrimeExponentQ().toByteArray()) ;

	 System.out.println("\n\nPrime P:\n" + pvkKey.getPrimeP().toString());
	displayData( pvkKey.getPrimeP().toByteArray()) ;

	 System.out.println("\n\nPrime Q:\n" + pvkKey.getPrimeQ().toString());
	displayData( pvkKey.getPrimeQ().toByteArray()) ;

	 System.out.println("\n\nCrtCoeff:\n" + pvkKey.getCrtCoefficient().toString());
	displayData(pvkKey.getCrtCoefficient().toByteArray()) ;
	}
	catch(Exception e) {System.err.println(e);} 
 }



  private static void displayData(byte[] data)
  {
	int bytecon = 0;    //to get unsigned byte representation
	for(int i=1; i<=data.length ; i++){
		bytecon = data[i-1] & 0xFF ;   // byte-wise AND converts signed byte to unsigned.
	if(bytecon<16)
		System.out.print("0" + Integer.toHexString(bytecon).toUpperCase() + " ");   // pad on left if single hex digit.
	else
		System.out.print(Integer.toHexString(bytecon).toUpperCase() + " ");   // pad on left if single hex digit.
	if(i%16==0)
		System.out.println();
	  }
   System.out.println() ;
  }


private static void ReverseMemory (byte[] pBuffer)
{
     byte b ;
     int iLength = pBuffer.length;     
     for (int i = 0 ; i < iLength/ 2 ; i++)
     {
          b = pBuffer [i] ;
          pBuffer [i] = pBuffer [iLength - i - 1] ;
          pBuffer [iLength - i - 1] = b ;
     }
}

}




