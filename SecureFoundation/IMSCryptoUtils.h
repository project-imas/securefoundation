//
//  IMSCryptoUtils.h
//  CryptoUtils
//
//  Upated:
//     Gregg Ganley    Sep 2013
//
//  Created on 10/8/12.
//  Copyright (c) 2013 The MITRE Corporation. All rights reserved.
//

#import <Foundation/Foundation.h>

/*
 
 Perform an in-place XOR on each byte in the input.
 
 */
#define IMSXOR(_key, _input, _length) for (size_t _i = 0; _i < _length; _i++) { _input[_i] ^= _key; }

/*
 
 Generate an array of random bytes with the given length in bytes. This is a
 wrapper to arc4random_buf.
 
 */
NSData *IMSCryptoUtilsPseudoRandomData(size_t length);

/*
  Generate a random string with the given length in bytes.
  */
NSString *IMSGenerateRandomString(int num);
    

/*
 
 Generate a derived key from the given key. This uses PBKDF2 key generation,
 SHA256 for pseudo random data generation, and one thousand rounds. Indicate
 the length of the resulting key and what salt should be used with the `length`
 and `salt` parameters respectively.
 
 */
NSData *IMSCryptoUtilsDeriveKey(NSData *key, size_t length, NSData *salt);


/*
 Encrypt/decrypt files in sandbox. If destPath is nil, the file is encrypted in place.
 Otherwise, an encrypted copy of the file at origPath is created at destPath.
 Functions return 0 if operation was successful and -1 otherwise.
 */
int IMSCryptoUtilsEncryptFileToPath(NSString *origPath, NSString *destPath, NSData *key);
int IMSCryptoUtilsDecryptFileToPath(NSString *origPath, NSString *destPath, NSData *key);

/*
 
 Run AES-128  encryption on the given data with the given key. The key length
 must be suitable for use in AES encryption. It is preferred that the key is 
 generated using `IMSCryptoUtilsDeriveKey`.  ciphertext contains IV and a checksum, so ciphertext len > plaintext len
 
 */
NSData *IMSCryptoUtilsEncryptData(NSData *data, NSData *key);
NSData *IMSCryptoUtilsDecryptData(NSData *data, NSData *key);


//** AES 256 bit encryption, ciphertext len = plaintext len
NSData *IMSCryptoUtilsSimpleEncryptData(NSData *plaintext, NSData *key, NSData *iv);
NSData *IMSCryptoUtilsSimpleDecryptData(NSData *ciphertext, NSData *key, NSData *iv);


//** AES 256 bit encryption, C buffers, and ciphertext len = plaintext len
//** Key length must be 32 bytes!!
//** IV length must be 16 bytes!!
void *IMSCryptoUtilsC_EncryptData(u_int8_t *plaintext,  int length, u_int8_t *key, u_int8_t *iv);
void *IMSCryptoUtilsC_DecryptData(u_int8_t *ciphertext, int length, u_int8_t *key, u_int8_t *iv);


/*
 
 Convert the given plist object then encrypt using `IMSCryptoUtilsEncryptData`.
 
 */
NSData *IMSCryptoUtilsEncryptPlistObject(id object, NSData *key);

/*
 
 Decrypt the given plist object then encrypt using `IMSCryptoUtilsDecryptData`.
 
 */
id IMSCryptoUtilsDecryptPlistObject(NSData *data, NSData *key);

/*
 
 Translate between plist objects and binary data.
 
 */
NSData *IMSConvertPlistObjectToData(id object);
id IMSConvertDataToPlistObject(NSData *data);

/*
 
 Perform an MD5 hash of the given object or data.
 
 */
NSData *IMSHashData_MD5(NSData *data);
NSData *IMSHashPlistObject_MD5(id object);
unsigned char *IMSHashBytes_MD5(void *obj, int len);

/*
 
 Perform a SHA256 hash of the given object or data.
 
 */
NSData *IMSHashData_SHA256(NSData *data);
NSData *IMSHashPlistObject_SHA256(id object);
unsigned char *IMSHashBytes_SHA256(void *obj, int len);


//**
NSString *IMSEncodeBase64(NSData *inputData);
NSData *IMSDeodeBase64(NSString *encodedString);



