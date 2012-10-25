//
//  IMSCryptoUtils.h
//  CryptoUtils
//
//  Created by Caleb Davenport on 10/8/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <Foundation/Foundation.h>

/*
 
 Perform an in-place XOR on each byte in the input.
 
 */
#define IMSXOR(_key, _input, _length) for (size_t _i = 0; _i < _length; _i++) { _input[_i] ^= _key; }

/*
 
 Perform a sum of the given bytes interpreted as eight-bit signed integers.
 This addition ignores overflow.
 
 */
int8_t IMSSum(const void *bytes, size_t length);

/*
 
 Simple utility for getting the two's complement of a signed integer value.
 
 */
int8_t IMSTwosComplement(int8_t value);

/*
 
 Get the checksum of a given data object by returning the two's complement
 of the sum of all of the bytes.
 
 */
int8_t IMSChecksum(NSData *data);

/*
 
 Generate an array of random bytes with the given length in bytes. This is a
 wrapper to arc4random_buf.
 
 */
NSData *IMSCryptoUtilsPseudoRandomData(size_t length);

/*
 
 Generate a derived key from the given key. This uses PBKDF2 key generation,
 SHA256 for pseudo random data generation, and one thousand rounds. Indicate
 the length of the resulting key and what salt should be used with the `length`
 and `salt` parameters respectively.
 
 */
NSData *IMSCryptoUtilsDeriveKey(NSData *key, size_t length, NSData *salt);

/*
 
 Run AES-128 encryption on the given data with the given key. The key length
 must be suitable for use in AES encryption. It is preferred that the key is 
 generated using `IMSCryptoUtilsDeriveKey`.
 
 */
NSData *IMSCryptoUtilsEncryptData(NSData *data, NSData *key);

/*
 
 Run AES-128 decryption on the given data with the given key. Given the nature
 of symetric-key encryption, the key must meet all requirements stated in
 `IMSCryptoUtilsEncryptData` and must be generated in the same fashion.
 
 */
NSData *IMSCryptoUtilsDecryptData(NSData *data, NSData *key);

/*
 
 Convert the given plist object then encrypt using `IMSEncryptData`.
 
 */
NSData *IMSCryptoUtilsEncryptPlistObjectWithKey(id object, NSData *key, NSData *salt);

/*
 
 Decrypt the given plist object then encrypt using `IMSDecryptData`.
 
 */
id IMSCryptoUtilsDecryptPlistObjectWithKey(NSData *data, NSData *key, NSData *salt);

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

/*
 
 Perform a SHA256 hash of the given object or data.
 
 */
NSData *IMSHashData_SHA256(NSData *data);
NSData *IMSHashPlistObject_SHA256(id object);
