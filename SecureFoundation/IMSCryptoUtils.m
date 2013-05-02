//
//  IMSCryptoUtils.m
//  CryptoUtils
//
//  Created by Caleb Davenport on 10/8/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"

#import <string.h>
#import <stdio.h>
#import <stdlib.h>
#import <openssl/evp.h>

#import "IMSKeyConst.h"

#define AES_BLOCK_SIZE 16

int8_t IMSSum(const void *bytes, size_t length) {
    int8_t sum = 0;
    int8_t *values = (int8_t *)bytes;
    for (size_t i = 0; i < length; i++) {
        sum += values[i];
    }
    return sum;
}

int8_t IMSTwosComplement(int8_t value) {
    return (~value + 1);
}

int8_t IMSChecksum(NSData *data) {
    int8_t sum = IMSSum([data bytes], [data length]);
    return IMSTwosComplement(sum);
}

NSData *IMSCryptoUtilsPseudoRandomData(size_t length) {
    if (length) {
        uint8_t *bytes = malloc(length);
        arc4random_buf(bytes, length);
        return [NSData dataWithBytesNoCopy:bytes length:length];
    }
    return nil;
}

// -----------------------------------------------------------------------------
// Create an 128 bit key and IV (initialization vector) for the key_data.
//
// returns an NSDictionary *gen on success with two keys @"k" and @"iv"
// -----------------------------------------------------------------------------

NSDictionary * IMSCryptoUtilsDeriveKey( NSData *key_data, NSData *salt) {
    
    NSDictionary  *gen     = nil;
    int            i       = 0;
    int            nrounds = 1000;
    unsigned char  key[16];
    unsigned char  iv [16];

    // -------------------------------------------------------------------------
    // Gen key & IV for AES 128 CBC mode. A SHA1 digest
    // is used to hash the supplied key material. nrounds is the number of times
    // the we hash the material. More rounds are more secure but slower.
    // -------------------------------------------------------------------------
    
    i = EVP_BytesToKey(  EVP_aes_128_cbc()
                       , EVP_sha1()
                       , [salt bytes]
                       , [key_data bytes]
                       , [key_data length]
                       , nrounds
                       , key
                       , iv);
    if (i != 16) {

#if DEBUG
        NSLog(@"Key size is %d bits - should be 128 bits\n", i);
#endif
    } else {
    
        NSData *k  = [NSData dataWithBytes:key length:16];
        NSData *iV = [NSData dataWithBytes:iv  length:16];
        
        gen        = @{@"k" : k, @"iv" : iV};
    }
    
    return gen;
}

int initEncryptContext ( EVP_CIPHER_CTX *ctx
                       , NSDictionary   *k_iv) {
    
    EVP_CIPHER_CTX_init(  ctx );
    
    return EVP_EncryptInit_ex ( ctx
                              , EVP_aes_128_cbc()
                              , NULL
                              , [k_iv[kOBJ1] bytes]
                              , [k_iv[kOBJ2] bytes]);
}
int initDencryptContext( EVP_CIPHER_CTX *ctx
                       , NSDictionary   *k_iv) {
    
    EVP_CIPHER_CTX_init(  ctx );
    
    return EVP_DecryptInit_ex ( ctx
                              , EVP_aes_128_cbc()
                              , NULL
                              , [k_iv[kOBJ1] bytes]
                              , [k_iv[kOBJ2] bytes]);
}

NSData *IMSCryptoUtilsEncryptData(NSData *data, NSDictionary *key) {

    NSData         *d          = nil;
    // ----------------------------------------------
    // max ciphertext len for a n bytes of plaintext
    // is n + AES_BLOCK_SIZE -1 bytes
    // ----------------------------------------------
    int             c_len      = [data length] + AES_BLOCK_SIZE;
    int             f_len      = 0;
    unsigned char  *ciphertext = malloc(c_len);
    
    EVP_CIPHER_CTX ctx;
    
    if ( initEncryptContext (&ctx,key) ) {
    
        // update ciphertext, c_len is filled with
        // the length of ciphertext generated, [data length]
        // is the size of plaintext in bytes
        int update = EVP_EncryptUpdate( &ctx
                                       ,ciphertext
                                       ,&c_len
                                       ,[data bytes]
                                       ,[data length]);
        if ( update ) {
            
            // update ciphertext with the final remaining bytes
            int final = EVP_EncryptFinal_ex(&ctx, ciphertext+c_len, &f_len);
            
            if ( final ) d = [NSData dataWithBytes:ciphertext
                                            length:c_len+f_len];
        }
        
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    
    free(ciphertext);
        
    return d;
}

NSData *IMSCryptoUtilsDecryptData(NSData *data, NSDictionary *key) {

    NSData        *d         = nil;
    // because we have padding ON,
    // we must allocate an extra cipher block size of memory
    int            p_len     = [data length];
    int            f_len     = 0;
    unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

    EVP_CIPHER_CTX ctx;
    
    if ( initDencryptContext(&ctx,key) ) {

        int update = EVP_DecryptUpdate  (&ctx
                                         ,plaintext
                                         ,&p_len
                                         ,[data bytes]
                                         ,[data length]);
        
        if ( update ) {
        
            int final = EVP_DecryptFinal_ex(&ctx, plaintext+p_len, &f_len);

            if ( final ) d = [NSData dataWithBytes:plaintext
                                            length:p_len+f_len];
        }
        
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    
    free(plaintext);
    
    return d;
}

/*
NSData *IMSCryptoUtilsDeriveKey(NSData *key, size_t length, NSData *salt) {
    if (key && length && salt) {
        uint8_t *derived_key = malloc(length);
        int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                          [key bytes],
                                          [key length],
                                          [salt bytes],
                                          [salt length],
                                          kCCPRFHmacAlgSHA256, // pseudo random algorithm
                                          1000, // number of rounds
                                          derived_key,
                                          length);
        if (status == kCCSuccess) { return [NSData dataWithBytesNoCopy:derived_key length:length]; }
        else {
            free(derived_key);
#if DEBUG
            NSLog(@"%s: Unable to generate derived key. Error %d", __PRETTY_FUNCTION__, status);
#endif
        }
    }
    return nil;
}

NSData *IMSCryptoUtilsEncryptData(NSData *data, NSData *key) {
    if (data && key) {
        
        // get initialization vector
        NSData *iv_data = IMSCryptoUtilsPseudoRandomData(kCCBlockSizeAES128);
        
        // get a cryptor instance
        CCCryptorRef cryptor;
        CCCryptorStatus status = CCCryptorCreate(kCCEncrypt, // operation
                                                 kCCAlgorithmAES128, // algorithm
                                                 kCCOptionPKCS7Padding, // options
                                                 [key bytes], [key length], // key bytes and length
                                                 [iv_data bytes], // initialization vector
                                                 &cryptor);
        if (status != kCCSuccess) { return nil; }
        
        // create a buffer
        size_t bufferSize = ([data length] + kCCBlockSizeAES128 + [iv_data length]);
        size_t length = [iv_data length];
        size_t written = length;
        void *buffer = malloc(bufferSize);
        if (buffer == nil) { return nil; }
        
        // set initialization vector
        memcpy(buffer, [iv_data bytes], [iv_data length]);
        
        // encrypt user data
        status = CCCryptorUpdate(cryptor,
                                 [data bytes], [data length],
                                 buffer + length,
                                 bufferSize - length,
                                 &written);
        if (status != kCCSuccess) { return nil; }
        length += written;
        
        // encrypt checksum
        int8_t checksum = IMSChecksum(data);
        CCCryptorUpdate(cryptor,
                        &checksum, sizeof(int8_t),
                        buffer + length,
                        bufferSize - length,
                        &written);
        length += written;
        
        // finalize
        status = CCCryptorFinal(cryptor,
                                buffer + length,
                                bufferSize - length,
                                &written);
        length += written;
        
        // release
        CCCryptorRelease(cryptor);
        
        // cleanup and return
        if (status == kCCSuccess) {
            return [NSData dataWithBytesNoCopy:buffer length:length];
        }
        else {
            free(buffer);
#if DEBUG
            NSLog(@"%s: Unable to perform encryption. Error %d", __PRETTY_FUNCTION__, status);
#endif
        }
        
    }
    return nil;
}

NSData *IMSCryptoUtilsDecryptData(NSData *data, NSData *key) {
    if (data && key) {
        
        // determine total needed space
        size_t length;
        CCCryptorStatus status;
        CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                [key bytes], [key length],
                [data bytes],
                [data bytes] + kCCBlockSizeAES128, [data length] - kCCBlockSizeAES128,
                NULL, 0,
                &length);
        
        // create buffer
        void *buffer = malloc(length);
        if (buffer == nil) { return nil; }
        
        // perform decryption
        status = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                         [key bytes], [key length],
                         [data bytes],
                         [data bytes] + kCCBlockSizeAES128, [data length] - kCCBlockSizeAES128,
                         buffer, length,
                         &length);
        
        // cleanup and return
        if (status == kCCSuccess) {
            int8_t sum = IMSSum(buffer, length);
            NSData *data = [NSData dataWithBytesNoCopy:buffer length:length - 1];
            if (sum == 0) { return data; }
            else {
                NSLog(@"%s: Integrity check failed.", __PRETTY_FUNCTION__);
                return nil;
            }    
        }
        else {
            free(buffer);
#if DEBUG
            NSLog(@"%s: Unable to perform encryption. Error %d", __PRETTY_FUNCTION__, status);
#endif
        }
        
    }
    return nil;
}
*/
NSData *IMSCryptoUtilsEncryptPlistObject(id object, NSData *key) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSCryptoUtilsEncryptData(data, key);
}

id IMSCryptoUtilsDecryptPlistObject(NSData *data, NSData *key) {
    NSData *decrypted = IMSCryptoUtilsDecryptData(data, key);
    return IMSConvertDataToPlistObject(decrypted);
}

NSData *IMSHashData_MD5(NSData *data) {
    void *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5([data bytes], [data length], buffer);
    return [NSData dataWithBytesNoCopy:buffer length:CC_MD5_DIGEST_LENGTH];
}

NSData *IMSHashPlistObject_MD5(id object) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSHashData_MD5(data);
}

NSData *IMSHashData_SHA256(NSData *data) {
    void *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([data bytes], [data length], buffer);
    return [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH];
}

NSData *IMSHashPlistObject_SHA256(id object) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSHashData_SHA256(data);
}

NSData *IMSConvertPlistObjectToData(id object) {
    return [NSPropertyListSerialization
            dataWithPropertyList:object
            format:NSPropertyListBinaryFormat_v1_0
            options:0
            error:nil];
}

id IMSConvertDataToPlistObject(NSData *data) {
    return [NSPropertyListSerialization
            propertyListWithData:data
            options:0
            format:0
            error:nil];
}
