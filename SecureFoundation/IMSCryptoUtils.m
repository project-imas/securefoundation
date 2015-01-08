//
//  IMSCryptoUtils.m
//  CryptoUtils
//
//  Upated:
//     Gregg Ganley    Sep 2013
//
//  Created on 10/8/12.
//  Copyright (c) 2013 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"


//**********************
//**********************
//**
//**
int8_t IMSSum(const void *bytes, size_t length) {
    int8_t sum = 0;
    int8_t *values = (int8_t *)bytes;
    for (size_t i = 0; i < length; i++) {
        sum += values[i];
    }
    return sum;
}


//**********************
//**********************
//**
//**
int8_t IMSTwosComplement(int8_t value) {
    return (~value + 1);
}


//**********************
//**********************
//**
//**
int8_t IMSChecksum(NSData *data) {
    int8_t sum = IMSSum([data bytes], [data length]);
    return IMSTwosComplement(sum);
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsPseudoRandomData(size_t length) {
    if (length) {
        NSMutableData* ret = [NSMutableData dataWithCapacity:length];
        for (int i = 0; i < length/4; i++) {
            u_int32_t randomBits = arc4random();
            [ret appendBytes:(void *)&randomBits length:4];
        }
        return ret;
    }
    return nil;
}


//**********************
//**********************
//**
//**
NSString *IMSGenerateRandomString(int num) {
    NSMutableString* string = [NSMutableString stringWithCapacity:num];
    for (int i = 0; i < num; i++) {
        [string appendFormat:@"%C", (unichar)('a' + arc4random_uniform(25))];
    }
    return string;
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsDeriveKey(NSData *key, size_t length, NSData *salt) {

    if (!(key && length && salt))
        return nil;
    

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
    if (status == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:derived_key length:length];
    }
    else {
        free(derived_key);
        //NSLog(@"%s: Unable to generate derived key. Error %d", __PRETTY_FUNCTION__, status);
    }
    
    return nil;
}

//**********************
//**********************
//** Encrypt file in sandbox
//** (either in place or to a separate location)
//** If error, returns -1 instead of file size
int IMSCryptoUtilsEncryptFileToPath(NSString *origPath, NSString *destPath, NSData *key) {
    NSError *err = nil;
    NSDictionary *fileAttr = [[NSFileManager defaultManager] attributesOfItemAtPath:origPath error:&err];
    if (err) {
        NSLog(@"Error reading file %@: %@", origPath, err);
        return -1;
    }
    int size = (int)[fileAttr fileSize];
    
    NSFileHandle *handle = [NSFileHandle fileHandleForUpdatingAtPath:origPath];
    NSFileHandle *writeHandle;
    if (destPath) {
        writeHandle = [NSFileHandle fileHandleForWritingAtPath:destPath];
        if (!writeHandle) {
            [[NSFileManager defaultManager] createFileAtPath:destPath contents:nil attributes:nil];
            writeHandle = [NSFileHandle fileHandleForWritingAtPath:destPath];
        }
    }
    NSData *fileChunk = [handle readDataOfLength:size]; // TODO does it auto advance?
    NSData *encryptedData = IMSCryptoUtilsEncryptData(fileChunk, key);
    
    if (!destPath) {
        [handle seekToFileOffset:0];
        [handle writeData:encryptedData];
    } else { // write encrypted file to to destPath
        [writeHandle writeData:encryptedData];
    }
    
    [handle closeFile];
    if (destPath)
        [writeHandle closeFile];
    
    return 0;
}

//**********************
//**********************
//** Decrypt file in sandbox
//** (either in place or to a separate location)
int IMSCryptoUtilsDecryptFileToPath(NSString *origPath, NSString *destPath, NSData *key) {
    NSDictionary *fileAttr = [[NSFileManager defaultManager] attributesOfItemAtPath:origPath error:nil];
    int size = (int)[fileAttr fileSize];
    
    NSFileHandle *handle = [NSFileHandle fileHandleForUpdatingAtPath:origPath];
    NSFileHandle *writeHandle;
    if (destPath) {
        writeHandle = [NSFileHandle fileHandleForWritingAtPath:destPath];
        if (!writeHandle) {
            [[NSFileManager defaultManager] createFileAtPath:destPath contents:nil attributes:nil];
            writeHandle = [NSFileHandle fileHandleForWritingAtPath:destPath];
        }
    }
    
    NSData *fileChunk = [handle readDataOfLength:size];
    NSData *decryptedData = IMSCryptoUtilsDecryptData(fileChunk, key);
    int decryptDataSize = (int)decryptedData.length;
    
    if (!decryptedData) {
        NSLog(@"Decryption of file %@ failed", origPath);
        return -1;
    }
    
    if (!destPath) {
        [handle seekToFileOffset:0];
        [handle writeData:decryptedData];
//        [handle truncateFileAtOffset:origSize];
        [handle truncateFileAtOffset:decryptDataSize];
    } else { // write encrypted file to to destPath
        [writeHandle writeData:decryptedData];
//        [writeHandle truncateFileAtOffset:origSize];
        [writeHandle truncateFileAtOffset:decryptDataSize];
    }
    
    [handle closeFile];
    if (destPath)
        [writeHandle closeFile];
    return 0;
}


//**********************
//**********************
//**
//** Key length must be 32 bytes!!
//** IV length must be 16 bytes!!
void *IMSCryptoUtilsC_EncryptData(u_int8_t *plaintext, int length, u_int8_t *key, u_int8_t *iv) {
    
    if (plaintext == 0 || key == 0 || iv == 0)
        return nil;
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    NSData *plaintextData = [NSData dataWithBytes:plaintext length:length];
    NSData *keyData = [NSData dataWithBytes:key length:kCCKeySizeAES256];
    NSData *ivData = [NSData dataWithBytes:iv length:kCCKeySizeAES128];
    
    
    NSData *data = IMSCryptoUtilsSimpleEncryptData(plaintextData, keyData, ivData);
    if(data) {
        return (u_int8_t *)[data bytes];
    }
    
    return nil;
}



//**********************
//**********************
//**
//**
void *IMSCryptoUtilsC_DecryptData(u_int8_t *ciphertext, int length, u_int8_t *key, u_int8_t *iv)
{
    if (ciphertext == 0 || key == 0 || iv == 0)
        return nil;
    
    //*****************************************
    //*****************************************
    //** Apple Crypto
    int remainder = length % 16;
    // Round up to block size and then add one more block
    length = length + 32 - remainder;

    NSData *ciphertextData = [NSData dataWithBytes:ciphertext length:length];
    NSData *keyData = [NSData dataWithBytes:key length:kCCKeySizeAES256];
    NSData *ivData = [NSData dataWithBytes:iv length:kCCKeySizeAES128];
    
    NSData *data = IMSCryptoUtilsSimpleDecryptData(ciphertextData, keyData, ivData);
    if(data) {
        return (u_int8_t *)[data bytes];
    }
    
    return nil;    
}




//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsSimpleEncryptData(NSData *plaintext, NSData *key, NSData *iv) {
    
    if (plaintext == 0 || key == 0 || iv == 0)
        return nil;

    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    // get a cryptor instance
    CCCryptorRef cryptor;
    CCCryptorStatus status = CCCryptorCreate(kCCEncrypt, // operation
                                             kCCAlgorithmAES128, // algorithm
                                             kCCOptionPKCS7Padding, // options
                                             [key bytes], [key length], // key bytes and length
                                             [iv bytes], // initialization vector
                                             &cryptor);
    if (status != kCCSuccess)
    { return nil; }
    
    // create a buffer
    size_t ciphertext_len = ([plaintext length] + kCCBlockSizeAES128 + [iv length]);
    size_t length = [iv length];
    size_t written;
    void *ciphertext = malloc(ciphertext_len);
    if (ciphertext == nil)
    { return nil; }
    
    // set initialization vector, at start of ciphertext...
    memcpy(ciphertext, [iv bytes], [iv length]);
    
    // encrypt user data, add to pointer after IV data
    status = CCCryptorUpdate(cryptor,
                             [plaintext bytes], [plaintext length],
                             ciphertext + length,
                             ciphertext_len - length,
                             &written);
    if (status != kCCSuccess)
    { return nil; }
    length += written;
    
    // encrypt plaintext checksum
    int8_t checksum = IMSChecksum(plaintext);
    CCCryptorUpdate(cryptor,
                    &checksum, sizeof(int8_t),
                    ciphertext + length,
                    ciphertext_len - length,
                    &written);
    length += written;
    
    // finalize
    status = CCCryptorFinal(cryptor,
                            ciphertext + length,
                            ciphertext_len - length,
                            &written);
    length += written;
    
    // release
    CCCryptorRelease(cryptor);
    
    // cleanup and return
    if (status == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:ciphertext length:length];
    }
    else {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error %d", __PRETTY_FUNCTION__, status);
    }
    
    return nil;
}



//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsSimpleDecryptData(NSData *ciphertext, NSData *key, NSData *iv) {
    if (ciphertext == 0 || key == 0 || iv == 0)
        return nil;
    
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    // determine total needed space
    size_t plaintext_len;
    CCCryptorStatus status;
    CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
            [key bytes], [key length],
            [ciphertext bytes],
            [ciphertext bytes] + kCCBlockSizeAES128, [ciphertext length] - kCCBlockSizeAES128,
            NULL, 0,
            &plaintext_len);
    
    // create buffer
    void *plaintext = malloc(32 + plaintext_len);
    if (plaintext == nil)
    { return nil; }
    
    // perform decryption
    status = CCCrypt(kCCDecrypt,
                     kCCAlgorithmAES128,
                     kCCOptionPKCS7Padding,
                     [key bytes],
                     [key length],
                     [iv bytes]/*[ciphertext bytes]*/, // iv
                     [ciphertext bytes] + kCCBlockSizeAES128,
                     [ciphertext length] - kCCBlockSizeAES128,
                     plaintext,
                     plaintext_len,
                     &plaintext_len);
    
    // cleanup and return
    if (status == kCCSuccess) {
        int8_t sum = IMSSum(plaintext, plaintext_len);
        NSData *data = [NSData dataWithBytesNoCopy:plaintext length:plaintext_len - 1];
        if (sum == 0) {
            // success
            return data;
        }
        else {
            NSLog(@"%s: Integrity check failed.", __PRETTY_FUNCTION__);
            return nil;
        }
    }
    else {
        free((__bridge void *)(ciphertext));
#ifdef DEBUG
        NSLog(@"%s: Unable to perform encryption. Error %d", __PRETTY_FUNCTION__, status);
#endif
    }
    
    return nil;
}


    
//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsEncryptData(NSData *plaintext, NSData *key) {
    if (plaintext == 0 || key == 0)
        return nil;
    
    
    // get initialization vector to pass to generalized function
    NSData *iv_data = IMSCryptoUtilsPseudoRandomData(kCCBlockSizeAES128);
    return IMSCryptoUtilsSimpleEncryptData(plaintext, key, iv_data);
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsDecryptData(NSData *ciphertext, NSData *key) {
    if (ciphertext == 0 || key == 0)
        return nil;
  
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    return IMSCryptoUtilsSimpleDecryptData(ciphertext, key, ciphertext);
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsEncryptPlistObject(id object, NSData *key) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSCryptoUtilsEncryptData(data, key);
}


//**********************
//**********************
//**
//**
id IMSCryptoUtilsDecryptPlistObject(NSData *data, NSData *key) {
    NSData *decrypted = IMSCryptoUtilsDecryptData(data, key);
    return IMSConvertDataToPlistObject(decrypted);
}


//**********************
//**********************
//**
//**
NSData *IMSHashData_MD5(NSData *data) {
    void *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5([data bytes], (unsigned int)[data length], buffer);
    return [NSData dataWithBytesNoCopy:buffer length:CC_MD5_DIGEST_LENGTH];
}

//**********************
//**********************
//**
//**
unsigned char *IMSHashBytes_MD5(void *obj, int len) {
    void *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5(obj, len, buffer);
    return buffer;
}


NSData *IMSHashPlistObject_MD5(id object) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSHashData_MD5(data);
}


//**********************
//**********************
//**
//**
NSData *IMSHashData_SHA256(NSData *data) {

    void *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([data bytes], (unsigned int)[data length], buffer);
    return [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH];
}

//**********************
//**********************
//**
//**
unsigned char *IMSHashBytes_SHA256(void *obj, int len) {
    void *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(obj, len, buffer);
    return buffer;
}

//**********************
//**********************
//**
//**
NSData *IMSHashPlistObject_SHA256(id object) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSHashData_SHA256(data);
}


//**********************
//**********************
//**
//**
NSData *IMSConvertPlistObjectToData(id object) {
    return [NSPropertyListSerialization
            dataWithPropertyList:object
            format:NSPropertyListBinaryFormat_v1_0
            options:0
            error:nil];
}


//**********************
//**********************
//**
//**
id IMSConvertDataToPlistObject(NSData *data) {
    return [NSPropertyListSerialization
            propertyListWithData:data
            options:0
            format:0
            error:nil];
}


/* Example Base64 test code
- (void)testZeroWrapWidth
{
    //set up data
    NSString *inputString = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    NSData *inputData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
    
    //encode
    NSString *encodedString = [inputData base64EncodedStringWithWrapWidth:0];
    
    //decode
    NSData *outputData = [NSData dataWithBase64EncodedString:encodedString];
    NSString *outputString = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
    NSAssert([outputString isEqualToString:inputString], @"WrappedInput test failed");
}
*/


//****************
//****************
//**
//**
NSString *IMSEncodeBase64(NSData *inputData) {
    //encode
    NSString *encodedString = [Base64 encodeBase64WithData:inputData];

    return encodedString;
}

//****************
//****************
//**
//**
NSData *IMSDeodeBase64(NSString *encodedString) {
    // decode
    NSData *outputData = [Base64 decodeBase64WithString:encodedString];

    return outputData;
}


