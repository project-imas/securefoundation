//
//  IMSCryptoUtils.m
//  CryptoUtils
//
//  Created by Caleb Davenport on 10/8/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"
#import "Base64.h"

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


