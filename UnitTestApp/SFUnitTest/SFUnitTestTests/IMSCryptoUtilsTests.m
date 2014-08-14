//
//  CryptoUtilsTests.m
//  CryptoUtilsTests
//
//  Upated:
//     Gregg Ganley    Sep 2013
//
//  Created on 10/8/12.
//
//  Copyright (c) 2013 The MITRE Corporation. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import <SecureFoundation/SecureFoundation.h>

int8_t IMSSum(const void *bytes, size_t length);
int8_t IMSTwosComplement(int8_t value);
int8_t IMSChecksum(NSData *data);

@interface IMSCryptoUtilsTests : SenTestCase

@end

@implementation IMSCryptoUtilsTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testPseudoRandomDataLength {
    [@[ @0, @128, @256, @512 ] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        NSUInteger length = [obj unsignedIntegerValue];
        NSData *data = IMSCryptoUtilsPseudoRandomData(length);
        if (length) { STAssertNotNil(data, @"Resulting data is nil"); }
        else { STAssertNil(data, @"Resulting data is not nil"); }
        STAssertEquals([data length], length, @"Resulting data is the wrong length");
    }];
}

- (void)testPseudoRandomDataContents {
    static NSUInteger length = 1024;
    
    // get two sets of data
    NSData *one = IMSCryptoUtilsPseudoRandomData(length);
    NSData *two = IMSCryptoUtilsPseudoRandomData(length);
    
    // they should not be nil
    STAssertNotNil(one, @"Resulting data is nil");
    STAssertNotNil(two, @"Resulting data is nil");
    
    // they should not be equal
    STAssertFalse([one isEqualToData:two], @"Two random sets of data are equal");
    
}

- (void)testGeneratedKeyLength {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    NSLog(@"Gregg was here");
    [@[ @0, @128, @256, @512 ] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        NSUInteger length = [obj unsignedIntegerValue];
        NSData *data = IMSCryptoUtilsDeriveKey(key, length, salt);
        if (length) { STAssertNotNil(data, @"Resulting data is nil"); }
        else { STAssertNil(data, @"Resulting data is not nil"); }
        STAssertEquals([data length], length, @"Resulting data is the wrong length");
    }];
}

- (void)testGeneratedKeyContentsWithSameSalt {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    
    // get two generated keys
    NSData *one = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    NSData *two = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // they should not be nil
    STAssertNotNil(one, @"Resulting data is nil");
    STAssertNotNil(two, @"Resulting data is nil");
    
    // they should be equal
    STAssertTrue([one isEqualToData:two], @"Two derived keys of are not equal");
    
}

- (void)testGeneratedKeyContentsWithDifferentSalt {
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    
    // get key one
    NSData *saltOne = IMSCryptoUtilsPseudoRandomData(8);
    NSData *keyOne = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, saltOne);
    
    // get key two
    NSData *saltTwo = IMSCryptoUtilsPseudoRandomData(8);
    NSData *keyTwo = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, saltTwo);
    
    // they should not be equal
    STAssertFalse([keyOne isEqualToData:keyTwo], @"Two keys with different salts are equal");
    
}

- (void)testEncryptedDataContents {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // get some plain data
    NSData *plain = IMSCryptoUtilsPseudoRandomData(14);
    
    // encrypt then decrypt
    NSData *cipher = IMSCryptoUtilsEncryptData(plain, key);
    NSData *plainPrime = IMSCryptoUtilsDecryptData(cipher, key);
    
    // tests
    STAssertTrue([plain isEqualToData:plainPrime], @"The data should be equal");
    STAssertFalse([plain isEqualToData:cipher], @"The data should not be equal");
    
    
    //** TEST 2
    plain = IMSCryptoUtilsPseudoRandomData(1);
    cipher = IMSCryptoUtilsEncryptData(plain, key);
    plainPrime = IMSCryptoUtilsDecryptData(cipher, key);
    STAssertTrue([plain isEqualToData:plainPrime], @"The data should be equal");
    STAssertFalse([plain isEqualToData:cipher], @"The data should not be equal");
    
    //** TEST 3
    plain = IMSCryptoUtilsPseudoRandomData(250);
    cipher = IMSCryptoUtilsEncryptData(plain, key);
    plainPrime = IMSCryptoUtilsDecryptData(cipher, key);
    STAssertTrue([plain isEqualToData:plainPrime], @"The data should be equal");
    STAssertFalse([plain isEqualToData:cipher], @"The data should not be equal");
}

- (void)testFileEncryptionDecryption {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // copy file for testing
    NSString *fileName = @"fileCipherTest.txt"; // name of test file
    NSString *destPath = [NSString stringWithFormat:@"%@/%@",[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject],fileName];
    NSString *origPath = [NSString stringWithFormat:@"%@/%@", [[NSBundle mainBundle] resourcePath],fileName];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error = nil;
    if ([fileManager fileExistsAtPath:destPath]) { // TEMP - later, change to !exists, copy
        [fileManager removeItemAtPath:destPath error:&error];
    }
    [fileManager copyItemAtPath:origPath toPath:destPath error:&error];
    
    if(error)
        NSLog(@"ERROR: %@",error);
    STAssertNil(error, @"There was an error copying the test file");
    
    // test in-place encryption/decryption on the file copy (located at destPath)
    NSData *origData = [NSData dataWithContentsOfFile:destPath];
    int origSize = IMSCryptoUtilsEncryptFileToPath(destPath, nil, key);
    STAssertFalse([origData isEqualToData:[NSData dataWithContentsOfFile:destPath]], @"The encrypted file should not be equal to the original file");
    IMSCryptoUtilsDecryptFileToPath(origSize, destPath, nil, key);
    STAssertTrue([origData isEqualToData:[NSData dataWithContentsOfFile:destPath]], @"The decrypted file should be equal to the original file");
    
    // test encryption/decryption to/from a different file path
    [fileManager removeItemAtPath:destPath error:nil];
    error = nil;
    [fileManager copyItemAtPath:origPath toPath:destPath error:&error];
    if(error)
        NSLog(@"ERROR: %@",error);
    STAssertNil(error, @"There was an error copying the test file again");
    
    origData = [NSData dataWithContentsOfFile:destPath];
    NSString *encryptedDestPath = [NSString stringWithFormat:@"%@_encrypted.txt",destPath];
    origSize = IMSCryptoUtilsEncryptFileToPath(destPath, encryptedDestPath, key);
    STAssertFalse([origData isEqualToData:[NSData dataWithContentsOfFile:encryptedDestPath]], @"The encrypted file should not be equal to the original file");
    NSString *decryptedDestPath = [NSString stringWithFormat:@"%@_decrypted.txt",destPath];
    IMSCryptoUtilsDecryptFileToPath(origSize, encryptedDestPath, decryptedDestPath, key);
    STAssertTrue([origData isEqualToData:[NSData dataWithContentsOfFile:decryptedDestPath]], @"The decrypted file should be equal to the original file");
    
    [[NSFileManager defaultManager] removeItemAtPath:destPath error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:encryptedDestPath error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:decryptedDestPath error:nil];
}


- (void)testSimpleCipher {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // get some plain data
    NSData *plain = IMSCryptoUtilsPseudoRandomData(14);
    
    // encrypt then decrypt
    NSData *iv = IMSCryptoUtilsPseudoRandomData(kCCBlockSizeAES128);
    NSData *cipher = IMSCryptoUtilsSimpleEncryptData(plain, key, iv);
    NSData *plainPrime = IMSCryptoUtilsSimpleDecryptData(cipher, key, iv);
    
    // tests
    STAssertTrue([plain isEqualToData:plainPrime], @"The data should be equal");
    STAssertFalse([plain isEqualToData:cipher], @"The data should not be equal");
    
    //** TEST 2
    plain = IMSCryptoUtilsPseudoRandomData(1);
    cipher = IMSCryptoUtilsSimpleEncryptData(plain, key, iv);
    plainPrime = IMSCryptoUtilsSimpleDecryptData(cipher, key, iv);
    STAssertTrue([plain isEqualToData:plainPrime], @"The data should be equal");
    STAssertFalse([plain isEqualToData:cipher], @"The data should not be equal");
    
    //** TEST 3
    plain = IMSCryptoUtilsPseudoRandomData(250);
    cipher = IMSCryptoUtilsSimpleEncryptData(plain, key, iv);
    plainPrime = IMSCryptoUtilsSimpleDecryptData(cipher, key, iv);
    STAssertTrue([plain isEqualToData:plainPrime], @"The data should be equal");
    STAssertFalse([plain isEqualToData:cipher], @"The data should not be equal");
    
    //** TEST 4 - C_encrypt/decrypt
    int len = 50;
    u_int8_t *data = malloc(len);
    memset(data, 0x5a, len);
    void *cipherB = IMSCryptoUtilsC_EncryptData(data, len, [key bytes], [iv bytes]);
    NSData *cipherD = [NSData dataWithBytesNoCopy:cipherB length:len freeWhenDone:NO];
    
    u_int8_t *plainB  = IMSCryptoUtilsC_DecryptData(cipherB, len, [key bytes], [iv bytes]);
    NSData *plainD = [NSData dataWithBytesNoCopy:plainB length:50 freeWhenDone:NO];
    NSData *dataD  = [NSData dataWithBytesNoCopy:data   length:50 freeWhenDone:YES];
    STAssertTrue([dataD isEqualToData:plainD], @"The data should be equal");
    STAssertFalse([plainD isEqualToData:cipherD], @"The data should not be equal");
}


- (void)testTwosComplement {
    int8_t known = 0b11111101;
    int8_t comp = IMSTwosComplement(3);
    STAssertEquals(comp, known, @"Two's complement failed");
}

- (void)testBinarySum {
    for (NSUInteger i = 0; i < 100; i++) {
        NSData *data = IMSCryptoUtilsPseudoRandomData(102);
        int8_t one = IMSSum([data bytes], [data length]);
        int8_t two = IMSSum([data bytes], [data length]);
        STAssertEquals(one, two, @"The sums are not equal");
    }
}

- (void)testBinaryChecksum {
    for (NSUInteger i = 0; i < 100; i++) {
        NSData *data = IMSCryptoUtilsPseudoRandomData(102);
        int8_t one = IMSChecksum(data);
        int8_t two = IMSChecksum(data);
        STAssertEquals(one, two, @"The checksums are not equal");
    }
}

- (void)testEncryptedPlistDataContents {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    NSArray *names = @[ @"Bob", @"Lauren", @"Dave" ];
    NSData *encrypted = IMSCryptoUtilsEncryptPlistObject(names, key);
    NSArray *namesPrime = IMSCryptoUtilsDecryptPlistObject(encrypted, key);
    STAssertTrue([names isEqualToArray:namesPrime], @"The arrays are not equal");
}



- (void)testShaHASH {
    NSUInteger slen = CC_SHA256_DIGEST_LENGTH;

    NSData *data1 = IMSCryptoUtilsPseudoRandomData(60);
    NSData *data2 = IMSCryptoUtilsPseudoRandomData(95);
    NSData *hash1 = IMSHashData_SHA256(data1);
    NSData *hash2 = IMSHashData_SHA256(data2);
    unsigned char *buf2  = IMSHashBytes_SHA256([data2 bytes], [data2 length]);
    //printf("data1 is:\n");
    //BIO_dump_fp(stdout, [data1 bytes], [data1 length]);
    //printf("hash1 is:\n");
    //BIO_dump_fp(stdout, [hash1 bytes], [hash1 length]);
    
    STAssertFalse([hash1 isEqualToData:hash2], @"The SHA hashes should not be equal");
    NSData *hash2b = [NSData dataWithBytesNoCopy:buf2 length:slen];
    STAssertTrue([hash2 isEqualToData:hash2b], @"The SHA hashes should be equal");
    STAssertFalse([data1 isEqualToData:hash1], @"data and SHA hash should not be equal");
    STAssertFalse([data2 isEqualToData:hash2], @"data and SHA hash should not be equal");
    STAssertEquals([hash1 length], slen, @"SHA hash1 and digest length are not equal");
    STAssertEquals([hash2 length], slen, @"SHA hash2 and digest length are not equal");
    
}

- (void)testMD5HASH {
    NSUInteger slen = CC_MD5_DIGEST_LENGTH;

    NSData *data1 = IMSCryptoUtilsPseudoRandomData(60);
    NSData *data2 = IMSCryptoUtilsPseudoRandomData(88);
    NSData *hash1 = IMSHashData_MD5(data1);
    NSData *hash2 = IMSHashData_MD5(data2);
    unsigned char *buf2  = IMSHashBytes_MD5([data2 bytes], [data2 length]);


    //printf("data1 is:\n");
    //BIO_dump_fp(stdout, [data1 bytes], [data1 length]);
    //printf("hash1 is:\n");
    //BIO_dump_fp(stdout, [hash1 bytes], [hash1 length]);

    STAssertFalse([hash1 isEqualToData:hash2], @"The MD5 hashes should not be equal");
    NSData *hash2b = [NSData dataWithBytesNoCopy:buf2 length:slen];
    STAssertTrue([hash2 isEqualToData:hash2b], @"The SHA hashes should be equal");
    STAssertFalse([data1 isEqualToData:hash1], @"data and MD5 hash should not be equal");
    STAssertFalse([data2 isEqualToData:hash2], @"data and MD5 hash should not be equal");
    STAssertEquals([hash1 length], slen, @"MD5 hash1 length are not equal");
    STAssertEquals([hash2 length], slen, @"MD5 hash2 length are not equal");
    
}

- (void)testBase64 {
    
    //NSString *str = [[NSString alloc] initWithFormat:@"Four hundred ninety five svsdfsdfsdf"];
    NSString *str = [[NSString alloc] initWithFormat:@"Four hundred ninety five svsdfsdfsdf ds$#QAGDAA gawtvq;hagawcl b85vaug sdfsdf agagdsfgsrtergegsergregagteshsyjdytk"];
    NSLog(@"str len: %d", [str length]);
    NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
    //**
    NSString *str_enc = IMSEncodeBase64(data);
    
    NSData *data2 = IMSDeodeBase64(str_enc);
    STAssertTrue([data isEqualToData:data2], @"the data should be equal");
    //** convert data to str and compare to orig
    NSString *str2 = [[NSString alloc] initWithData:data2 encoding:NSUTF8StringEncoding];
    STAssertTrue([str isEqualToString:str2], @"the strings should be equal");
    STAssertEquals([str length], [str2 length], nil);
}

@end
