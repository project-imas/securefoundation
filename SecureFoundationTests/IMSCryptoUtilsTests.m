//
//  CryptoUtilsTests.m
//  CryptoUtilsTests
//
//  Created by Caleb Davenport on 10/8/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "SecureFoundation.h"

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

- (void)testEncrtypedPlistDataContents {
    NSData *salt = IMSCryptoUtilsPseudoRandomData(8);
    NSData *key = IMSCryptoUtilsPseudoRandomData(8);
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    NSArray *names = @[ @"Bob", @"Lauren", @"Dave" ];
    NSData *encrypted = IMSCryptoUtilsEncryptPlistObject(names, key);
    NSArray *namesPrime = IMSCryptoUtilsDecryptPlistObject(encrypted, key);
    STAssertTrue([names isEqualToArray:namesPrime], @"The arrays are not equal");
}

@end
