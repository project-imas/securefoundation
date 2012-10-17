//
//  CryptoUtilsTests.m
//  CryptoUtilsTests
//
//  Created by Caleb Davenport on 10/8/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "IMSCryptoUtils.h"

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
        NSData *data = IMSPseudoRandomData(length);
        if (length) { STAssertNotNil(data, @"Resulting data is nil"); }
        else { STAssertNil(data, @"Resulting data is not nil"); }
        STAssertEquals([data length], length, @"Resulting data is the wrong length");
    }];
}

- (void)testPseudoRandomDataContents {
    static NSUInteger length = 1024;
    
    // get two sets of data
    NSData *one = IMSPseudoRandomData(length);
    NSData *two = IMSPseudoRandomData(length);
    
    // they should not be nil
    STAssertNotNil(one, @"Resulting data is nil");
    STAssertNotNil(two, @"Resulting data is nil");
    
    // they should not be equal
    STAssertFalse([one isEqualToData:two], @"Two random sets of data are equal");
    
}

- (void)testGeneratedKeyLength {
    static NSString *key = @"key";
    NSData *salt = IMSPseudoRandomData(256);
    [@[ @0, @128, @256, @512 ] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        NSUInteger length = [obj unsignedIntegerValue];
        NSData *data = IMSDeriveKey(key, length, salt);
        if (length) { STAssertNotNil(data, @"Resulting data is nil"); }
        else { STAssertNil(data, @"Resulting data is not nil"); }
        STAssertEquals([data length], length, @"Resulting data is the wrong length");
    }];
}

- (void)testGeneratedKeyContentsWithSameSalt {
    static NSString *key = @"key";
    static NSUInteger length = 1024;
    NSData *salt = IMSPseudoRandomData(256);
    
    // get two generated keys
    NSData *one = IMSDeriveKey(key, length, salt);
    NSData *two = IMSDeriveKey(key, length, salt);
    
    // they should not be nil
    STAssertNotNil(one, @"Resulting data is nil");
    STAssertNotNil(two, @"Resulting data is nil");
    
    // they should be equal
    STAssertTrue([one isEqualToData:two], @"Two derived keys of are not equal");
    
}

- (void)testGeneratedKeyContentsWithDifferentSalt {
    static NSString *key = @"key";
    static NSUInteger length = 1024;
    
    // get key one
    NSData *saltOne = IMSPseudoRandomData(256);
    NSData *keyOne = IMSDeriveKey(key, length, saltOne);
    
    // get key two
    NSData *saltTwo = IMSPseudoRandomData(256);
    NSData *keyTwo = IMSDeriveKey(key, length, saltTwo);
    
    // they should not be equal
    STAssertFalse([keyOne isEqualToData:keyTwo], @"Two keys with different salts are equal");
    
}

- (void)testEncryptedDataContents {
    static NSString *key = @"key";
    NSData *salt = IMSPseudoRandomData(256);
    
    // get some plain data
    NSData *plain = IMSPseudoRandomData(5);
    
    // encrypt then decrypt
    NSData *cipher = IMSEncryptData(plain, key, salt);
    NSData *plainPrime = IMSDecryptData(cipher, key, salt);
    
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
        NSData *data = IMSPseudoRandomData(102);
        int8_t one = IMSSum([data bytes], [data length]);
        int8_t two = IMSSum([data bytes], [data length]);
        STAssertEquals(one, two, @"The sums are not equal");
    }
}

- (void)testBinaryChecksum {
    for (NSUInteger i = 0; i < 100; i++) {
        NSData *data = IMSPseudoRandomData(102);
        int8_t one = IMSChecksum(data);
        int8_t two = IMSChecksum(data);
        STAssertEquals(one, two, @"The checksums are not equal");
    }
}

- (void)testEncrtypedPlistDataContents {
    static NSString *key = @"key";
    NSArray *names = @[ @"Bob", @"Lauren", @"Dave" ];
    NSData *salt = IMSPseudoRandomData(128);
    NSData *encrypted = IMSEncryptPlistObjectWithKey(names, key, salt);
    NSArray *namesPrime = IMSDecryptPlistObjectWithKey(encrypted, key, salt);
    STAssertTrue([names isEqualToArray:namesPrime], @"The arrays are not equal");
}

@end
