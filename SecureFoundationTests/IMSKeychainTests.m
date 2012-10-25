//
//  IMSKeychainTests.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/17/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "IMSKeychain.h"
#import "IMSCryptoUtils.h"

@interface IMSKeychainTests : SenTestCase

@end

@implementation IMSKeychainTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testKeychainContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    NSError *error;
    
    NSData *one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account error:&error];
    STAssertTrue(success, @"Password was not saved.\n%@", error);
    
    NSData *two = [IMSKeychain passwordDataForService:service account:account error:&error];
    STAssertTrue([two isEqualToData:one], @"Passwords were not equal.");
    
}

- (void)testDeletedKeychainItemContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    NSError *error;
    
    NSData *one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account error:&error];
    STAssertTrue(success, @"Password was not saved.\n%@", error);
    
    success = [IMSKeychain deletePasswordForService:service account:account error:&error];
    STAssertTrue(success, @"Password was not deleted.\n%@", error);
    
    NSData *two = [IMSKeychain passwordDataForService:service account:account error:&error];
    STAssertNil(two, @"No data should have been returned.");
    
}

- (void)testDeletingNonexistentKeychainItem {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    NSError *error;
    
    success = [IMSKeychain deletePasswordForService:service account:account error:&error];
    STAssertTrue(success, @"Password was not deleted.\n%@", error);
    
    success = [IMSKeychain deletePasswordForService:service account:account error:&error];
    STAssertTrue(success, @"Password was not deleted.\n%@", error);
    
}

- (void)testUpdatingKeychainItemContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    NSError *error;
    NSData *one;
    NSData *two;
    
    one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account error:&error];
    STAssertTrue(success, @"Password was not saved.\n%@", error);
    
    two = [IMSKeychain passwordDataForService:service account:account error:&error];
    STAssertTrue([two isEqualToData:one], @"Passwords were not equal.");
    
    one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account error:&error];
    STAssertTrue(success, @"Password was not saved.\n%@", error);
    
    two = [IMSKeychain passwordDataForService:service account:account error:&error];
    STAssertTrue([two isEqualToData:one], @"Passwords were not equal.");
    
}

@end
