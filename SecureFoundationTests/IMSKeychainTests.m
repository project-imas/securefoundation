//
//  IMSKeychainTests.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/17/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "SecureFoundation.h"

@interface IMSKeychain (TestExtensions)

+ (NSURL *)URLForKeychainFile;

@end

@interface IMSKeychainTests : SenTestCase

@end

@implementation IMSKeychainTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [IMSKeychain synchronize];
    NSURL *URL = [IMSKeychain URLForKeychainFile];
    [[NSFileManager defaultManager] removeItemAtURL:URL error:nil];
    [super tearDown];
}

- (void)testKeychainContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    
    NSData *one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account];
    STAssertTrue(success, @"Password was not saved.");
    
    NSData *two = [IMSKeychain passwordDataForService:service account:account];
    STAssertTrue([two isEqualToData:one], @"Passwords were not equal.");
    
}

- (void)testDeletedKeychainItemContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    
    NSData *one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account];
    STAssertTrue(success, @"Password was not saved.");
    
    success = [IMSKeychain deletePasswordForService:service account:account];
    STAssertTrue(success, @"Password was not deleted.");
    
    NSData *two = [IMSKeychain passwordDataForService:service account:account];
    STAssertNil(two, @"No data should have been returned.");
    
}

- (void)testDeletingNonexistentKeychainItem {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    
    success = [IMSKeychain deletePasswordForService:service account:account];
    STAssertTrue(success, @"Password was not deleted.");
    
    success = [IMSKeychain deletePasswordForService:service account:account];
    STAssertTrue(success, @"Password was not deleted.");
    
}

- (void)testUpdatingKeychainItemContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    BOOL success;
    NSData *one;
    NSData *two;
    
    one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account];
    STAssertTrue(success, @"Password was not saved.");
    
    two = [IMSKeychain passwordDataForService:service account:account];
    STAssertTrue([two isEqualToData:one], @"Passwords were not equal.");
    
    one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setPasswordData:one forService:service account:account];
    STAssertTrue(success, @"Password was not saved.");
    
    two = [IMSKeychain passwordDataForService:service account:account];
    STAssertTrue([two isEqualToData:one], @"Passwords were not equal.");
    
}

- (void)testEncryptedKeychainItemContents {
    static NSString * const service = @"service";
    static NSString * const account = @"account";
    static NSString * const passcode = @"1234";
    NSArray *questions = @[ @"question" ];
    NSArray *answers = @[ @"answer" ];
    BOOL success;
    NSData *one;
    NSData *two;
    
    IMSCryptoManagerStoreTP(passcode);
    IMSCryptoManagerStoreTSQAnswers(questions, answers);
    IMSCryptoManagerFinalize();
    
    IMSCryptoManagerPurge();
    IMSCryptoManagerUnlockWithPasscode(passcode);
    
    one = IMSCryptoUtilsPseudoRandomData(54);
    success = [IMSKeychain setSecurePasswordData:one forService:service account:account];
    STAssertTrue(success, @"Password was not saved.");
    
    two = [IMSKeychain passwordDataForService:service account:account];
    STAssertFalse([two isEqualToData:one], @"Passwords should not be equal.");
    
    two = [IMSKeychain securePasswordDataForService:service account:account];
    STAssertTrue([two isEqualToData:one], @"Passwords should be equal.");
    
}

@end
