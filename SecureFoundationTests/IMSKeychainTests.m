//
//  IMSKeychainTests.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/17/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "SecureFoundation.h"

@interface IMSKeychainTests : SenTestCase

@end

@implementation IMSKeychainTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    
    [IMSKeychain synchronize];
    
    static NSURL *URL;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        NSFileManager *manager = [NSFileManager defaultManager];
        URL = [[manager
                URLsForDirectory:NSLibraryDirectory
                inDomains:NSUserDomainMask]
               objectAtIndex:0];
        URL = [URL URLByAppendingPathComponent:@".imskeychain"];
    });
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
    
    IMSCryptoManagerStoreTemporaryPasscode(passcode);
    IMSCryptoManagerStoreTemporarySecurityQuestionsAndAnswers(questions, answers); 
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
