//
//  IMSCryptoManager.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/18/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <CommonCrypto/CommonCrypto.h>

#import "IMSCryptoManager.h"
#import "IMSCryptoUtils.h"
#import "IMSKeychain.h"

// constants
static NSString * const IMSCryptoManagerKeychainService = @"org.mitre.imas.crypt-manager";
static NSString * const IMSCryptoManagerSharedKeyPasscodeAccount = @"shared-key.passcode";
static NSString * const IMSCryptoManagerSharedKeySecurityAnswersAccount = @"shared-key.security-answers";
static NSString * const IMSCryptoManagerSecurityQuestionsAccount = @"security-questions";
static NSString * const IMSCryptoManagerSaltAccount = @"salt";
static const int IMSCryptoManagerSecurityQuestionsXORKey = 156;

// temporary memory storage
static NSData *IMSCryptoManagerSharedKey;
static NSString *IMSCryptoManagerTemporaryPasscode;
static NSArray *IMSCryptoManagerTemporarySecurityQuestions;
static NSArray *IMSCryptoManagerTemporarySecurityAnswers;

NSData *IMSCryptoManagerSalt(void) {
    static NSData *salt;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        salt = [IMSKeychain
                passwordDataForService:IMSCryptoManagerKeychainService
                account:IMSCryptoManagerSaltAccount
                error:nil];
        if (salt == nil) {
            salt = IMSCryptoUtilsPseudoRandomData(kCCKeySizeAES256);
            [IMSKeychain
             setPasswordData:salt
             forService:IMSCryptoManagerKeychainService
             account:IMSCryptoManagerSaltAccount
             error:nil];
        }
    });
    return salt;
}

NSData *IMSCryptoManagerDecryptData(NSData *data) {
    return IMSCryptoUtilsEncryptData(data, IMSCryptoManagerSharedKey);
}

NSData *IMSCryptoManagerEncryptData(NSData *data) {
    return IMSCryptoUtilsDecryptData(data, IMSCryptoManagerSharedKey);
}

void IMSCryptoManagerPurge(void) {
    IMSCryptoManagerSharedKey = nil;
}

void IMSCryptoManagerStoreTemporaryPasscode(NSString *code) {
    IMSCryptoManagerTemporaryPasscode = code;
}

void IMSCryptoManagerStoreTemporarySecurityQuestionsAndAnswers(NSArray *questions, NSArray *answers) {
    IMSCryptoManagerTemporarySecurityQuestions = questions;
    IMSCryptoManagerTemporarySecurityAnswers = answers;
}

void IMSCryptoManagerFinalize(void) {
    
    // generate a new key
    NSData *key = IMSCryptoUtilsPseudoRandomData(kCCKeySizeAES256);
    NSData *salt = IMSCryptoManagerSalt();
    IMSCryptoManagerSharedKey = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // store things
    IMSCryptoManagerUpdatePasscode(IMSCryptoManagerTemporaryPasscode);
    IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(IMSCryptoManagerTemporarySecurityQuestions,
                                                      IMSCryptoManagerTemporarySecurityAnswers);
    
    // clear memory
    IMSCryptoManagerTemporaryPasscode = nil;
    IMSCryptoManagerTemporarySecurityQuestions = nil;
    IMSCryptoManagerTemporarySecurityAnswers = nil;
    
}

void IMSCryptoManagerUpdatePasscode(NSString *passcode) {
    NSCParameterAssert(passcode != nil);
    NSCAssert(!IMSCryptoManagerIsLocked(), @"The application must be unlocked.");
    if (!IMSCryptoManagerIsLocked()) {
        NSData *key = [passcode dataUsingEncoding:NSUTF8StringEncoding];
        NSData *salt = IMSCryptoManagerSalt();
        key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
        NSData *encryptedKey = IMSCryptoUtilsEncryptData(IMSCryptoManagerSharedKey, key);
        [IMSKeychain
         setPasswordData:encryptedKey
         forService:IMSCryptoManagerKeychainService
         account:IMSCryptoManagerSharedKeyPasscodeAccount
         error:nil];
    }
}

void IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(NSArray *questions, NSArray *answers) {
    NSCParameterAssert(questions != nil);
    NSCParameterAssert(answers != nil);
    NSCAssert(!IMSCryptoManagerIsLocked(), @"The application must be unlocked.");
    if (!IMSCryptoManagerIsLocked()) {
        
        // answers
        NSString *answersString = [answers componentsJoinedByString:@""];
        NSData *key = [answersString dataUsingEncoding:NSUTF8StringEncoding];
        NSData *salt = IMSCryptoManagerSalt();
        key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
        NSData *encryptedKey = IMSCryptoUtilsEncryptData(IMSCryptoManagerSharedKey, key);
        [IMSKeychain
         setPasswordData:encryptedKey
         forService:IMSCryptoManagerKeychainService
         account:IMSCryptoManagerSharedKeyPasscodeAccount
         error:nil];
        
        // questions
        NSMutableData *questionsData = [[NSJSONSerialization dataWithJSONObject:questions options:0 error:nil] mutableCopy];
        NSUInteger length = [questionsData length];
        char *bytes = [questionsData mutableBytes];
        IMSXOR(IMSCryptoManagerSecurityQuestionsXORKey, bytes, length);
        [IMSKeychain
         setPasswordData:questionsData
         forService:IMSCryptoManagerKeychainService
         account:IMSCryptoManagerSecurityQuestionsAccount
         error:nil];
        
    }
}

BOOL IMSCryptoManagerUnlockWithPasscode(NSString *passcode) {
    NSCParameterAssert(passcode != nil);
    
    // get encrypted key
    NSData *encryptedKey = [IMSKeychain
                            passwordDataForService:IMSCryptoManagerKeychainService
                            account:IMSCryptoManagerSharedKeyPasscodeAccount
                            error:nil];
    
    // generate decryption key
    NSData *key = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt = IMSCryptoManagerSalt();
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // perform decryption
    IMSCryptoManagerSharedKey = IMSCryptoUtilsDecryptData(encryptedKey, key);
    
    // return
    return !IMSCryptoManagerIsLocked();
    
}

BOOL IMSCryptoManagerUnlockWithAnswersForSecurityQuestions(NSArray *answers) {
    NSCParameterAssert(answers != nil);
    
    // get encrypted key
    NSData *encryptedKey = [IMSKeychain
                            passwordDataForService:IMSCryptoManagerKeychainService
                            account:IMSCryptoManagerSharedKeySecurityAnswersAccount
                            error:nil];
    
    // generate decryption key
    NSString *answersString = [answers componentsJoinedByString:@""];
    NSData *key = [answersString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt = IMSCryptoManagerSalt();
    key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
    
    // perform decryption
    IMSCryptoManagerSharedKey = IMSCryptoUtilsDecryptData(encryptedKey, key);
    
    // return
    return !IMSCryptoManagerIsLocked();
    
}

BOOL IMSCryptoManagerIsLocked(void) {
    return (IMSCryptoManagerSharedKey == nil);
}

NSArray *IMSCryptoManagerSecurityQuestions(void) {
    NSMutableData *questions = [[IMSKeychain
                                 passwordDataForService:IMSCryptoManagerKeychainService
                                 account:IMSCryptoManagerSharedKeySecurityAnswersAccount
                                 error:nil]
                                mutableCopy];
    NSUInteger length = [questions length];
    char *bytes = [questions mutableBytes];
    IMSXOR(IMSCryptoManagerSecurityQuestionsXORKey, bytes, length);
    return [NSJSONSerialization JSONObjectWithData:questions options:0 error:nil];
}

BOOL IMSCryptoManagerHasPasscode(void) {
    NSData *data = [IMSKeychain
                    passwordDataForService:IMSCryptoManagerKeychainService
                    account:IMSCryptoManagerSharedKeyPasscodeAccount
                    error:nil];
    return (data != nil);
}

BOOL IMCryptoManagerHasSecurityQuestions(void) {
    NSData *questions = [IMSKeychain
                         passwordDataForService:IMSCryptoManagerKeychainService
                         account:IMSCryptoManagerSecurityQuestionsAccount
                         error:nil];
    NSData *answers = [IMSKeychain
                       passwordDataForService:IMSCryptoManagerKeychainService
                       account:IMSCryptoManagerSharedKeySecurityAnswersAccount
                       error:nil];
    return (answers != nil && questions != nil);
}
