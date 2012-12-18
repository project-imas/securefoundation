//
//  IMSCryptoManager.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/18/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"

// constants
static NSString * const IMSCryptoManagerKeychainService = @"org.mitre.imas.crypto-manager";
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
                account:IMSCryptoManagerSaltAccount];
        if (salt == nil) {
            salt = IMSCryptoUtilsPseudoRandomData(kCCKeySizeAES256);
            [IMSKeychain
             setPasswordData:salt
             forService:IMSCryptoManagerKeychainService
             account:IMSCryptoManagerSaltAccount];
        }
    });
    return salt;
}

NSData *IMSCryptoManagerDecryptData(NSData *data) {
    return IMSCryptoUtilsDecryptData(data, IMSCryptoManagerSharedKey);
}

NSData *IMSCryptoManagerEncryptData(NSData *data) {
    return IMSCryptoUtilsEncryptData(data, IMSCryptoManagerSharedKey);
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
    
    // check state
    if (IMSCryptoManagerHasPasscode() ||
        IMSCryptoManagerHasSecurityQuestionsAndAnswers() ||
        !IMSCryptoManagerIsLocked()) {
        return;
    }
    
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

BOOL IMSCryptoManagerUpdatePasscode(NSString *passcode) {
    NSCParameterAssert(!IMSCryptoManagerIsLocked());
    BOOL success = NO;
    if (!IMSCryptoManagerIsLocked() && passcode != nil) {
        NSData *key = [passcode dataUsingEncoding:NSUTF8StringEncoding];
        NSData *salt = IMSCryptoManagerSalt();
        key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
        NSData *encryptedKey = IMSCryptoUtilsEncryptData(IMSCryptoManagerSharedKey, key);
        success = [IMSKeychain
                   setPasswordData:encryptedKey
                   forService:IMSCryptoManagerKeychainService
                   account:IMSCryptoManagerSharedKeyPasscodeAccount];
    }
    return success;
}

BOOL IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(NSArray *questions, NSArray *answers) {
    NSCParameterAssert(!IMSCryptoManagerIsLocked());
    BOOL success = NO;
    if (!IMSCryptoManagerIsLocked() && questions != nil && answers != nil) {
        
        // answers
        NSString *answersString = [answers componentsJoinedByString:@""];
        NSData *key = [answersString dataUsingEncoding:NSUTF8StringEncoding];
        NSData *salt = IMSCryptoManagerSalt();
        key = IMSCryptoUtilsDeriveKey(key, kCCKeySizeAES256, salt);
        NSData *encryptedKey = IMSCryptoUtilsEncryptData(IMSCryptoManagerSharedKey, key);
        BOOL answersSet = [IMSKeychain
                           setPasswordData:encryptedKey
                           forService:IMSCryptoManagerKeychainService
                           account:IMSCryptoManagerSharedKeySecurityAnswersAccount];
        
        // questions
        NSMutableData *questionsData = [[NSJSONSerialization dataWithJSONObject:questions options:0 error:nil] mutableCopy];
        NSUInteger length = [questionsData length];
        char *bytes = [questionsData mutableBytes];
        IMSXOR(IMSCryptoManagerSecurityQuestionsXORKey, bytes, length);
        BOOL questionsSet = [IMSKeychain
                             setPasswordData:questionsData
                             forService:IMSCryptoManagerKeychainService
                             account:IMSCryptoManagerSecurityQuestionsAccount];
        
        // save
        success = (questionsSet && answersSet);
        
    }
    return success;
}

BOOL IMSCryptoManagerUnlockWithPasscode(NSString *passcode) {
    NSCParameterAssert(passcode != nil);
    
    // get encrypted key
    NSData *encryptedKey = [IMSKeychain
                            passwordDataForService:IMSCryptoManagerKeychainService
                            account:IMSCryptoManagerSharedKeyPasscodeAccount];
    
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
                            account:IMSCryptoManagerSharedKeySecurityAnswersAccount];
    
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
                                 account:IMSCryptoManagerSecurityQuestionsAccount]
                                mutableCopy];
    NSUInteger length = [questions length];
    char *bytes = [questions mutableBytes];
    IMSXOR(IMSCryptoManagerSecurityQuestionsXORKey, bytes, length);
    return [NSJSONSerialization JSONObjectWithData:questions options:0 error:nil];
}

BOOL IMSCryptoManagerHasPasscode(void) {
    NSData *data = [IMSKeychain
                    passwordDataForService:IMSCryptoManagerKeychainService
                    account:IMSCryptoManagerSharedKeyPasscodeAccount];
    return (data != nil);
}

BOOL IMSCryptoManagerHasSecurityQuestionsAndAnswers(void) {
    NSData *questions = [IMSKeychain
                         passwordDataForService:IMSCryptoManagerKeychainService
                         account:IMSCryptoManagerSecurityQuestionsAccount];
    NSData *answers = [IMSKeychain
                       passwordDataForService:IMSCryptoManagerKeychainService
                       account:IMSCryptoManagerSharedKeySecurityAnswersAccount];
    return (answers != nil && questions != nil);
}
