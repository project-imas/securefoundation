//
//  IMSCryptoManager.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/18/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"
#import "IMSKeyConst.h"
// constants
static NSString * const IMSCryptoManagerKeychainService = @"org.mitre.imas.crypto-manager";
static NSString * const IMSCryptoManagerSharedKeyPasscodeAccount = @"shared-key.passcode";
static NSString * const IMSCryptoManagerSharedKeySecurityAnswersAccount = @"shared-key.security-answers";
static NSString * const IMSCryptoManagerSecurityQuestionsAccount = @"security-questions";
static NSString * const IMSCryptoManagerSaltAccount = @"salt";
static const int IMSCryptoManagerSecurityQuestionsXORKey = 156;

// temporary memory storage
static NSDictionary *IMSCryptoManagerSharedKey;
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
    NSData *key  = IMSCryptoUtilsPseudoRandomData(kCCKeySizeAES256);
    NSData *salt = IMSCryptoManagerSalt();
    
    IMSCryptoManagerSharedKey = IMSCryptoUtilsDeriveKey( key
                                                       , salt);
    
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

        NSData       *key;
        NSData       *salt;
        NSDictionary *dkey;
        NSData       *encryptedKey;

        key  = [passcode dataUsingEncoding:NSUTF8StringEncoding];
        salt = IMSCryptoManagerSalt();
        dkey = IMSCryptoUtilsDeriveKey(key, salt);
        
        NSData *k    = IMSCryptoManagerSharedKey[kOBJ1];
        
        encryptedKey = IMSCryptoUtilsEncryptData( k, dkey );
        
//        success = [IMSKeychain
//                   setPasswordData:encryptedKey
//                        forService:IMSCryptoManagerKeychainService
//                           account:IMSCryptoManagerSharedKeyPasscodeAccount];
        success = [IMSKeychain
                   setPasswordDictionary:dkey
                   forService:IMSCryptoManagerKeychainService
                   account:IMSCryptoManagerSharedKeyPasscodeAccount];

    }
    return success;
}

BOOL IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(  NSArray *questions
                                                       , NSArray *answers) {
    
    NSCParameterAssert(!IMSCryptoManagerIsLocked());
    BOOL success = NO;
    
    if (!IMSCryptoManagerIsLocked()
    &&   questions != nil
    &&   answers   != nil) {
        
        //----------------------------------------------------------------------
        // answers
        //----------------------------------------------------------------------
        NSData       *key;
        NSData       *salt;
        NSDictionary *dkey;
        NSData       *encryptedKey;
        NSString     *answersString;
        BOOL          answersSet;

        answersString = [answers componentsJoinedByString:@""];
        
        key           = [answersString dataUsingEncoding:NSUTF8StringEncoding];
        salt          = IMSCryptoManagerSalt();
        dkey          = IMSCryptoUtilsDeriveKey(key, salt);
        
        NSData *k     = IMSCryptoManagerSharedKey[kOBJ1];
        
        encryptedKey  = IMSCryptoUtilsEncryptData( k, dkey );
        
        answersSet    = [IMSKeychain
                         setPasswordData:encryptedKey
                         forService:IMSCryptoManagerKeychainService
                       account:IMSCryptoManagerSharedKeySecurityAnswersAccount];
        
        //----------------------------------------------------------------------
        // questions
        //----------------------------------------------------------------------
        NSMutableData *questionsData;
        NSUInteger     length;
        char          *bytes;
        BOOL           questionsSet;

        questionsData = [[NSJSONSerialization dataWithJSONObject:questions
                                                         options:0
                                                           error:nil]
                         mutableCopy];
        
        length        = [questionsData length];
        bytes         = [questionsData mutableBytes];
        
        IMSXOR(IMSCryptoManagerSecurityQuestionsXORKey, bytes, length);
        
        questionsSet  = [IMSKeychain
                          setPasswordData:questionsData
                          forService:IMSCryptoManagerKeychainService
                          account:IMSCryptoManagerSecurityQuestionsAccount];
        //----------------------------------------------------------------------
        // save
        //----------------------------------------------------------------------
        success = (questionsSet && answersSet);
    }
    return success;
}

BOOL IMSCryptoManagerUnlockWithPasscode(NSString *passcode) {
    NSCParameterAssert(passcode != nil);
    
    NSData       *key;
    NSData       *salt;
    NSDictionary *dkey;
    NSDictionary *encryptedKey;

    // get encrypted key
    encryptedKey = [IMSKeychain
                    passwordDictionaryForService:IMSCryptoManagerKeychainService
                    account:IMSCryptoManagerSharedKeyPasscodeAccount];
    
    // generate decryption key
    key          = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    salt         = IMSCryptoManagerSalt();
    dkey         = IMSCryptoUtilsDeriveKey(key, salt);
    
    // perform decryption
    NSData *k    = IMSCryptoUtilsDecryptData(encryptedKey[kOBJ1], dkey);
    NSData *iv   = IMSCryptoUtilsDecryptData(encryptedKey[kOBJ2], dkey);

    if ( k && iv ) {
    
        IMSCryptoManagerSharedKey = @{kOBJ1 : k, kOBJ2 : iv};
        
    } else {
        
        IMSCryptoManagerSharedKey = nil;
    }
    // return
    return !IMSCryptoManagerIsLocked();
}

BOOL IMSCryptoManagerUnlockWithAnswersForSecurityQuestions(NSArray *answers) {
    NSCParameterAssert(answers != nil);
    
    NSData       *key;
    NSData       *salt;
    NSDictionary *dkey;
    NSDictionary *encryptedKey;
    NSString     *answersString;
    
    // get encrypted key
    encryptedKey  = [IMSKeychain
                    passwordDictionaryForService:IMSCryptoManagerKeychainService
                    account:IMSCryptoManagerSharedKeySecurityAnswersAccount];
    
    // generate decryption key
    answersString = [answers componentsJoinedByString:@""];
    key           = [answersString dataUsingEncoding:NSUTF8StringEncoding];
    salt          = IMSCryptoManagerSalt();
    dkey          = IMSCryptoUtilsDeriveKey(key, salt);
    
    // perform decryption
    NSData *k    = IMSCryptoUtilsDecryptData(encryptedKey[kOBJ1],  dkey);
    NSData *iv   = IMSCryptoUtilsDecryptData(encryptedKey[kOBJ2], dkey);
    
    if ( k && iv ) {
        
        IMSCryptoManagerSharedKey = @{kOBJ1 : k, kOBJ2 : iv};
        
    } else {
        
        IMSCryptoManagerSharedKey = nil;
    }
    
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
    
    if ( length )
    
        return [NSJSONSerialization JSONObjectWithData:questions
                                               options:0
                                                 error:nil];
    else
        
        return nil;
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
