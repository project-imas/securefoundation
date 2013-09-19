//
//  IMSCryptoManager.m
//  SecureFoundation
//
//  Upated:
//     Gregg Ganley    Sep 2013
//     Gregg Ganley    June 2013
//     Kevin O'Keefe   Apr 2013
//
//  Created on 10/18/12.
//  Copyright (c) 2012, 2013 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"

// constants
static NSString * const IMSCryptoManagerKeychainService = @"org.mitre.imas.crypto-manager";
static NSString * const IMSCryptoManagerSharedKeyPasscodeAccount = @"shared-key.passcode";
static NSString * const IMSCryptoManagerSharedKeySecurityAnswersAccount = @"shared-key.security-answers";
static NSString * const IMSCryptoManagerSecurityQuestionsAccount = @"security-questions";
//** storage of generic item, could be a key to database or API key etc
static NSString * const IMSCryptoManagerGenItemAccount = @"gen-item";
static NSString * const IMSCryptoManagerGenItemKAccount = @"gen-itemk";
static NSString * const IMSCryptoManagerSaltAccount = @"salt";
static const int IMSCryptoManagerSecurityQuestionsXORKey = 156;

// temporary memory storage
static NSData   *IMSCryptoManagerSharedKey;
//** renamed for obfuscation pruposes
//*  IMSCryptoManagerTemporaryPasscode
static NSString *IMSCryptoManagerTP;
//** TemporarySecurityQuestions
static NSArray  *IMSCryptoManagerTSQ;
//** TemporarySecurityAnswers
static NSArray  *IMSCryptoManagerTSA;


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

//** only called during initial passcode creation and no other times
//** store temp password
void IMSCryptoManagerStoreTP(NSString *code) {
   
    IMSCryptoManagerTP = code;
}

//** store temp questions and answers
void IMSCryptoManagerStoreTSQA(NSArray *questions, NSArray *answers) {

    IMSCryptoManagerTSQ = questions;
    IMSCryptoManagerTSA = answers;
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
    IMSCryptoManagerUpdatePasscode(IMSCryptoManagerTP);
    IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(IMSCryptoManagerTSQ,
                                                      IMSCryptoManagerTSA);
    
    // clear memory
    IMSCryptoManagerTP  = nil;
    IMSCryptoManagerTSQ = nil;
    IMSCryptoManagerTSA = nil;
    
}

NSString *IMSCryptoManagerGenItemCreate(NSArray *answers, int len) {
    NSCParameterAssert(IMSCryptoManagerTP != nil);
    
    if (len <= 0 || answers == nil)
        return nil;
    
    //** generate this string, encode, encrypt, store it, and return it
    NSString *genItem = IMSGenerateRandomString(len);
    NSData *dbk = [genItem dataUsingEncoding:NSUTF8StringEncoding];
    
    // secure gen item with answers
    NSString *answersString = [answers componentsJoinedByString:@""];
    NSData *akey = [answersString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt = IMSCryptoManagerSalt();
    NSData *adk = IMSCryptoUtilsDeriveKey(akey, kCCKeySizeAES256, salt);
    //** encrypt dbk item with adk, returns encrypted cipher text to store on keychain
    NSData *encryptedCT = IMSCryptoUtilsEncryptData(dbk, adk);
    BOOL genItemSet = [IMSKeychain
                       setPasswordData:encryptedCT
                       forService:IMSCryptoManagerKeychainService
                       account:IMSCryptoManagerGenItemAccount];

    //** secure answers key with user password
    NSData *passcodeD = [IMSCryptoManagerTP dataUsingEncoding:NSUTF8StringEncoding];
    NSData *pak = IMSCryptoUtilsDeriveKey(passcodeD, kCCKeySizeAES256, salt);
    //** encrypt abk item with upasswd, returns encrypted cipher text to store on keychain
    encryptedCT = IMSCryptoUtilsEncryptData(adk, pak);
    BOOL genItemKSet = [IMSKeychain
                        setPasswordData:encryptedCT
                        forService:IMSCryptoManagerKeychainService
                        account:IMSCryptoManagerGenItemKAccount];
    
    if (genItemSet == YES && genItemKSet == YES)
        return genItem;
    
    return nil;
}

NSString *IMSCryptoManagerGenItemGet(NSString *passcode) {
    NSCParameterAssert(passcode != nil);
    NSCParameterAssert(!IMSCryptoManagerIsLocked());
    
    // get encrypted key
    NSData *encryptedCT = [IMSKeychain
                           passwordDataForService:IMSCryptoManagerKeychainService
                           account:IMSCryptoManagerGenItemKAccount];
    
    // generate decryption key
    NSData *passcodeD = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt = IMSCryptoManagerSalt();
    NSData *pak = IMSCryptoUtilsDeriveKey(passcodeD, kCCKeySizeAES256, salt);
    
    // perform decryption
    NSData *adk = IMSCryptoUtilsDecryptData(encryptedCT, pak);

    
    encryptedCT = [IMSKeychain
                   passwordDataForService:IMSCryptoManagerKeychainService
                   account:IMSCryptoManagerGenItemAccount];
    
    // perform decryption
    NSData *genItemD = IMSCryptoUtilsDecryptData(encryptedCT, adk);
    NSString* genItem = [[NSString alloc] initWithData:genItemD encoding:NSASCIIStringEncoding];
    
    return genItem;
}

NSString *IMSCryptoManagerGenItemReset(NSArray *answers, NSString *passcode) {

    if (passcode == nil || answers == nil)
        return nil;
    
    //** get genItem from keychain
    NSString *answersString = [answers componentsJoinedByString:@""];
    NSData *akey = [answersString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt = IMSCryptoManagerSalt();
    NSData *adk = IMSCryptoUtilsDeriveKey(akey, kCCKeySizeAES256, salt);
    
    NSData *encryptedCT = [IMSKeychain
                           passwordDataForService:IMSCryptoManagerKeychainService
                           account:IMSCryptoManagerGenItemAccount];
    
    NSData *genItemD = IMSCryptoUtilsDecryptData(encryptedCT, adk);
    NSString* genItem = [[NSString alloc] initWithData:genItemD encoding:NSASCIIStringEncoding];
    
    //** encrypt with passcode and store on keychain
    
    //** secure answers key with user password
    NSData *passcodeD = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    NSData *pak = IMSCryptoUtilsDeriveKey(passcodeD, kCCKeySizeAES256, salt);
    //** encrypt abk item with upasswd, returns encrypted cipher text to store on keychain
    encryptedCT = IMSCryptoUtilsEncryptData(adk, pak);
    BOOL genItemKSet = [IMSKeychain
                        setPasswordData:encryptedCT
                        forService:IMSCryptoManagerKeychainService
                        account:IMSCryptoManagerGenItemKAccount];
    
    if (genItemKSet == YES)
        return genItem;
    
    return nil;
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
