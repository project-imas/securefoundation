//
//  IMSCryptoManager.h
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/18/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <Foundation/Foundation.h>

/*
 
 Encrypt and decrypt data with the application shared key. These methods will
 return data on success or `nil` if or the application is locked or if the 
 operation fails.
 
 */
NSData *IMSCryptoManagerDecryptData(NSData *data);
NSData *IMSCryptoManagerEncryptData(NSData *data);

/*
 
 Call this method at any time to drop encryption keys from memory. Any calls to
 the methods in this file that require encryption or decryption will fail until
 the user is reauthenticated or the keys are reloaded.
 
 */
void IMSCryptoManagerPurge(void);

/*
 
 Store values that will be used to drive encryption with these methods. Data
 stored by these methods will only be kept in memory until
 `IMSCryptoManagerFinalize` is called.
 
 */
void IMSCryptoManagerStoreTemporaryPasscode(NSString *code);
void IMSCryptoManagerStoreTemporarySecurityQuestionsAndAnswers(NSArray *questions, NSArray *answers);

/*
 
 Finalize the encryption setup process and save all valid attributes to the
 keychain. This method generates the shared encryption key, stores all
 relevant resources to the keychain, and purges any values from memory that
 are not necessary to keep.
 
 */
void IMSCryptoManagerFinalize(void);

/*
 
 Set new authentication information. These may only be called when the app is
 unlocked.
 
 */
BOOL IMSCryptoManagerUpdatePasscode(NSString *passcode);
BOOL IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(NSArray *questions, NSArray *answers);

/*
 
 Unlock the application given the appropriate data. Each of these functions
 returns whether the app has been successfully unlocked.
 
 */
BOOL IMSCryptoManagerUnlockWithPasscode(NSString *passcode);
BOOL IMSCryptoManagerUnlockWithAnswersForSecurityQuestions(NSArray *answers);
BOOL IMSCryptoManagerIsLocked(void);

/*
 
 Access the stored security questions.
 
 */
NSArray *IMSCryptoManagerSecurityQuestions(void);

/*
 
 Ask the manager if it has data that indicates that the app has been configured
 with a passcode or security questions and answers.
 
 */
BOOL IMSCryptoManagerHasPasscode(void);
BOOL IMSCryptoManagerHasSecurityQuestionsAndAnswers(void);
