# iMas Secure Foundation

## Background

The "iMas Secure Foundation" project is designed to provide basic application-level security based on simple encryption mechanisms. It contains three components: a suite of cipher utilities, a collection of functions to assist with encryption through an application key, and a file-based keychain replacement.

## Cipher Utilities

The methods found in `IMSCryptoUtils.h` help with encrypting and hashing various forms of data, as well as generating pseudo-random data and encryption keys. The methods here are all implemented in C so that they do not show up in the Objective-C symbol table or pass through `objc_msgSend`.

### Key Generation

Key generation is performed using `PBKDF2` using 1000 rounds by default. It accepts parameters for the length of the resulting key as well as a salt to be used during generation.

### Encryption

Encryption is currently implemented using AES with 128 bit blocks, `PKCS7` padding, a randomly generated initialization vector (stored on the resulting cipher text), and a checksum of the plain text. The decryption function performs an integrity check of the decrypted body using the included checksum.

Functions are included to encrypt and decrypt binary data (`NSData` objects), as well as any `plist` object (`NSString`, `NSNumber`, `NSArray`, `NSDictionary`, etc).

### Hashing

Just as with encryption, functions are provided to perform both MD5 and SHA256 hashes of binary data and `plist` objects.

## Cryptography Manager

`IMSCryptoManager.h` contains functions to help applications build a secure container for themselves. Its primary task is to generate, maintain, and store application-wide encryption key. It also assists with the secure storage of other encryption keys and user data protected by an application passcode and, optionally, security questions and answers.

Like the Cipher Utilities, the methods here are all implemented in C so that they do not show up in the Objective-C symbol table or pass through `objc_msgSend`.

### Using the Cryptography Manager

On application launch, you should check to see if your application has been configured with the required security controls.

    if (IMSCryptoManagerHasPasscode() && IMSCryptoManagerHasSecurityQuestionsAndAnswers()) {
        // show interface for verifying passcode
    }
    else {
        // show interface for creating passcode and security questions and answers
    }

If the application has not been configured, you can set it up using the temporary storage and finalize methods.

    IMSCryptoManagerStoreTemporaryPasscode(passcode);
    IMSCryptoManagerStoreTemporarySecurityQuestionsAndAnswers(questions, answers);
    IMSCryptoManagerFinalize();

To attempt an application unlock with either a passcode or answers to security questions, call

    if (IMSCryptoManagerUnlockWithPasscode(passcode)) {
        // yay
    }
    else {
        // nope
    }
    
or

    if (IMSCryptoManagerUnlockWithAnswersForSecurityQuestions(answers)) {
        // yay
    }
    else {
        // nope
    }

When your application enters the background, call `IMSCryptoManagerPurge()` to remove the application encryption key from memory.

The security questions and answers and the application passcode may be changed, as long as the user is authenticated, using

    IMSCryptoManagerUpdatePasscode(passcode);
    IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(questions, answers);
    
Lastly, `IMSCryptoManager.h` contains two functions for performing encryption and decryption using the shared application encryption key.

    IMSCryptoManagerDecryptData(data);
    IMSCryptoManagerEncryptData(data);
    
## Keychain

The keychain API is designed to mirror the system keychain as closely as possible. The major difference is that it is stored in a file inside the application sandbox so that it does not stay on the device if the application is uninstalled. It follows the same service, user, and password pattern that the system keychain uses. All writes to the keychain are coalesced and performed in the background.

It has methods like

    + (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account;
    + (NSString *)passwordForService:(NSString *)service account:(NSString *)account;
    
that store the exact data provided to it.

It also has methods like

    + (BOOL)setSecurePasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account;
    + (NSData *)securePasswordDataForService:(NSString *)service account:(NSString *)account;
    
that pass the data through the Crypto Manager to perform encryption or decryption using the application shared key. It is important to note that the account service and account names are *not* stored encrypted in either case.
