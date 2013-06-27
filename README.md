# iMas Secure Foundation

## Background

The "iMas Secure Foundation" project is designed to provide advanced application-level security based on simple 
encryption mechanisms. It contains three components: a suite of cipher utilities, a collection of functions to 
assist with encryption through an application key, and a file-based keychain replacement.  Of note is that we include 
openSSL - a full-strength general purpose cryptography library.

## Vulnerabilities Addressed

1. Objective-C reflectivity run-time application code exploration and exploitation
  - new CWE under review
  - CWE-545: Use of Dynamic Class Loading
  - SRG-APP-000160-MAPP-000035 Severity-CAT II: The mobile application must authenticate devices using bidirectional cryptographic authentication if it manages wireless network connections for other devices.
  - SRG-APP-000196-MAPP-000042 Severity-CAT II: The mobile application must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
  - SRG-APP-000225-MAPP-000047 Severity-CAT II: The mobile application must fail to an initial state when the application unexpectedly terminates, unless it maintains a secure state at all times.
  - SRG-APP-000264-MAPP-000057 Severity-CAT II: The mobile application must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission.
2. iOS keychain accessible after device pin-code login
  - CWE-311: Missing Encryption of Sensitive Data
  - SRG-APP-000200-MAPP-000044 Severity-CAT II: The mobile application must shut down when it determines that a required security function is unavailable.
  - SRG-APP-000243-MAPP-000049 Severity-CAT II: The mobile application must not write data to persistent memory accessible to other applications.
  - SRG-APP-000243-MAPP-000050 Severity-CAT II: The mobile application must not share working memory with other applications or processes.
  - SRG-APP-999999-MAPP-000067 Severity-CAT II: The mobile application must clear or overwrite memory blocks used to process sensitive data.
  - SRG-APP-000128-MAPP-000028 Severity-CAT II: The mobile application must not change the file permissions of any files other than those dedicated to its own operation.


## Installation

- Add SecureFoundation as a submodule to your project. `git submodule add https://github.com/mitre-imas/securefoundation.git vendor/securefoundation`
- Add the "SecureFoundation" Xcode project as a subproject in your project
- Add "libSecureFoundation.a" as a target dependency and to the "Link with Binary Libraries" build phase
- Import SecureFoundation in your source files `#import <SecureFoundation/SecureFoundation.h>`
- Add security.framework to build phase "Link Binary With Libraries"

## Installation via CocoaPod

- Add `pod 'SecureFoundation', :git => 'https://github.com/project-imas/securefoundation.git'` to your `PodFile`
- Run `pod install`
- Add `#import <SecureFoundation/SecureFoundation.h>` to your app

## Test Suite

Some (not all, yet) of the components here are testing using `OCUnit`. The tests can be found in `SecureFoundationTests`.

## Cipher Utilities

The methods found in `IMSCryptoUtils.h` help with encrypting and hashing various forms of data as well as generating pseudo-random data and encryption keys. All of the methods here are implemented in C so that they do not show up in the Objective-C symbol table or pass through `objc_msgSend`.

### Key Generation

Key generation is performed using `PBKDF2` using 1000 rounds by default. It accepts parameters for the length of the resulting key as well as a salt to be used during generation.

### Encryption

Encryption is currently implemented using AES with 128 bit blocks, `PKCS7` padding, a randomly generated initialization vector (stored on the resulting cipher text), and a checksum of the plain text. The decryption function performs an integrity check of the decrypted body using the included checksum.

Functions are included to encrypt and decrypt binary data (`NSData` objects), as well as any `plist` object (`NSString`, `NSNumber`, `NSArray`, `NSDictionary`, etc).

### Hashing

Just as with encryption, functions are provided to perform both MD5 and SHA256 hashes of binary data and `plist` objects.

## Cryptography Manager

`IMSCryptoManager.h` contains functions to help applications build a secure container for themselves. Its primary task is to generate, maintain, and store an application-wide encryption key. It also assists with the secure storage of other encryption keys and user data protected by an application passcode and, optionally, security questions and answers.

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

    IMSCryptoManagerStoreTP(passcode);
    IMSCryptoManagerStoreTSQAnswers(questions, answers);
    IMSCryptoManagerFinalize();

To attempt an application unlock with either a passcode or answers to security questions, call:

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

The security questions and answers and the application passcode may be changed as long as the user is authenticated using:

    IMSCryptoManagerUpdatePasscode(passcode);
    IMSCryptoManagerUpdateSecurityQuestionsAndAnswers(questions, answers);

Lastly, `IMSCryptoManager.h` contains two functions for performing encryption and decryption using the shared application encryption key.

    IMSCryptoManagerDecryptData(data);
    IMSCryptoManagerEncryptData(data);

## Keychain

The keychain API is designed to mirror the system keychain as closely as possible. The major difference is that it is stored in a file inside the application sandbox so that it does not stay on the device if the application is uninstalled. It follows the same service, user, and password pattern that the system keychain uses. All writes to the keychain are coalesced and performed in the background.

It has methods like:

    + (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account;
    + (NSString *)passwordForService:(NSString *)service account:(NSString *)account;
    
These methods store the exact data provided to them.

It also has methods like:

    + (BOOL)setSecurePasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account;
    + (NSData *)securePasswordDataForService:(NSString *)service account:(NSString *)account;
    
These methods pass the data through the Crypto Manager to perform encryption or decryption using the application shared key. It is important to note that the account service and account names are *not* stored encrypted in either case.

## License

Copyright 2012 The MITRE Corporation, All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project source code except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


[![githalytics.com alpha](https://cruel-carlota.pagodabox.com/deee09168244f6094f41ef957d2a30b7 "githalytics.com")](http://githalytics.com/project-imas/securefoundation)


