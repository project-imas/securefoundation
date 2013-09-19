//
//  SecureFoundation.h
//  SecureFoundation
//
//  Upated:
//     Gregg Ganley    Sep 2013
//
//  Created on 10/8/12.
//  Copyright (c) 2013 The MITRE Corporation. All rights reserved.
//

//** select CRYPTO, comment out to use commonCrypto
#define OpenSSL

#import <Foundation/Foundation.h>

#ifdef OpenSSL
//** redefine here for use with OpenSSL calls
#define kCCKeySizeAES256 32
#define kCCBlockSizeAES128 16


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#else

#import <CommonCrypto/CommonCrypto.h>

#endif

#import "IMSCryptoUtils.h"
#import "IMSCryptoManager.h"
#import "IMSKeychain.h"
#import "Base64.h"
