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

#import <CommonCrypto/CommonCrypto.h>

#import "IMSCryptoUtils.h"
#import "IMSCryptoManager.h"
#import "IMSKeychain.h"
#import "Base64.h"
