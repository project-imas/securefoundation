//
//  IMSKeychain.h
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/15/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface IMSKeychain : NSObject

+ (NSArray *)accounts:(NSError **)error;

+ (NSArray *)accountsForService:(NSString *)serviceName error:(NSError **)error;

+ (NSString *)passwordForService:(NSString *)service account:(NSString *)account error:(NSError **)error;
+ (NSData *)passwordDataForService:(NSString *)service account:(NSString *)account error:(NSError **)error;

+ (BOOL)deletePasswordForService:(NSString *)service account:(NSString *)account error:(NSError **)error;

+ (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error;
+ (BOOL)setPasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error;

@end
