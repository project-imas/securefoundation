//
//  IMSKeychain.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/15/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import "IMSKeychain.h"
#import "IMSCryptoUtils.h"

@implementation IMSKeychain

+ (NSArray *)accounts:(NSError **)error {
    return [self accountsForService:nil error:error];
}

+ (NSArray *)accountsForService:(NSString *)service error:(NSError **)error {
    NSURL *URL = [self URLForService:service account:nil];
    return [self accountsInDirectory:URL error:error];
}

+ (NSString *)passwordForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSData *data = [self passwordDataForService:service account:account error:error];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSData *)passwordDataForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSURL *URL = [self URLForService:service account:account];
    return [NSData dataWithContentsOfURL:URL options:0 error:error];
}

+ (BOOL)deletePasswordForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSURL *URL = [self URLForService:service account:account];
    NSFileManager *manager = [NSFileManager defaultManager];
    if ([manager fileExistsAtPath:[URL path]]) { return [manager removeItemAtURL:URL error:error]; }
    return YES;
}

+ (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    return [self setPasswordData:data forService:service account:account error:error];
}

+ (BOOL)setPasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    if ([self deletePasswordForService:service account:account error:error]) {
        NSURL *URL = [self URLForService:service account:account];
        return [password writeToURL:URL options:0 error:error];
    }
    return NO;
}

#pragma mark - private methods

+ (NSURL *)URLForService:(NSString *)service account:(NSString *)account {
    NSFileManager *manager = [NSFileManager defaultManager];
    NSURL *URL = nil;
    
    // get root directory
    static NSURL *root;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        root = [[manager
                 URLsForDirectory:NSLibraryDirectory
                 inDomains:NSUserDomainMask]
                objectAtIndex:0];
        root = [root URLByAppendingPathComponent:@"IMSKeychain"];
    });
    URL = root;
    
    // add service
    if (service) {
        URL = [URL URLByAppendingPathComponent:service];
    }
    
    // create directories
    [manager createDirectoryAtURL:URL withIntermediateDirectories:YES attributes:nil error:nil];
    
    // add account
    if (account) {
        URL = [URL URLByAppendingPathComponent:account];
    }
    
    return URL;
}

+ (NSArray *)accountsInDirectory:(NSURL *)directory error:(NSError **)error {
    
    // get enumerator
    NSFileManager *manager = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator = [manager
                                         enumeratorAtURL:directory
                                         includingPropertiesForKeys:nil
                                         options:NSDirectoryEnumerationSkipsHiddenFiles
                                         errorHandler:nil];
    
    // get contents
    NSURL *URL = nil;
    NSMutableArray *contents = [NSMutableArray array];
    while ((URL = [enumerator nextObject])) {
        NSString *account = [URL lastPathComponent];
        account = [self transformedStringWithString:account];
        [contents addObject:account];
    }
    
    // return
    return contents;
    
}

+ (NSString *)transformedStringWithString:(NSString *)string {
    return string;
}

@end
