//
//  IMSKeychain.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/15/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"

@implementation IMSKeychain

+ (NSArray *)accounts:(NSError **)error {
    return [self accountsForService:nil error:error];
}

+ (NSArray *)accountsForService:(NSString *)service error:(NSError **)error {
    __block NSArray *keys = nil;
    [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
        if (service == nil) {
            NSMutableArray *accounts = [NSMutableArray array];
            [keychain enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
                [accounts addObjectsFromArray:[obj allKeys]];
            }];
            keys = accounts;
        }
        else {
            NSMutableDictionary *accounts = [keychain objectForKey:service];
            keys = [accounts allKeys];
        }
    }];
    return keys;
}

+ (NSString *)passwordForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSData *data = [self passwordDataForService:service account:account error:error];
    if ([data length]) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (NSData *)passwordDataForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    if (service == nil || account == nil) { return nil; }
    
    // access keychain
    __block NSData *password = nil;
    [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
        NSMutableDictionary *accounts = [keychain objectForKey:service];
        password = [accounts objectForKey:account];
    }];
    return password;
    
}

+ (BOOL)deletePasswordForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    if (service == nil || account == nil) { return NO; }
    
    // access keychain
    [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
        NSMutableDictionary *accounts = [keychain objectForKey:service];
        if ([accounts count] == 1) { [keychain removeObjectForKey:service]; }
        else { [accounts removeObjectForKey:account]; }
    }];
    [self setKeychainIsDirty];
    return YES;
    
}

+ (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    return [self setPasswordData:data forService:service account:account error:error];
}

+ (BOOL)setPasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    NSParameterAssert(password != nil);
    if (service == nil || account == nil || password == nil) { return NO; }
    
    // access keychain
    [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
        NSMutableDictionary *accounts = [keychain objectForKey:service];
        if (accounts == nil) {
            accounts = [NSMutableDictionary dictionary];
            [keychain setObject:accounts forKey:service];
        }
        [accounts setObject:password forKey:account];
    }];
    [self setKeychainIsDirty];
    return YES;
    
}

+ (BOOL)setSecurePassword:(NSString *)password forService:(NSString *)service account:(NSString *)account {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    return [self setSecurePasswordData:data forService:service account:account];
}

+ (BOOL)setSecurePasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    NSParameterAssert(password != nil);
    if (service == nil || account == nil || password == nil) { return NO; }
    
    // access keychain
    NSData *encrypted = IMSCryptoManagerEncryptData(password);
    if (encrypted) {
        return [self setPasswordData:encrypted forService:service account:account error:nil];
    }
    return NO;
    
}

+ (NSString *)securePasswordForService:(NSString *)service account:(NSString *)account {
    NSData *data = [self securePasswordDataForService:service account:account];
    if ([data length]) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (NSData *)securePasswordDataForService:(NSString *)service account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    if (service == nil || account == nil) { return NO; }
    
    // access keychain
    NSData *data = [self passwordDataForService:service account:account error:nil];
    return IMSCryptoManagerDecryptData(data);
    
}

#pragma mark - private methods

+ (void)accessKeychainInLock:(void (^) (NSMutableDictionary *keychain))block {
    
    // create variables
    static NSMutableDictionary *dictionary = nil;
    static NSRecursiveLock *lock = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        
        // lock
        lock = [[NSRecursiveLock alloc] init];
        
        // read data
        NSURL *URL = [self URLForKeychainFile];
        NSData *data = [NSData dataWithContentsOfURL:URL];
        if (data) {
            dictionary = [NSPropertyListSerialization
                          propertyListWithData:data
                          options:NSPropertyListMutableContainers
                          format:NULL
                          error:NULL];
        }
        if (dictionary == nil) {
            dictionary = [NSMutableDictionary dictionary];
        }
        
    });
    
    // perform block
    if (block) {
        [lock lock];
        block(dictionary);
        [lock unlock];
    }
    
}

+ (void)setKeychainIsDirty {
    static NSLock *lock;
    static dispatch_queue_t queue;
    static dispatch_once_t token;
    static dispatch_source_t timer;
    
    // create queue and lock
    dispatch_once(&token, ^{
        queue = dispatch_queue_create("org.mitre.imas.keychain.file-output-queue", DISPATCH_QUEUE_SERIAL);
        lock = [[NSLock alloc] init];
    });
    
    // lock
    [lock lock];
    
    // reset timer
    if (timer == NULL) {
        timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        dispatch_source_set_event_handler(timer, ^{
            
            // cancel timer
            [lock lock];
            dispatch_source_cancel(timer);
            timer = NULL;
            [lock unlock];
            
            // perform write
            [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
                NSURL *URL = [self URLForKeychainFile];
                NSFileManager *manager = [NSFileManager defaultManager];
                [manager removeItemAtURL:URL error:nil];
                [keychain writeToURL:URL atomically:NO];
            }];
            
        });
        dispatch_resume(timer);
    }
    dispatch_time_t time = dispatch_time(DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC);
    dispatch_source_set_timer(timer, time, 1000.0 * NSEC_PER_SEC, 0.0);
    
    // unlock
    [lock unlock];
    
}

+ (NSURL *)URLForKeychainFile {
    static NSURL *URL;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        NSFileManager *manager = [NSFileManager defaultManager];
        URL = [[manager
                URLsForDirectory:NSLibraryDirectory
                inDomains:NSUserDomainMask]
               objectAtIndex:0];
        URL = [URL URLByAppendingPathComponent:@".imskeychain"];
    });
    return URL;
}

@end
