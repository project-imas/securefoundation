//
//  IMSKeychain.m
//  SecureFoundation
//
//  Created by Caleb Davenport on 10/15/12.
//  Copyright (c) 2012 The MITRE Corporation. All rights reserved.
//

#import <UIKit/UIKit.h>

#import "SecureFoundation.h"

static dispatch_source_t _delayedWriteTimer = NULL;
static dispatch_queue_t _delayedWriteQueue = NULL;
static NSLock *_delayedWriteLock = nil;

@implementation IMSKeychain

+ (void)initialize {
    if (self == [IMSKeychain class]) {
        
        // notifications
        NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
        [center
         addObserverForName:UIApplicationWillResignActiveNotification
         object:nil
         queue:[NSOperationQueue mainQueue]
         usingBlock:^(NSNotification *note) {
             [self synchronize];
         }];
        
        // static resources
        _delayedWriteLock = [[NSLock alloc] init];
        _delayedWriteQueue = dispatch_queue_create("org.mitre.imas.keychain.file-output-queue", DISPATCH_QUEUE_SERIAL);
        
    }
}

+ (NSArray *)accounts {
    return [self accountsForService:nil];
}

+ (NSArray *)accountsForService:(NSString *)service {
    
    // create accounts list
    NSMutableArray *accounts = [NSMutableArray array];
    
    // declare block for collecting accounts
    void (^collectAccounts) (NSString *, NSDictionary *) = ^(NSString *blockService, NSDictionary *blockDictionary) {
        [blockDictionary enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
            [accounts addObject:@{
                 (__bridge NSString *)kSecAttrService : blockService,
                 (__bridge NSString *)kSecAttrAccount : key
             }];
        }];
    };
    
    // grab stuff
    [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
        if (service == nil) {
            [keychain enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
                collectAccounts(key, obj);
            }];
        }
        else {
            NSMutableDictionary *dictionary = [keychain objectForKey:service];
            collectAccounts(service, dictionary);
        }
    }];
    
    // return
    return accounts;
    
}

+ (NSString *)passwordForService:(NSString *)service account:(NSString *)account {
    NSData *data = [self passwordDataForService:service account:account];
    if ([data length]) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (NSData *)passwordDataForService:(NSString *)service account:(NSString *)account {
    
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

+ (BOOL)deletePasswordForService:(NSString *)service account:(NSString *)account {
    
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
    [self setNeedsDelayedWrite];
    return YES;
    
}

+ (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    return [self setPasswordData:data forService:service account:account];
}

+ (BOOL)setPasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account {
    
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
    [self setNeedsDelayedWrite];
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
        return [self setPasswordData:encrypted forService:service account:account];
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
    NSData *data = [self passwordDataForService:service account:account];
    return IMSCryptoManagerDecryptData(data);
    
}

+ (void)synchronize {
    [self accessKeychainInLock:^(NSMutableDictionary *keychain) {
        NSURL *URL = [self URLForKeychainFile];
        NSFileManager *manager = [NSFileManager defaultManager];
        [manager removeItemAtURL:URL error:nil];
        [keychain writeToURL:URL atomically:NO];
    }];
    [self cancelDelayedWrite];
}

#pragma mark - private methods

+ (void)accessKeychainInLock:(void (^) (NSMutableDictionary *keychain))block {
    
    // load variables
    static NSMutableDictionary *dictionary = nil;
    static NSLock *lock = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        
        // lock
        lock = [[NSLock alloc] init];
        
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

+ (void)setNeedsDelayedWrite {
    [_delayedWriteLock lock];
    if (_delayedWriteTimer == NULL) {
        _delayedWriteTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _delayedWriteQueue);
        dispatch_source_set_event_handler(_delayedWriteTimer, ^{
            [self synchronize];
        });
        dispatch_resume(_delayedWriteTimer);
    }
    dispatch_time_t time = dispatch_time(DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC);
    dispatch_source_set_timer(_delayedWriteTimer, time, 1000.0 * NSEC_PER_SEC, 0.0);
    [_delayedWriteLock unlock];
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

+ (void)cancelDelayedWrite {
    [_delayedWriteLock lock];
    if (_delayedWriteTimer != NULL) {
        dispatch_source_cancel(_delayedWriteTimer);
        _delayedWriteTimer = NULL;
    }
    [_delayedWriteLock unlock];
}

@end
