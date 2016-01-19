//
//  IMSKeychain.m
//  SecureFoundation
//
//  Upated:
//     Gregg Ganley    Sep 2013
//
//  Created on 10/8/12.
//  Copyright (c) 2013 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"
#import "IMSKeys.h"

char * s = "shared-key.passcode";


@implementation IMSKeychain

// ---------------------------------------------
// this class is not meant to be instantiated...
// ---------------------------------------------
-(id) init  {
    
    self = nil;
    
    return self;
}
+(id) alloc {
    
    return nil;
}

+ (void) initialize {
    
    if (self == [IMSKeychain class]) {
        
        [self firstTimeCheck];
        [self theChain];        
    }
}

+ (NSArray *) accounts {
    
    return [self accountsForService:nil];
}

+ (NSArray *) accountsForService:(NSString *)service {
    
    // create accounts list
    NSMutableArray *accounts = [NSMutableArray array];
    
    // declare block for collecting accounts
    void (^collectAccounts) (NSString *, NSDictionary *) =
    
        ^(NSString *blockService, NSDictionary *blockDictionary) {
            
            [blockDictionary enumerateKeysAndObjectsUsingBlock:
             
             ^(id key, id obj, BOOL *stop) {
                
                [accounts addObject:
                 
                 @{ (__bridge NSString *)kSecAttrService : blockService,
                    (__bridge NSString *)kSecAttrAccount : key}];
            }];
        };
    
    // grab stuff
    NSMutableDictionary *keychain = [self link];
    
    if (service == nil) {
        
        [keychain enumerateKeysAndObjectsUsingBlock:
         
         ^(id key, id obj, BOOL *stop) {collectAccounts(key, obj);} ];
        
    } else {
        
        NSMutableDictionary *dictionary = [keychain objectForKey:service];
        
        collectAccounts(service, dictionary);
    }
    
    return accounts;
}

+ (NSString*) passwordForService:(NSString *)service
                         account:(NSString *)account {
    
    NSData *data = [self passwordDataForService:service account:account];
    
    if ([data length]) {
        
        return [[NSString alloc] initWithData:data
                                     encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (NSData  *) passwordDataForService:(NSString *)service
                             account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    
    if (service == nil || account == nil) { return nil; }
    
    // access keychain
    NSData              *password =  nil;
    NSMutableDictionary *keychain = [self link];
    NSMutableDictionary *accounts = [keychain objectForKey:service];
                         password = [accounts objectForKey:account];
    
//    NSString * test =  [[NSString alloc] initWithData:password
//                                             encoding:NSUTF8StringEncoding];
//    
//    if ( nil == test ) password = nil;
    
    return password;
}

+ (BOOL) deletePasswordForService:(NSString *)service
                          account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    
    if (service == nil || account == nil) { return NO; }
    
    // access keychain
    NSMutableDictionary *keychain = [self link];
    NSMutableDictionary *accounts = [keychain objectForKey:service];
        
    if ([accounts count] == 1) { [keychain removeObjectForKey:service]; }
    else                       { [accounts removeObjectForKey:account]; }
    
    [self setNeedsWrite];
    
    return YES;    
}

+ (BOOL) setPassword:(NSString *)password
          forService:(NSString *)service
             account:(NSString *)account {
    
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    return [self setPasswordData:data
                      forService:service
                         account:account];
}

+ (BOOL) setPasswordData:(NSData   *)password
              forService:(NSString *)service
                 account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service  != nil);
    NSParameterAssert(account  != nil);
    NSParameterAssert(password != nil);
    
    if (service == nil || account == nil || password == nil) { return NO; }
    
    // access keychain
    NSMutableDictionary *keychain = [self link];
    NSMutableDictionary *accounts = [keychain objectForKey:service];
    
    if (accounts == nil) {
        
        accounts = [NSMutableDictionary dictionary];
        [keychain setObject:accounts forKey:service];
    }
    
    [accounts setObject:password forKey:account];
    
    [self setNeedsWrite];
    
    return YES;
}

+ (BOOL) setSecurePassword:(NSString *)password
                forService:(NSString *)service
                   account:(NSString *)account {
    
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    return [self setSecurePasswordData:data
                            forService:service
                               account:account];
}

+ (BOOL) setSecurePasswordData:(NSData   *)password
                    forService:(NSString *)service
                       account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service  != nil);
    NSParameterAssert(account  != nil);
    NSParameterAssert(password != nil);
    
    if (service == nil || account == nil || password == nil) { return NO; }
    
    // access keychain
    NSData *encrypted = IMSCryptoManagerEncryptData(password);
    
    if (encrypted) {
        
        return [self setPasswordData:encrypted
                          forService:service
                             account:account];
    }
    
    return NO;
}

+ (NSString*) securePasswordForService:(NSString *)service
                               account:(NSString *)account {
    
    NSData *data = [self securePasswordDataForService:service account:account];
    
    if ([data length])
        
        return [[NSString alloc] initWithData:data
                                     encoding:NSUTF8StringEncoding];
    else
        return nil;
}

+ (NSData  *) securePasswordDataForService:(NSString *)service
                                   account:(NSString *)account {
    
    // check parameters
    NSParameterAssert(service != nil);
    NSParameterAssert(account != nil);
    
    if (service == nil || account == nil) { return nil; }
    
    // access keychain
    NSData *data = [self passwordDataForService:service account:account];
    
    return IMSCryptoManagerDecryptData(data);
}

+ (void) setNeedsWrite {
    
    @synchronized(self) { [self synchronize]; }
}

+ (void) synchronize   {

    NSFileManager       *manager  = [NSFileManager defaultManager];
    NSMutableDictionary *chain    = [self link];
    NSURL               *URL;       IMSKeychainUrl
    
    
    if ( ![chain count] ) chain   = nil;
    
    NSData *dataRep = [NSPropertyListSerialization
                       dataWithPropertyList:chain
                       format:NSPropertyListBinaryFormat_v1_0
                       options:0
                       error:nil];
    
    if ( [manager fileExistsAtPath:[URL path]] ) [manager removeItemAtURL:URL
                                                                    error:nil];
    // real
    if ( chain ) {
        
        [dataRep writeToURL:URL atomically:NO];
        
    } else {
        
        FILE *fd  = fopen(URL.path.UTF8String,"w");
        
        fclose(fd);
    }
    
    NSMutableDictionary *keychain = [self accessKeychain];
    NSURL               *url      = [self URLForKeychainFile];
    
    if ( [manager fileExistsAtPath:[url path]] ) [manager removeItemAtURL:url
                                                                    error:nil];
    // decoy
    [keychain     writeToURL:url atomically:NO];
}

#pragma mark - private methods
// -------------------------------------------------
// this can be decommisioned with version 2 or lib
// -------------------------------------------------
+(void) firstTimeCheck {
    
    NSFileManager *manager = [NSFileManager defaultManager];
    NSURL         *urlOld  = [self URLForKeychainFile];
    NSURL         *URL;      IMSKeychainUrl
    NSData        *data    = nil;
    NSDictionary  *dict    = nil;
    
    if ( ![manager fileExistsAtPath:[URL    path]]
    &&    [manager fileExistsAtPath:[urlOld path]] ) {
        
        data = [NSData dataWithContentsOfURL:urlOld];
        
        dict = [NSPropertyListSerialization
                propertyListWithData:data
                             options:NSPropertyListImmutable
                              format:NULL
                               error:NULL];
        
        data = [NSPropertyListSerialization
                dataWithPropertyList:dict
                format:NSPropertyListBinaryFormat_v1_0
                options:0
                error:nil];
        
        [data  writeToURL:URL atomically:NO];
    }
}
//----------------------------------
// create the decoy keychain
//----------------------------------
+ (void) theChain      {
    
    char imsKeyFile[IMSKEYCHAIN_SIZE];
    
    IMSKeyChainFile(imsKeyFile);
    
    NSURL         *URL;      IMSKeychainUrl
    NSURL         *url     = [self URLForKeychainFile];
    NSData        *sFile   = [NSData dataWithBytes:imsKeyFile
                                            length:strlen(imsKeyFile)];
    NSDictionary  *d       = [NSPropertyListSerialization
                              propertyListWithData:sFile
                              options:NSPropertyListImmutable
                              format:NULL
                              error:NULL];

    NSFileManager *manager = [NSFileManager defaultManager];
    
    if ( [manager fileExistsAtPath:[url path]] )
        
        [manager removeItemAtURL:url
                           error:nil];

    if ( [manager fileExistsAtPath:[URL path]])
        
    [d writeToURL:url atomically:NO];
}

//----------------------------------
// access the decoy keychain
//----------------------------------

+ (NSURL *) URLForKeychainFile {
    
    static NSURL           *URL;
    static dispatch_once_t uToken;
    
    dispatch_once(&uToken, ^{
        
        NSFileManager *manager = [NSFileManager defaultManager];
        
        URL = [[manager URLsForDirectory:NSLibraryDirectory
                               inDomains:NSUserDomainMask]
               objectAtIndex:0];
        
        URL = [URL URLByAppendingPathComponent:@".imskeychain"];
    });
    
    return URL;
}

+ (NSMutableDictionary *)accessKeychain {
    
    // load variables
    static NSMutableDictionary *dictionary = nil;
    static dispatch_once_t      token;
    
    dispatch_once(&token, ^{
        
        // read data
        NSURL  *URL  = [self URLForKeychainFile];
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
    
    return dictionary;    
}

//----------------------------------
// access the real keychain
//----------------------------------
+ (NSMutableDictionary *)link {
    
    // load variables
    static NSMutableDictionary *aDict = nil;
    static dispatch_once_t      dToken;

    dispatch_once(&dToken, ^{
        
        NSURL  *URL;      IMSKeychainUrl
        NSData *data    = [NSData dataWithContentsOfURL:URL];
        
        if (data) aDict = [NSPropertyListSerialization
                     
                         propertyListWithData:data
                                      options:NSPropertyListMutableContainers
                                       format:NULL
                                        error:NULL];
        
        
        if (aDict == nil) aDict = [NSMutableDictionary dictionary];
        
    });
    
    return aDict;
}

@end
