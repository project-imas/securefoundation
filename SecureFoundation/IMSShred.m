//
//  Shred.m
//  shred-files
//
//  Created by Black, Gavin S. on 5/22/14.
//  Copyright (c) 2014 Black, Gavin S. All rights reserved.
//

#import "SecureFoundation.h"
#import "IMSShred.h"

static NSMutableDictionary* fileSizes;
static NSMutableDictionary* filePaths;

NSData* randomNSData(int size) {
    NSMutableData* ret = [NSMutableData dataWithCapacity:size];
    for( unsigned int i = 0 ; i < size/4 ; ++i )
    {
        u_int32_t randomBits = arc4random();
        [ret appendBytes:(void*)&randomBits length:4];
    }
    return ret;
}

void shred(NSString* path, int size, int passes, BOOL addEOF) {
    if (passes <= 0) return;
    NSData* garbage;
    if(addEOF) {
        // EOF is 0xffffffff in iOS
        // which is 4 bytes
        unsigned char bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF};

        NSMutableData *garbageTmp = [NSMutableData dataWithData: randomNSData(size - 4)];
        [garbageTmp appendData: [NSData dataWithBytes:bytes length:4]];
        garbage = [NSData dataWithData: garbageTmp];
    } else {
        garbage = randomNSData(size);
    }
    
    [garbage writeToFile:path atomically:NO];
    
    shred(path, size, passes - 1, addEOF);
}

void* dlVolatileOpen(NSString* path) {
    void *ret = dlopen([path UTF8String], RTLD_NOW);
    const char* msg = dlerror();
    if (msg) NSLog(@"\n****\n%s\n****\n", msg);
    
    // Find and save path/size so we can overwrite it properly later
    NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSNumber *fileSizeNumber = [fileAttributes objectForKey:NSFileSize];
    //NSNumber *fileNodeNumber = [fileAttributes objectForKey:NSFileSystemFileNumber];
    //NSLog(@"%@", fileNodeNumber);
    
    char buffer[16];
    sprintf (buffer, "%p", ret);
    NSString* pKey = [NSString stringWithCString:buffer encoding:NSASCIIStringEncoding];
    
    if(fileSizes == nil) {
        fileSizes = [[NSMutableDictionary alloc] init];
        filePaths = [[NSMutableDictionary alloc] init];
    }
    
    [filePaths setObject:path forKey:pKey];
    [fileSizes setObject:fileSizeNumber forKey:pKey];

    shred(path, arc4random() % (1024 - 256) + 256, 1, YES);
    return ret;
}

void dlVolatileClose(void* handle){
    char buffer[16];
    sprintf (buffer, "%p", handle);
    dlclose(handle);
    
    // No check for fileSizes init
    // would rather it crash out then give a false sense shred happened
    // which can't happen without the file path/size being available
    NSString* pKey = [NSString stringWithCString:buffer encoding:NSASCIIStringEncoding];
    NSString* filePath = [filePaths objectForKey:pKey];
    NSNumber* fileSize = [fileSizes objectForKey:pKey];
    
    /*NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:nil];
    NSNumber *fileNodeNumber = [fileAttributes objectForKey:NSFileSystemFileNumber];
    NSLog(@"%@", fileNodeNumber);*/
    
    shred(filePath, [fileSize intValue], 3, NO);
    shred(filePath, arc4random() % (1024 - 256) + 256, 1, YES);
}
