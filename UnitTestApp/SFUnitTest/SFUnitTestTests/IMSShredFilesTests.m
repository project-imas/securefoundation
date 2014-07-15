//
//  IMSShredFilesTests.m
//  SFUnitTest
//
//  Created by Ren, Alice on 7/7/14.
//  Copyright (c) 2014 MITRE Corp. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>
#import <SecureFoundation/SecureFoundation.h>

@interface IMSShredFilesTests : SenTestCase

@end

@implementation IMSShredFilesTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class. 
    [super tearDown];
}

BOOL isDataDifferent(NSData *origData, NSFileHandle *handle, int size, int subsize) {
    for(int i = 0; i+subsize <= size && size > subsize; i+=subsize) {
        @autoreleasepool {
            [handle seekToFileOffset:i];
            NSData *shreddedData = [handle readDataOfLength:subsize];
            if ([[origData subdataWithRange:NSMakeRange(i, subsize)] isEqualToData:shreddedData]) {
                return NO;
            }
        }
    }
    int leftover = size % subsize;
    if(leftover != 0) {
        [handle seekToFileOffset:(size-leftover)];
        NSData *shreddedData = [handle readDataOfLength:(leftover)];
        if ([[origData subdataWithRange:NSMakeRange(size-leftover, leftover)] isEqualToData:shreddedData])
            return NO;
    }
    return YES;
}

- (void)testShredMethod
{
    NSError *error = nil;
    int passes = 3;
#if !(TARGET_IPHONE_SIMULATOR)
    NSLog(@"started");
    NSString *fileName = @"testShredFile"; // name of file to be shredded
    NSString *path = [NSString stringWithFormat:@"%@/%@",[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject],fileName];
    NSString *bundleLib = [NSString stringWithFormat:@"%@/%@", [[NSBundle mainBundle] resourcePath],fileName];
    NSLog(@"bundleLib: %@, path: %@",bundleLib,path);
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:path])
        [fileManager copyItemAtPath:bundleLib toPath:path error:&error];
    if(error)
        NSLog(@"ERROR: %@",error);
    NSLog(@"file copied");
    NSFileHandle *handle = [NSFileHandle fileHandleForUpdatingAtPath:path];
    unsigned long long fileSize = [[[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil] fileSize];
    int len = (int)fileSize;
    NSData *origData = [NSData dataWithContentsOfFile:path];
#else
    int len = 5000;
    NSString *path = @"/tmp/testShred";
    NSMutableData *origData = [NSMutableData dataWithCapacity:len];
    for( unsigned int i = 0 ; i < len/4 ; i++ )
    {
        @autoreleasepool {
            u_int32_t randomBits = arc4random();
            [origData appendBytes:(void*)&randomBits length:4];
        }
    }
    [origData writeToFile:path atomically:NO];
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
#endif
    
    // without EOF
    NSLog(@"about to shred");
    shred(path,len,passes,NO);
    NSLog(@"shred 1");
    STAssertTrue(isDataDifferent(origData, handle, len, 16), @"Shredded data (no EOF) is equal to previous data");
    
    // with EOF
    NSLog(@"about to shred 2");
    shred(path,len,passes,YES);
    NSLog(@"shred 2");
    STAssertTrue(isDataDifferent(origData, handle, len, 16), @"Shredded data (with EOF) is equal to previous data");
    // test that EOF marker has been added
    [handle seekToFileOffset:[handle seekToEndOfFile]-4];
    NSData *EOFMarker = [handle readDataOfLength:4];
    unsigned char bytes[] = {0xFF, 0xFF, 0xFF, 0xFF};
    STAssertTrue([EOFMarker isEqualToData:[NSData dataWithBytes:bytes length:4]], @"EOF marker was not added");
    
    error = nil;
    [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
    NSLog(@"file deleted");
    [handle closeFile];
}

// note: dylib was compiled for iOS 7 -- this test won't run on iOS 6
#if __IPHONE_OS_VERSION_MAX_ALLOWED > __IPHONE_6_0 && !(TARGET_IPHONE_SIMULATOR)
- (void) testDLVolatileOpenAndClose
{
    // Path setup
    NSString *fileName = @"imas_app_check.dylib";
    NSString *docLib = [NSString stringWithFormat:@"%@/%@",[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject],fileName];
    NSString *bundleLib = [NSString stringWithFormat:@"%@/%@", [[NSBundle mainBundle] resourcePath],fileName];
    
    NSError *error = nil;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath:docLib] == YES) {
        [fileManager removeItemAtPath:docLib error:&error];
    }
    [fileManager copyItemAtPath:bundleLib toPath:docLib error:&error];
    if(error)
        NSLog(@"ERROR: %@",error);
    STAssertNil(error, @"Dylib was not copied");
    
    void *libHandle = dlVolatileOpen(docLib);
    BOOL open = true;
    if(libHandle == nil) open = false;
    STAssertTrue(open, @"Dylib was not opened");
    
    void (*helloWorld)(NSString* f) = dlsym(libHandle, "helloWorld");
    BOOL run = true;
    if(helloWorld == nil) run = false;
    STAssertTrue(run, @"Dylib function failed");
    
    [NSThread sleepForTimeInterval:20];
    
    NSLog(@"Volatile dlclose");
    dlVolatileClose(libHandle);
    STAssertFalse([[fileManager contentsAtPath:docLib] isEqualToData:[fileManager contentsAtPath:bundleLib]], @"File was not shredded after close");
}
#endif

@end
