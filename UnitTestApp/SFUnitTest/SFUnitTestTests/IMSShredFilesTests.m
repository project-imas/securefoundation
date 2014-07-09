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

- (void)testShredMethod
{
    NSData *data = IMSCryptoUtilsPseudoRandomData(16);
    NSString *path = @"/tmp/testShred";
    [data writeToFile:path atomically:YES];
    shred(path,16,10,NO);
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    NSData *shreddedData = [handle readDataOfLength:16];
    STAssertFalse([data isEqualToData:shreddedData], @"Shredded data is equal to original data");
    NSError *error = nil;
    [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
}

- (void) testDLVolatileOpenAndClose
{
    // Path setup
    NSString *fileName = @"imas_app_check.dylib";
    NSString *docLib = [NSString stringWithFormat:@"%@/%@",[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject],fileName];
    NSString *bundleLib = [NSString stringWithFormat:@"%@/%@", [[NSBundle mainBundle] resourcePath],fileName ];
    
    NSError *error = nil;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath:docLib] == YES) {
        [fileManager removeItemAtPath:docLib error:&error];
    }
    [fileManager copyItemAtPath:bundleLib toPath:docLib error:&error];
    NSLog(@"%@",error);
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

@end
