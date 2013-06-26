// ====================================================================
// Copyright (c) 2013 The OpenSSL Project. Rights for redistribution
// and usage in source and binary forms are granted according to the
// OpenSSL license.
// ====================================================================
//  ViewController.m
//
//  Created by Tim Hudson, Steve Marquess, Jeffrey Walton on 1/5/13.
// ====================================================================

#import "ViewController.h"

//
// FIPS_mode, FIPS_mode_set, ERR_get_error, etc
#include <openssl/crypto.h>
#include <openssl/err.h>

// Random operations to test FIPS mode
#include <openssl/rand.h>
#include <openssl/aes.h>

//
// Debug instrumentation
#include "fips_assert.h"

//
// Symbols from fips_premain.c
static const unsigned int   MAGIC_20 = 20;
extern const void*          FIPS_text_start(),  *FIPS_text_end();
extern const unsigned char  FIPS_rodata_start[], FIPS_rodata_end[];
extern unsigned char        FIPS_signature[20];
extern unsigned int         FIPS_incore_fingerprint (unsigned char *, unsigned int);


@interface ViewController ()

@end

@implementation ViewController

@synthesize m_dataLabel, m_textLabel;

@synthesize m_embeddedLabel, m_calculatedLabel;

@synthesize  m_modeSwitch;

@synthesize m_mainView;

void DisplayErrorMessage(const char* msg, unsigned long err)
{
    if(!msg)
        msg = "";
    
    NSString* message = nil;
    
    if(0 == err)
        message = [NSString stringWithFormat:@"%s", msg];
    else
        message = [NSString stringWithFormat:@"%s, error code: %ld, 0x%lx", msg, err, err];
    
    UIAlertView* alert = [[UIAlertView alloc] initWithTitle:@"Module Error"
                                                    message:message delegate:nil
                                          cancelButtonTitle:@"OK"
                                          otherButtonTitles: nil];
    
    FIPS_ASSERT(alert != nil);
    if(alert != nil)
        [alert show];
    
}

-(IBAction) modeSwitched
{
    int mode = 0, ret = 0;
    unsigned long err = 0;
    
    mode = FIPS_mode();
    FIPS_ASSERT(1 == mode || 0 == mode);
    
    if(mode == 0)
    {
        NSLog(@"\n  FIPS mode is off. Attempting to enter FIPS mode");
        
        // Lots of possible return codes here
        ret = FIPS_mode_set(1 /*on*/);
        err = ERR_get_error();
        
        FIPS_ASSERT(ret == 1);
        if(1 != ret) {
            DisplayErrorMessage("\n  FIPS_mode_set failed", err);
        }
    }
    else
    {
        NSLog(@"\n  FIPS mode is on. Attempting to exit FIPS mode");
        
        ret = FIPS_mode_set(0 /*off*/);
        err = ERR_get_error();
        
        FIPS_ASSERT(ret == 1);
        if(1 != ret) {
            DisplayErrorMessage("\n  FIPS_mode_set failed", err);
        }
    }
    
    // Verify mode is consistent.
    if(1 == ret)
    {
        BOOL state = [m_modeSwitch isOn];
        mode = FIPS_mode();
        FIPS_ASSERT((0 != mode && YES == state) || (0 == mode && NO == state));
    }
    
    // Attempt a few operations in FIPS mode of operation
    if(1 == ret && 0 != mode)
    {
        static const unsigned int AES_KEYSIZE = 16;
        static const unsigned int AES_BLOCKSIZE = 16;
        
        static const unsigned char t[AES_BLOCKSIZE] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
        
        AES_KEY k1 = {}, k2 = {};
        unsigned char r[AES_KEYSIZE];
        unsigned char d[AES_BLOCKSIZE];
        
        memcpy(d, t, sizeof(d));
        
        do {
            
            // RAND_bytes() returns 1 on success, 0 otherwise. The error
            // code can be obtained by ERR_get_error(3).
            ret = RAND_bytes(r, sizeof(r));
            err = ERR_get_error();
            
            FIPS_ASSERT(ret == 1);
            if(!(ret == 1)) {
                DisplayErrorMessage("\n  RAND_bytes failed", err);
                break; /* failed */
            }
            
            ret = AES_set_encrypt_key(r, AES_KEYSIZE * 8 /*bits*/, &k1);
            err = ERR_get_error();
            
            FIPS_ASSERT(ret == 0);
            if(!(ret == 0)) {
                DisplayErrorMessage("\n  AES_set_encrypt_key failed", err);
                break; /* failed */
            }
            
            ret = AES_set_decrypt_key(r, AES_KEYSIZE * 8 /*bits*/, &k2);
            err = ERR_get_error();
            
            FIPS_ASSERT(ret == 0);
            if(!(ret == 0)) {
                DisplayErrorMessage("\n  AES_set_decrypt_key failed", err);
                break; /* failed */
            }
            
            // Hmm... void - cannot fail 
            AES_encrypt(d, d, &k1);
            AES_decrypt(d, d, &k2);
            
            // Did it round trip?
            FIPS_ASSERT(0 == memcmp(d, t, sizeof(d)));
            if(!(0 == memcmp(d, t, sizeof(d)))) {
                DisplayErrorMessage("\n  Data did not round trip", 0);
                break; /* failed */
            }
            
        } while(0);
    }
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    /******************************************/
    
    FIPS_ASSERT(m_dataLabel != nil);
    FIPS_ASSERT(m_textLabel != nil);
    FIPS_ASSERT(m_embeddedLabel != nil);
    FIPS_ASSERT(m_calculatedLabel != nil);
    FIPS_ASSERT(m_modeSwitch != nil);
    
    /******************************************/
    
    const UInt32 p1 = (UInt32)FIPS_rodata_start;
    const UInt32 p2 = (UInt32)FIPS_rodata_end;
    [m_dataLabel setText:[NSString stringWithFormat:@"Data: 0x%06lx, 0x%06lx", p1, p2]];
    
    /******************************************/
    
    const UInt32 p3 = (UInt32)FIPS_text_start();
    const UInt32 p4 = (UInt32)FIPS_text_end();
    [m_textLabel setText:[NSString stringWithFormat:@"Text: 0x%06lx, 0x%06lx", p3, p4]];
    
    /******************************************/
    
    NSMutableString* f1 = [NSMutableString stringWithCapacity:MAGIC_20*2 + 8];
    FIPS_ASSERT(f1 != nil);
    
    for(unsigned int i = 0; i < MAGIC_20; i++)
        [f1 appendFormat:@"%02x", FIPS_signature[i]];
    
    [m_embeddedLabel setText:f1];
    
    /******************************************/
    
    unsigned char calculated[MAGIC_20] = {};
    unsigned int ret = FIPS_incore_fingerprint(calculated, sizeof(calculated));
    FIPS_ASSERT(ret == MAGIC_20);
    
    if(ret != MAGIC_20)
    {
        // Failure - wipe it.
        // Default is 0x00. We use 0xFF to differentiate
        memset(calculated, 0xFF, sizeof(calculated));
    }
    
    NSMutableString* f2 = [NSMutableString stringWithCapacity:MAGIC_20*2 + 8];
    FIPS_ASSERT(f1 != nil);
    
    for(unsigned int j = 0; j < MAGIC_20; j++)
        [f2 appendFormat:@"%02x", calculated[j]];
    
    [m_calculatedLabel setText:f2];
    
    /******************************************/
    
    const int mode = FIPS_mode();
    const BOOL state = mode ? YES : NO;
    [m_modeSwitch setOn:state];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
