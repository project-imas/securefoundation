// ====================================================================
// Copyright (c) 2013 The OpenSSL Project. Rights for redistribution
// and usage in source and binary forms are granted according to the
// OpenSSL license.
// ====================================================================
//  fips_assert.c
//
//  Created by Tim Hudson, Steve Marquess, Jeffrey Walton on 1/5/13.
// ====================================================================

#include <stdlib.h>
#include <signal.h>

#include "fips_assert.h"

#if !defined(NDEBUG)

void NullTrapHandler(int unused) { UNUSED(unused); }

// No reason to return a value even though the function can fail.
// Its not like we can assert to alert of a failure.
int InstallDebugTrapHandler()
{
    // http://pubs.opengroup.org/onlinepubs/007908799/xsh/sigaction.html
    struct sigaction new_handler, old_handler;
    
    int ret = 0;
    
    do {
        ret = sigaction (SIGTRAP, NULL, &old_handler);
        if (ret != 0) break; // Failed
        
        // Don't step on another's handler
        if (old_handler.sa_handler != NULL) {
            ret = 0;
            break;
        }
        
        // Set up the structure to specify the null action.
        new_handler.sa_handler = &NullTrapHandler;
        new_handler.sa_flags = 0;
        
        ret = sigemptyset (&new_handler.sa_mask);
        if (ret != 0) break; // Failed
        
        // Install it
        ret = sigaction (SIGTRAP, &new_handler, NULL);
        if (ret != 0) break; // Failed
        
        ret = 0;
        
    } while(0);
    
    return ret;
}

#endif
