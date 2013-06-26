// ====================================================================
// Copyright (c) 2013 The OpenSSL Project. Rights for redistribution
// and usage in source and binary forms are granted according to the
// OpenSSL license.
// ====================================================================
//  fips_assert.h
//
//  Created by Tim Hudson, Steve Marquess, Jeffrey Walton on 1/5/13.
// ====================================================================

#ifndef fips_assert_h
#define fips_assert_h

#include <stdlib.h>

#if !defined(NDEBUG)

#include <signal.h>

int InstallDebugTrapHandler();

#  define FIPS_ASSERT(x) { \
  if(!(x)) { \
    fprintf(stderr, "Assertion failed: %s(%d): %s\n", (char*)(__FILE__), (int)__LINE__, (char*)(__func__)); \
    raise(SIGTRAP); \
  } \
}

#else

#  define FIPS_ASSERT(x) UNUSED(x)

#endif

#endif // fips_assert.h
