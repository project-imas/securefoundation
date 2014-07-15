//
//  Shred.h
//  shred-files
//
//  Created by Black, Gavin S. on 5/22/14.
//  Copyright (c) 2014 Black, Gavin S. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>


extern inline void shred(NSString* path, int size, int passes, BOOL addEOF);

extern inline void shredHelper(NSFileHandle *handle, int size, int subsize);

extern inline void* dlVolatileOpen(NSString* path);

extern inline void dlVolatileClose(void* handle);


