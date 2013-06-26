// ====================================================================
// Copyright (c) 2013 The OpenSSL Project. Rights for redistribution
// and usage in source and binary forms are granted according to the
// OpenSSL license.
// ====================================================================
//  AppDelegate.h
//
//  Created by Tim Hudson, Steve Marquess, Jeffrey Walton on 1/5/13.
// ====================================================================

#import <UIKit/UIKit.h>

@class ViewController;

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (strong, nonatomic) ViewController *viewController;

@end
