// ====================================================================
// Copyright (c) 2013 The OpenSSL Project. Rights for redistribution
// and usage in source and binary forms are granted according to the
// OpenSSL license.
// ====================================================================
//  ViewController.h
//
//  Created by Tim Hudson, Steve Marquess, Jeffrey Walton on 1/5/13.
// ====================================================================

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController
{
    UILabel* m_dataLabel;
    UILabel* m_textLabel;
    UILabel* m_embeddedLabel;
    UILabel* m_calculatedLabel;
    
    UISwitch* m_modeSwitch;
    
    UIView* m_mainView;
}

-(IBAction) modeSwitched;

@property (nonatomic, retain) IBOutlet UILabel* m_dataLabel;
@property (nonatomic, retain) IBOutlet UILabel* m_textLabel;

@property (nonatomic, retain) IBOutlet UILabel* m_embeddedLabel;
@property (nonatomic, retain) IBOutlet UILabel* m_calculatedLabel;

@property (nonatomic, retain) IBOutlet UISwitch* m_modeSwitch;

@property (nonatomic, retain) IBOutlet UIView* m_mainView;

@end
