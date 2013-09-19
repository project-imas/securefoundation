//
//  iMASFlipsideViewController.h
//  SFUnitTest
//
//  Created by Ganley, Gregg on 9/13/13.
//  Copyright (c) 2013 MITRE Corp. All rights reserved.
//

#import <UIKit/UIKit.h>

@class iMASFlipsideViewController;

@protocol iMASFlipsideViewControllerDelegate
- (void)flipsideViewControllerDidFinish:(iMASFlipsideViewController *)controller;
@end

@interface iMASFlipsideViewController : UIViewController

@property (weak, nonatomic) id <iMASFlipsideViewControllerDelegate> delegate;

- (IBAction)done:(id)sender;

@end
