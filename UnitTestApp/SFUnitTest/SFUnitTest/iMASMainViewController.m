//
//  iMASMainViewController.m
//  SFUnitTest
//
//  Created by Ganley, Gregg on 9/13/13.
//  Copyright (c) 2013 MITRE Corp. All rights reserved.
//

#import "iMASMainViewController.h"

@interface iMASMainViewController ()

@end

@implementation iMASMainViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - Flipside View

- (void)flipsideViewControllerDidFinish:(iMASFlipsideViewController *)controller
{
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)showInfo:(id)sender
{    
    iMASFlipsideViewController *controller = [[iMASFlipsideViewController alloc] initWithNibName:@"iMASFlipsideViewController" bundle:nil];
    controller.delegate = self;
    controller.modalTransitionStyle = UIModalTransitionStyleFlipHorizontal;
    [self presentViewController:controller animated:YES completion:nil];
}

@end
