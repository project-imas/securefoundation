//
//  iMASFlipsideViewController.m
//  SFUnitTest
//
//  Created by Ganley, Gregg on 9/13/13.
//  Copyright (c) 2013 MITRE Corp. All rights reserved.
//

#import "iMASFlipsideViewController.h"

@interface iMASFlipsideViewController ()

@end

@implementation iMASFlipsideViewController

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

#pragma mark - Actions

- (IBAction)done:(id)sender
{
    [self.delegate flipsideViewControllerDidFinish:self];
}

@end
