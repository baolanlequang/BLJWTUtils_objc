//
//  ViewController.m
//  DemoBLJWTUtilsObjC
//
//  Created by Bao Lan Le Quang on 2/24/17.
//  Copyright © 2017 baolan2005. All rights reserved.
//

#import "ViewController.h"
#import "BLJWTUtils.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSDictionary *dataPayload = @{@"userid":@"1234", @"username":@"test", @"age":@"101"};
    NSError *error;
    NSString *encodedJWT = [[BLJWTUtils instance] encodeJWTAlgHS256WithDictionaryData:dataPayload secretKey:@"secret_abc" error:&error];
    if (error == nil) {
        NSLog(@"encodedJWT: %@", encodedJWT);
    }
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
