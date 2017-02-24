//
//  BLJWTUtils.h
//  DemoBLJWTUtilsObjC
//
//  Created by Bao Lan Le Quang on 2/24/17.
//  Copyright © 2017 baolan2005. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ERRORJWT.h"

@interface BLJWTUtils : NSObject

+ (instancetype)instance;

- (NSDictionary *)decondeJWTToken:(NSString *)token withSecretKey:(NSString *)secretKey error:(NSError **)error;
- (NSString *)encodeJWTAlgHS256WithDictionaryData:(NSDictionary *)dicData secretKey:(NSString *)secretKey error:(NSError **)error;
- (ERRORJWT)verifyJWTToken:(NSString *)token withSecretKey:(NSString *)secretKey;

@end
