//
//  BLJWTUtils.m
//  DemoBLJWTUtilsObjC
//
//  Created by Bao Lan Le Quang on 2/24/17.
//  Copyright © 2017 baolan2005. All rights reserved.
//

#import "BLJWTUtils.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation BLJWTUtils

// init singleton
+ (instancetype)instance {
    static BLJWTUtils *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[BLJWTUtils alloc] init];
    });
    return sharedInstance;
}


- (NSString *)encodeJWTAlgHS256WithDictionaryData:(NSDictionary *)dicData secretKey:(NSString *)secretKey error:(NSError **)error {
    NSString *resultStr = nil;
    
    NSError *errorJSON;
    NSData *dataPayload = [NSJSONSerialization dataWithJSONObject:dicData options:NSJSONWritingPrettyPrinted error:&errorJSON];
    if (errorJSON) {
        *error = errorJSON;
    }
    else {
        NSString *jsonPayload = [[NSString alloc] initWithData:dataPayload encoding:NSUTF8StringEncoding];
        NSDictionary *dicHeader = [NSDictionary dictionaryWithObjectsAndKeys:@"HS256", @"alg", @"JWT", @"typ", nil];
        NSData *dataHeader = [NSJSONSerialization dataWithJSONObject:dicHeader options:NSJSONWritingPrettyPrinted error:nil];
        NSString *jsonHeader = [[NSString alloc] initWithData:dataHeader encoding:NSUTF8StringEncoding];
        NSString *base64Header = [self encodeBase64:jsonHeader];
        NSString *base64Payload = [self encodeBase64:jsonPayload];
        NSString *plainText = [NSString stringWithFormat:@"%@.%@", [self encodeBase64URL:base64Header], [self encodeBase64URL:base64Payload]];
        NSString *signatureStr = [self hashStringSHA256:plainText withKey:secretKey];
        resultStr = [NSString stringWithFormat:@"%@.%@", plainText, signatureStr];
    }
    return resultStr;
}

- (NSDictionary *)decondeJWTToken:(NSString *)token withSecretKey:(NSString *)secretKey error:(NSError *__autoreleasing *)error {
    NSDictionary *resultDic = nil;
    ERRORJWT errorJWT = [self verifyJWTToken:token withSecretKey:secretKey];
    switch (errorJWT) {
        case JWT_INVALID: {
            NSMutableDictionary* details = [NSMutableDictionary dictionary];
            [details setValue:@"JWT_INVALID" forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:@"JWT" code:2001 userInfo:details];
        }
            break;
        case JWT_INVALID_HEADER: {
            NSMutableDictionary* details = [NSMutableDictionary dictionary];
            [details setValue:@"JWT_INVALID_HEADER" forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:@"JWT" code:2002 userInfo:details];
        }
            break;
        case JWT_INVALID_PAYLOAD: {
            NSMutableDictionary* details = [NSMutableDictionary dictionary];
            [details setValue:@"JWT_INVALID_PAYLOAD" forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:@"JWT" code:2003 userInfo:details];
        }
            break;
        case JWT_INVALID_SIGNATURE: {
            NSMutableDictionary* details = [NSMutableDictionary dictionary];
            [details setValue:@"JWT_INVALID_SIGNATURE" forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:@"JWT" code:2004 userInfo:details];
        }
            break;
        case JWT_EXP_DATE: {
            NSMutableDictionary* details = [NSMutableDictionary dictionary];
            [details setValue:@"JWT_EXP_DATE" forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:@"JWT" code:2005 userInfo:details];
        }
            break;
        default: {
            NSArray *arrTokenItem = [token componentsSeparatedByString:@"."];
            NSString *payload = [arrTokenItem objectAtIndex:1];
            NSString *payloadContent = [self decodeBase64:payload];
            NSData *dataPayload = [payloadContent dataUsingEncoding:NSUTF8StringEncoding];
            resultDic = [NSJSONSerialization JSONObjectWithData:dataPayload options:kNilOptions error:nil];
        }
            break;
    }
    
    
    return resultDic;
}

- (NSString *)encodeBase64:(NSString *)inputString {
    NSData *encodeData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [encodeData base64EncodedStringWithOptions:0];
    return base64String;
}

- (NSString *)decodeBase64:(NSString *)inputString {
    int needPadding = inputString.length % 4;
    if (needPadding > 0) {
        needPadding = 4 - needPadding;
        inputString = [inputString stringByPaddingToLength:inputString.length+needPadding withString:@"=" startingAtIndex:0];
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:inputString options:0];
    NSString *decodedString = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    return decodedString;
}

- (NSString *)hashStringSHA256:(NSString *)plainText withKey:(NSString *)key {
    const char *cKey  = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [plainText cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    
    NSData *hashedData = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *base64String = [self base64forData:hashedData];
    
    return [self encodeBase64URL:base64String];
    
}

- (NSString*)base64forData:(NSData*)theData {
    const uint8_t* input = (const uint8_t*)[theData bytes];
    NSInteger length = [theData length];
    
    static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    
    NSMutableData* data = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;
    
    NSInteger i;
    for (i=0; i < length; i += 3) {
        NSInteger value = 0;
        NSInteger j;
        for (j = i; j < (i + 3); j++) {
            value <<= 8;
            
            if (j < length) {  value |= (0xFF & input[j]);  }  }  NSInteger theIndex = (i / 3) * 4;  output[theIndex + 0] = table[(value >> 18) & 0x3F];
        output[theIndex + 1] = table[(value >> 12) & 0x3F];
        output[theIndex + 2] = (i + 1) < length ? table[(value >> 6) & 0x3F] : '=';
        output[theIndex + 3] = (i + 2) < length ? table[(value >> 0) & 0x3F] : '=';
    }
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
}

- (NSString *)encodeBase64URL:(NSString *)base64 {
    NSString *resultStr = [base64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    resultStr = [resultStr stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    resultStr = [resultStr stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return resultStr;
}

- (NSString *)decodeBase64URL:(NSString *)base64 {
    NSString *resultStr = [base64 stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    resultStr = [base64 stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    return  resultStr;
}

- (ERRORJWT)verifyJWTToken:(NSString *)token withSecretKey:(NSString *)secretKey {
    NSArray *arrTokenItem = [token componentsSeparatedByString:@"."];
    if (arrTokenItem.count != 3) {
        return JWT_INVALID;
    }
    
    NSString *header = [arrTokenItem objectAtIndex:0];
    NSString *payload = [arrTokenItem objectAtIndex:1];
    NSString *signature = [arrTokenItem objectAtIndex:2];
    
    NSError *errorValidateJSON;
    NSString *headerContent = [self decodeBase64:header];
    NSString *payloadContent = [self decodeBase64:payload];
    NSData *dataHeader = [headerContent dataUsingEncoding:NSUTF8StringEncoding];
    NSData *dataPayload = [payloadContent dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *jsonHeader = [NSJSONSerialization JSONObjectWithData:dataHeader options:kNilOptions error:&errorValidateJSON];
    if (errorValidateJSON) {
        return JWT_INVALID_HEADER;
    }
    
    NSDictionary *jsonPayload = [NSJSONSerialization JSONObjectWithData:dataPayload options:kNilOptions error:&errorValidateJSON];
    if (errorValidateJSON) {
        return JWT_INVALID_PAYLOAD;
    }
    
    if (![jsonHeader objectForKey:@"typ"] || ![jsonHeader objectForKey:@"alg"]) {
        return JWT_INVALID_HEADER;
    }
    
    NSString *plainText = [NSString stringWithFormat:@"%@.%@", header, payload];
    
    NSString *hashedString = @"";
    
    NSString *algorithm = [[jsonHeader objectForKey:@"alg"] lowercaseString];
    
    if ([algorithm isEqualToString:@"hs256"]) {
        hashedString = [self hashStringSHA256:plainText withKey:secretKey];
    }
    
    
    if (![hashedString isEqualToString:signature]) {
        return JWT_INVALID_SIGNATURE;
    }
    
    if ([jsonPayload objectForKey:@"exp"]) {
        long expTime = [[jsonPayload objectForKey:@"exp"] longValue];
        NSDate *expDate = [NSDate dateWithTimeIntervalSince1970:expTime];
        NSDate *today = [NSDate date];
        if ([expDate compare:today] == NSOrderedAscending) {
            return JWT_EXP_DATE;
        }
    }
    
    return JWT_VALID;
}

@end
