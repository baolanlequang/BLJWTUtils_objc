//
//  ERRORJWT.h
//  DemoBLJWTUtilsObjC
//
//  Created by Bao Lan Le Quang on 2/24/17.
//  Copyright © 2017 baolan2005. All rights reserved.
//

typedef enum {
    JWT_VALID = 0,
    JWT_INVALID = 1,
    JWT_INVALID_HEADER = 2,
    JWT_INVALID_PAYLOAD = 3,
    JWT_INVALID_SIGNATURE = 4,
    JWT_EXP_DATE = 5
} ERRORJWT;
