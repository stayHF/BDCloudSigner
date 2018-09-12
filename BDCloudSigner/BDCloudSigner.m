/*
 * Copyright (c) 2017 Baidu.com, Inc. All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

#import "BDCloudSigner.h"
#import <CommonCrypto/CommonHMAC.h>

@interface BDCloudSignerUtil : NSObject

/**
 Validate whether the string is empty.
 Define empty: nil, not NSString class, or length is zero.

 @param string The string.
 @return If empty, return YES. Otherwise, return NO.
 */
+ (BOOL)isEmptyString:(NSString*)string;

/**
 Convert NSDate to ISO8601 format：yyyy-MM-dd'T'HH:mm:ss'Z'.

 @param date date.
 @return Date string in ISO8601 format.
 */
+ (NSString*)dateEncodeISO8601:(NSDate*)date;

/**
 SHA256 HMAC. The length of the output string is 64.

 @param key SecretKey.
 @param message The message to be HMAC.
 @return Output string.
 */
+ (NSString*)hmac:(NSString*)key message:(NSString*)message;

/**
 Encode URI. Character in [alpha, digit, '-', '.', '_', '~'] will not be encode.
 If param exclude is set to YES, the slash will be reserved.
 According document: https://tools.ietf.org/html/rfc3986#section-2.3

 @param uri URI.
 @param exclude Whether exclude slash.
 @return Encoded URI.
 */
+ (NSString*)uriEncode:(NSString*)uri excludeSlash:(BOOL)exclude;

/**
 Encode Http queries. The process is as follows:
    1.foreach key and value:
        1) if the key is an empty string, skip 2) 3) 4);
        2) Encode the key and value;
        3) Concat URI encoded key and value with sign : "key=value";
        4) Add the concat string into array;
    2.Sort arry by ascending;
    3.Join each string in the array with '&';

 @param items HTTP queries dictionary.
 @return Encoded query string.
 */
+ (NSString*)queryEncode:(NSArray<NSURLQueryItem*>*)items;

/**
 Encode Http headers. The process is as follows:
    1.foreach key and value:
        1) Trim the value, if the trimmed value is an empty string, skip 2) 3) 4) 5);
        2) Transform key to lower case;
        3) Encode the transformed key and trimmed value;
        4) Concat URI encoded key and value with colon : "key:value";
        5) Add the concat string into array;
    2.Sort arry by ascending;
    3.Join each string in the array with '\n';

 @param headers HTTP Header dictionary.
 @return Encoded header string.
 */
+ (NSString*)headerEncode:(NSDictionary<NSString*, NSString*>*)headers;
@end

@implementation BDCloudSignerUtil

+ (BOOL)isEmptyString:(NSString*)string {
    if (!string) {
        return YES;
    }

    if (![string isKindOfClass:[NSString class]]) {
        return YES;
    }

    if (string.length == 0) {
        return YES;
    }

    return NO;
}

+ (NSString*)dateEncodeISO8601:(NSDate*)date {
    static NSDateFormatter* formater = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        formater = [[NSDateFormatter alloc] init];
        formater.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        formater.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US"];
        [formater setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    });

    return [formater stringFromDate:date];
}

+ (NSString*)hmac:(NSString*)key message:(NSString*)message {
    if ([self isEmptyString:key]
        || [self isEmptyString:message]) {
        return nil;
    }

    // hmac
    const char* keyBuffer = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char* msgBuffer = [message cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char outBuffer[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyBuffer, strlen(keyBuffer), msgBuffer, strlen(msgBuffer), outBuffer);

    // format to hex string
    NSMutableString* result = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        [result appendFormat:@"%02x", outBuffer[i]];
    }

    return result;
}

+ (NSString*)uriEncode:(NSString*)url excludeSlash:(BOOL)exclude {
    if ([self isEmptyString:url]) {
        return @"";
    }

    static NSMutableCharacterSet* set;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        set = [NSMutableCharacterSet alphanumericCharacterSet];
        [set addCharactersInString:@"-._~"];
    });

    NSString* ret = [url stringByAddingPercentEncodingWithAllowedCharacters:set];
    if (!exclude) {
        return ret;
    }

    return [ret stringByReplacingOccurrencesOfString:@"%2F" withString:@"/"];
}

+ (NSString*)queryEncode:(NSArray<NSURLQueryItem*>*)items {
    NSMutableArray* encoding = [NSMutableArray array];
    for (NSURLQueryItem* item in items) {
        if ([self isEmptyString:item.name]) {
            continue;
        }

        NSString* name = item.name;
        NSString* value = item.value;
        name = [self uriEncode:name excludeSlash:NO];
        value = [self uriEncode:value excludeSlash:NO];
        NSString* query = [NSString stringWithFormat:@"%@=%@", name, value];
        [encoding addObject:query];
    }

    NSArray<NSString*>* sortedQueries = [encoding sortedArrayUsingSelector:@selector(compare:)];
    return [sortedQueries componentsJoinedByString:@"&"];
}

+ (NSString*)headerEncode:(NSDictionary<NSString*, NSString*>*)headers {
    NSMutableArray* encoding = [NSMutableArray array];
    for (__strong NSString* name in headers.allKeys) {
        NSString* value = [headers objectForKey:name];

        // trim
        value = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

        // skip empty value
        if ([self isEmptyString:value]) {
            continue;
        }

        // lowercase
        name = [name lowercaseString];

        // URI encoding
        name = [self uriEncode:name excludeSlash:NO];
        value = [self uriEncode:value excludeSlash:NO];

        // concat
        NSString* query = [NSString stringWithFormat:@"%@:%@", name, value];
        [encoding addObject:query];
    }

    // sort
    NSArray<NSString*>* sortedQueries = [encoding sortedArrayUsingSelector:@selector(compare:)];
    return [sortedQueries componentsJoinedByString:@"\n"];
}

@end

#pragma mark - credentials
@implementation BDCloudCredentials
@end

@implementation BDCloudSTSCredentials
@end

#pragma mark - signers

@implementation BDCloudAKSKSigner
@synthesize expiredTimeInSeconds = _expiredTimeInSeconds;
@synthesize credentials = _credentials;

-(instancetype)initWithCredentials:(BDCloudCredentials*)credentials {
    if (self = [super init]) {
        _expiredTimeInSeconds = 1800;
        _credentials = credentials;
    }
    return self;
}

- (BOOL)sign:(NSMutableURLRequest*)request {
    if (![self check:request]) {
        return NO;
    }

    NSURLComponents* components = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];

    // automatic set Host header field.
    NSString* host = components.host;
    if (components.port) {
        host = [NSString stringWithFormat:@"%@:%zd", host, components.port.integerValue];
    }
    [request setValue:host forHTTPHeaderField:@"Host"];

    NSString* canonicalURI = [self generalCanonicalURI:components.path];
    NSString* canonicalQuery = [self generalCanonicalQuery:components.queryItems];
    NSString* canonicalHeaders = [self generalCanonicalHeader:request];

    NSArray* signComponents = @[
        request.HTTPMethod,
        canonicalURI,
        canonicalQuery,
        canonicalHeaders,
    ];
    NSString* canonicalRequest = [signComponents componentsJoinedByString:@"\n"];

    NSString* authPrefix = [self generalAuthStringPrefix:request];
    NSString* signingKey = [BDCloudSignerUtil hmac:self.credentials.secretKey message:authPrefix];
    NSString* signature = [BDCloudSignerUtil hmac:signingKey message:canonicalRequest];

    signComponents = @[
        authPrefix,
        @"",
        signature
    ];

    NSString* authorization = [signComponents componentsJoinedByString:@"/"];
    [request setValue:authorization forHTTPHeaderField:@"Authorization"];

    return YES;
}

- (BOOL)check:(NSMutableURLRequest*)request {
    if (!request) {
        return NO;
    }

    if ([BDCloudSignerUtil isEmptyString:self.credentials.accessKey]
        || [BDCloudSignerUtil isEmptyString:self.credentials.secretKey]) {
        return NO;
    }

    return YES;
}

- (NSString*)generalCanonicalURI:(NSString*)path {
    return [BDCloudSignerUtil uriEncode:path excludeSlash:YES];
}

- (NSString*)generalCanonicalQuery:(NSArray<NSURLQueryItem*>*)items {
    return [BDCloudSignerUtil queryEncode:items];
}

- (NSString*)generalCanonicalHeader:(NSMutableURLRequest*)request {
    NSDictionary<NSString*, NSString*>* headers = request.allHTTPHeaderFields;

    NSArray<NSString*>* defaultHeaders = @[
        @"Host",
        @"Content-Length",
        @"Content-Type",
        @"Content-MD5"
    ];

    NSString* lowerCaseHeader;
    NSMutableDictionary<NSString*, NSString*>* signHeaders = [NSMutableDictionary dictionary];

    for (NSString* key in headers.allKeys) {
        lowerCaseHeader = key.lowercaseString;
        if ([lowerCaseHeader hasPrefix:@"x-bce-"] || [defaultHeaders containsObject:key]) {
            NSString* value = [headers objectForKey:key];
            [signHeaders setObject:value forKey:key];
        }
    }

    return [BDCloudSignerUtil headerEncode:signHeaders];
}

- (NSString*)generalAuthStringPrefix:(NSMutableURLRequest*)request {
    NSString* timestamp = [BDCloudSignerUtil dateEncodeISO8601:[NSDate date]];
    NSArray* components = @[
        @"bce-auth-v1",
        self.credentials.accessKey,
        timestamp,
        @(self.expiredTimeInSeconds)
    ];
    return [components componentsJoinedByString:@"/"];
}

@end

@implementation BDCloudSTSSigner
- (BOOL)sign:(NSMutableURLRequest*)request {
    if (![self.credentials isKindOfClass:[BDCloudSTSCredentials class]]) {
        return NO;
    }

    BDCloudSTSCredentials* credentials = (BDCloudSTSCredentials*)self.credentials;
    if ([BDCloudSignerUtil isEmptyString:credentials.sessionToken]) {
        return NO;
    }

    [request setValue:credentials.sessionToken forHTTPHeaderField:@"x-bce-security-token"];
    return [super sign:request];
}
@end
