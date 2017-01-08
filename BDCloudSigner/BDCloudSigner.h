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

#import <Foundation/Foundation.h>

/**
 Provides access to the Baidu Cloud credentials used for accessing Baidu Cloud services: access key and secret key.
 These credentials are used to securely sign requests to Baidu Cloud services.
 Used to initialize BDCloudAKSKSigner.
 */
@interface BDCloudCredentials : NSObject

/**
 The Baidu Cloud access key for this credentials object.
 */
@property(nonatomic, copy) NSString* accessKey;

/**
 The Baidu Cloud secret access key for this credentials object.
 */
@property(nonatomic, copy) NSString* secretKey;
@end

/**
 Most like BDCloudCredentials, but for temporary authorization.
 Used to initialize BDCloudSTSSigner.
 */
@interface BDCloudSTSCredentials : BDCloudCredentials

/**
 The Baidu Cloud session token for this credentials object.
 */
@property(nonatomic, copy) NSString* sessionToken;
@end

/**
 The common property and interface for signer.
 */
@protocol BDCloudSigner <NSObject>

/**
 The signature expire time range: abs(ServerTimestamp - signatureTimestamp) < expirationInSeconds.
 The default value is 1800.
 */
@property(nonatomic, assign) NSUInteger expiredTimeInSeconds;

/**
 The Baidu Cloud credentials used by the client to sign HTTP requests.
 */
@property(nonatomic, strong, readonly) BDCloudCredentials* credentials;

/**
 Constructs a signer from a credentials.
 Must pass correct object:
     * Constructs BDCloudAKSKSigner with BDCloudCredentials instance.
     * Constructs BDCloudSTSSigner with BDCloudSTSCredentials instance.

 @param credentials Baidu Cloud credentials.
 @return a signer.
 */
-(instancetype)initWithCredentials:(BDCloudCredentials*)credentials;

/**
 Signatures the given mutable HTTP request.

 @param request Mutable HTTP request.
 @return If the signature succeed, return YES. Otherwise, return NO.
 */
- (BOOL)sign:(NSMutableURLRequest*)request;
@end

/**
 The V1 implementation of Signer with the Baidu Cloud signing protocol.
 */
@interface BDCloudAKSKSigner : NSObject<BDCloudSigner>
@end

/**
 The V1 implementation of Signer with the Baidu Cloud STS signing protocol.
 */
@interface BDCloudSTSSigner : BDCloudAKSKSigner
@end
