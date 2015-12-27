//
//  RNCryptoUtils.h
//  rnecc
//
//  Created by Mark Vayngrib on 12/24/15.
//  Copyright © 2015 Tradle, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <RCTBridgeModule.h>

@interface RNECC : NSObject <RCTBridgeModule>

extern NSString *const RNECCErrorDomain;

enum RNECCError
{
  RNECCNoError = 0,           // Never used
  RNECCInvalidInvocationError,// Invalid method invocation
  RNECCBadConfigError,        // Invalid configuration
  RNECCBadParamError,         // Invalid parameter was passed
  RNECCDuplicateKeyError,     // Attempt to create a key with the same attributes as an existing one
  RNECCOtherError,            // Description provided in userInfo
};

typedef enum RNECCError RNECCError;

- (NSString *) toPublicIdentifier:(NSString *)privIdentifier;
- (NSData *)getPublicKeyDataByLabel:(NSString *)label;
- (SecKeyRef)getKeyRef:(NSString *)tag;//
- (NSError *)genericError:(NSString *)errMsg;
- (NSError *)createError:(RNECCError)type msg:(NSString *)msg;
- (NSString *)keychainErrorToString:(OSStatus)error;
- (OSStatus) tagKeyWithLabel:(NSString*)label tag:(NSString*)tag;
- (NSString *)uuidString;

@end
