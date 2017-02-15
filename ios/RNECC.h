//
//  RNECC.h
//
//  Created by Mark Vayngrib on 12/24/15.
//  Copyright © 2015 Tradle, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

@interface RNECC : NSObject <RCTBridgeModule>

- (NSString *) toPublicIdentifier:(NSString *)privIdentifier;
- (NSData *) getPublicKeyDataByLabel:(NSString *)label;
- (SecKeyRef) getPublicKeyRef:(NSString *)base64pub;
- (SecKeyRef) getPrivateKeyRef:(NSString *)serviceID pub:(NSString *)base64pub status:(OSStatus *)status;
- (OSStatus) tagKeyWithLabel:(NSString*)label tag:(NSString*)tag;
- (NSString *) uuidString;
- (NSData *)sign:(nonnull NSDictionary*)options errMsg:(NSString **) errMsg;
- (BOOL) verify:(NSString *)base64pub hash:(NSData *)hash sig:(NSData *)sig errMsg:(NSString **)errMsg;
@end
