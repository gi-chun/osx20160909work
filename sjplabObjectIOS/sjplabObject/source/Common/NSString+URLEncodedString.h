//
//  NSString+URLEncodedString.h
//  
//
//  Created by gclee on 2015. 6. 22..
//  Copyright (c) 2015년 gclee. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (URLEncodedString)

- (NSString *)URLEncodedStringWithEncoder:(CFStringEncoding)encoder;
- (NSString *)stringByInsertingComma;
- (int)indexOfBackwardSearch:(NSString *)text;
- (BOOL)compareToken:(NSString *)token;
- (BOOL)isHttpProtocol;
- (NSString *)trim;

@end
