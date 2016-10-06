//
//  CPTouchActionView.m
//
//
//  Created by gclee on 2015. 6. 17..
//  Copyright (c) 2015년 gclee. All rights reserved.
//

#import "CPTouchActionView.h"
#import "NSString+URLEncodedString.h"
#import "AppDelegate.h"

@implementation CPTouchActionView


- (void)setTouchEffect:(BOOL)isTouch
{
	if (isTouch)	self.backgroundColor = UIColorFromRGBA(0x000000, 0.3);
	else			self.backgroundColor = [UIColor clearColor];
}

- (void)onTouchAction
{
	if (self.actionType == CPButtonActionTypeOpenSubview) {
		NSString *url = (NSString *)self.actionItem;
		
		if (url && [[url trim] length] > 0) {
//			AppDelegate *app = (AppDelegate *)[[UIApplication sharedApplication] delegate];
//			CPHomeViewController *homeViewController = app.homeViewController;
//			
//            if ([homeViewController respondsToSelector:@selector(openWebViewControllerWithUrl:animated:)]) {
//                //Exception URL은 풀스크린으로 보여줌
//                BOOL isException = [CPCommonInfo isExceptionalUrl:url];
//                [homeViewController openWebViewControllerWithUrl:[url trim] animated:!isException];
//            }
		}
	}
	else if (self.actionType == CPButtonActionTypeOpenPupup) {
		
		NSDictionary *item = (NSDictionary *)self.actionItem;
		
		NSString *linkUrl = item[@"openPopupUrl"];
		NSString *popupTitle = (item[@"popupTitle"] ? item[@"popupTitle"] : @"신상보기");
		
		NSMutableDictionary *param = [NSMutableDictionary dictionary];
		[param setObject:@"insetzero" forKey:@"controls"];
		[param setObject:@"1" forKey:@"showTitle"];
		[param setObject:popupTitle forKey:@"title"];
		[param setObject:linkUrl forKey:@"url"];
		
//		AppDelegate *app = (AppDelegate *)[[UIApplication sharedApplication] delegate];
//		CPHomeViewController *homeViewController = app.homeViewController;
//
//		if ([homeViewController respondsToSelector:@selector(openPopupBrowserView:)]) {
//			[homeViewController openPopupBrowserView:param];
//		}
	}
    
}

#pragma touch event
- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event
{
	[self setTouchEffect:YES];
}

- (void)touchesMoved:(NSSet *)touches withEvent:(UIEvent *)event
{
}

- (void)touchesEnded:(NSSet *)touches withEvent:(UIEvent *)event
{
	[self setTouchEffect:NO];
	[self onTouchAction];
}

- (void)touchesCancelled:(NSSet *)touches withEvent:(UIEvent *)event
{
	[self setTouchEffect:NO];
}

@end


