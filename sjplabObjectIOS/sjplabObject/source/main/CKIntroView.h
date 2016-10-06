//
//  CKIntroView.h
//  knbankmbr
//
//  Created by gclee on 2016. 3. 31..
//  Copyright © 2016년 knbank. All rights reserved.
//

#import <UIKit/UIKit.h>

@protocol CKIntroViewDelegate;

@interface CKIntroView : UIView

@property (nonatomic, weak) id<CKIntroViewDelegate> delegate;

- (id)initWithFrame:(CGRect)frame;
//- (void)releaseItem;
//- (id)initWithFrame:(CGRect)frame title:(NSString *)aTitle linkUrl:(NSString *)aLinkUrl;
//- (void)openUrl:(NSString *)url;
//- (void)stopLoading;
//- (void)setScrollTop;
//- (void)setScrollEnabled:(BOOL)isEnable;
//- (void)setShowsHorizontalScrollIndicator:(BOOL)isShow;
//- (void)setShowsVerticalScrollIndicator:(BOOL)isShow;

@end

@protocol CKIntroViewDelegate <NSObject>
@optional
- (void)touchIntroDissmisView;
//- (void)productExchangeView:(CPCommonLayerPopupView *)view isLoading:(NSNumber *)loading;
//- (void)productExchangeView:(CPCommonLayerPopupView *)view scrollViewDidScroll:(UIScrollView *)scrollView;
@end