//
//  CKIntroView.m
//  knbankmbr
//
//  Created by gclee on 2016. 3. 31..
//  Copyright © 2016년 knbank. All rights reserved.
//

#import "CKIntroView.h"

#define HEADVIEW_HEIGHT      100
#define LEFTVIEW_WIDTH       100
#define LEFTMARGIN_WIDTH     50

//-------------------------------

//-------------------------------






//-------------------------------

@interface CKIntroView() <CKIntroViewDelegate>
{
//    NSString *title;
//    NSString *linkUrl;
//    
//    UIImageView *containerView;
//    UIWebView *aWebview;
    UIView *backView;
    UIView *headerView;
    UIScrollView *leftVerticalView;
    UIScrollView *CenterHorizontalView;
    
    UIImageView *introView;
    UIWindow *mainWindow;
}

@end

@implementation CKIntroView

- (void)releaseItem
{
//    if (title) title = nil;
//    if (linkUrl) linkUrl = nil;
//    if (containerView) containerView = nil;
//    if (aWebview) [aWebview stopLoading], aWebview = nil;
}

- (void)removeFromSuperview
{
    for (UIView *subview in self.subviews) {
        [subview removeFromSuperview];
    }
    
    [super removeFromSuperview];
}

- (id)initWithFrame:(CGRect)frame
{
    if (self = [super initWithFrame:frame]) {
        
//        title = [aTitle copy];
//        
//        if (aLinkUrl) {
//            linkUrl = [aLinkUrl copy];
//            
//            [self initLayout];
//        }
    }
    [self initLayout];
    
    return self;
}

- (void)initLayout
{
//    [self setBackgroundColor:[UIColor clearColor]];
    [self setBackgroundColor:[[UIColor blackColor] colorWithAlphaComponent:0.6]];
    [self setOpaque:NO];
    
//    UIView *containerView;
//    UIView *headerView;
//    UIScrollView *leftVerticalView;
//    UIScrollView *CenterHorizontalView;
    
//    initWithFrame: CGRectMake(kScreenBoundsWidth-50, kScreenBoundsHeight-50, 50, 50)];
//    mainWindow = [UIApplication sharedApplication].keyWindow;
    
    backView = [[UIView alloc]initWithFrame:[UIScreen mainScreen].bounds];
    //backView = [[UIView alloc]initWithFrame:CGRectMake(50, 0, kScreenBoundsWidth-50, kScreenBoundsHeight)];
    backView.backgroundColor = [UIColor clearColor];
    backView.userInteractionEnabled = YES;
    backView.backgroundColor = [UIColor colorWithWhite:0 alpha:0.2];
    //backView.alpha = 0.2;
    
//    UITapGestureRecognizer *buttonTap = [[UITapGestureRecognizer alloc]initWithTarget:self action:@selector(handleTap:)];
//    buttonTap.cancelsTouchesInView = NO;
//    [backView addGestureRecognizer:buttonTap];
    [self addSubview:backView];
 
    //UIImage *backgroundImage = [[UIImage imageNamed:@"sample.jpg"] resizableImageWithCapInsets:UIEdgeInsetsMake(10, 10, 10, 10)];
    UIImage *backgroundImage = [UIImage imageNamed:@"sample.jpg"];
    
    UIImageView *contentView = [[UIImageView alloc] initWithFrame:CGRectMake(0, 0, kScreenBoundsWidth, kScreenBoundsHeight)];
    [contentView setUserInteractionEnabled:YES];
    [contentView setImage:backgroundImage];
    [backView addSubview:contentView];

    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(17, 0, kScreenBoundsWidth-42, 42)];
    [titleLabel setText:@"test test"];
    [titleLabel setFont:[UIFont boldSystemFontOfSize:15]];
    [titleLabel setTextColor:UIColorFromRGB(0x333333)];
    [titleLabel setBackgroundColor:[UIColor clearColor]];
    [backView addSubview:titleLabel];
    
    UIButton *closeButton = [UIButton buttonWithType:UIButtonTypeCustom];
    [closeButton setFrame:CGRectMake(50, 100, 100, 100)];
    [closeButton setImage:[UIImage imageNamed:@"google-icon.png"] forState:UIControlStateNormal];
    [closeButton addTarget:self action:@selector(handleButton) forControlEvents:UIControlEventTouchUpInside];
    [backView addSubview:closeButton];
    
    [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(handleButton) userInfo:@1 repeats:NO];
    
//    UIView *lineView = [[UIView alloc] initWithFrame:CGRectMake(2, 41, CGRectGetWidth(self.frame)-31, 1)];
//    [lineView setBackgroundColor:UIColorFromRGBA(0xafb0c2, 0.3f)];
//    [containerView addSubview:lineView];
    
//    aWebview = [[UIWebView alloc] initWithFrame:CGRectMake(2.5f, CGRectGetMaxY(lineView.frame), containerView.frame.size.width-5.f, 0)];
//    aWebview.delegate = self;
//    aWebview.clipsToBounds = NO;
//    aWebview.scalesPageToFit = YES;
//    aWebview.scrollView.scrollsToTop = NO;
//    [containerView addSubview:aWebview];
    
}

-(void)handleTap:(id)sender //close view
{
    [self.delegate touchIntroDissmisView];
}

-(void)handleButton //close view
{
    NSLog(@"intro close button click");
    [self.delegate touchIntroDissmisView];
}



@end
