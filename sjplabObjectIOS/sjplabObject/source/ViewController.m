//
//  ViewController.m
//  knbankmbr
//
//  Created by gclee on 2016. 2. 26..
//  Copyright © 2016년 knbank. All rights reserved.
//

#import "ViewController.h"
#import "MenuViewController.h"

typedef NS_ENUM(NSUInteger, MenuTags) {
    MenuLogin = 0,
    MenuTotal
};


@interface ViewController ()
{
    UIImage *screenshot;
}
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Do any additional setup after loading the view, typically from a nib.
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    UIView *buttonContainer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 80, 44)];
//    buttonContainer.backgroundColor = [UIColor clearColor];
//    UIToolbar *dummyBar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, 80, 44)];
//    
//    UIBarButtonItem *b1 = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(doSomething:)];
//    
//    UIBarButtonItem *b2 = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction target:self action:@selector(doSomething:)];
//    
//    NSArray *items = [[NSArray alloc] initWithObjects:b1, b2, nil];
//    
//    [dummyBar setItems:items];
//    
//    [buttonContainer addSubview:dummyBar];
    
    CGFloat xMargin = 30.0f;
    //////////////////////////////
    UIButton* buttonLeft = [UIButton buttonWithType:UIButtonTypeCustom];
    [buttonLeft setFrame:CGRectMake(xMargin, 10, 50, 50)];
    [buttonLeft setImage:[UIImage imageNamed:@"linkedin-icon.png"] forState:UIControlStateNormal];
    [buttonLeft setTitle:@"" forState:UIControlStateNormal];
    [buttonLeft addTarget:self action:@selector(doSomething:)forControlEvents:UIControlEventTouchUpInside];
    //[buttonLeft sizeToFit];
    //top,left bottom,right
    buttonLeft.imageEdgeInsets = UIEdgeInsetsMake(0, -10, 0, 10);
    [buttonLeft setTag:MenuLogin];
    
    UIBarButtonItem* barButtonItemLeft = [[UIBarButtonItem alloc] initWithCustomView:buttonLeft];
    self.navigationItem.leftBarButtonItem = barButtonItemLeft;
    
    UIButton* buttonRigth = [UIButton buttonWithType:UIButtonTypeCustom];
    [buttonRigth setFrame:CGRectMake(kScreenBoundsWidth-xMargin-50, 10, 50, 50)];
    [buttonRigth setImage:[UIImage imageNamed:@"fb-icon.png"] forState:UIControlStateNormal];
    [buttonRigth setTitle:@"" forState:UIControlStateNormal];
    [buttonRigth addTarget:self action:@selector(doSomething:)forControlEvents:UIControlEventTouchUpInside];
    //[buttonRigth sizeToFit];
    [buttonRigth setTag:MenuTotal];
    buttonRigth.imageEdgeInsets = UIEdgeInsetsMake(0, 10, 0, -10);
    UIBarButtonItem* barButtonItemRight = [[UIBarButtonItem alloc] initWithCustomView:buttonRigth];
    self.navigationItem.rightBarButtonItem = barButtonItemRight;
    
    /*
     leftButton.imageEdgeInsets = UIEdgeInsetsMake(-2, 0, 0, 0);
     */
    
    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //self.navigationItem.rightBarButtonItem = self.editButtonItem;
//    
//    UIBarButtonItem *shareItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction target:self action:nil];
//    
//    UIBarButtonItem *cameraItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCamera target:self action:nil];
//    
//    NSArray *actionButtonItems = @[shareItem, cameraItem];
//    self.navigationItem.rightBarButtonItems = actionButtonItems;
    
    // Uncomment to display a logo as the navigation bar title
    // self.navigationItem.titleView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"appcoda-logo.png"]];
    
    self.title = @"SJPLab ObjectTracking";
    
    UILabel *updateTimeLabel = [[UILabel alloc] initWithFrame:CGRectMake(100, 100, 100, 26)];
    [updateTimeLabel setBackgroundColor:[UIColor clearColor]];
    [updateTimeLabel setTextColor:UIColorFromRGB(0x000000)]; //0x8c6239
    [updateTimeLabel setFont:[UIFont fontWithName:@"Helvetica-Bold" size:13]];
    [updateTimeLabel setShadowColor:[UIColor whiteColor]];
    [updateTimeLabel setShadowOffset:CGSizeMake(0,2)];
    [updateTimeLabel setText:@"test test test gclee"];
    [updateTimeLabel setTextAlignment:NSTextAlignmentCenter];
    [self.view addSubview:updateTimeLabel];
    
    [self.view setBackgroundColor:UIColorFromRGBA(0xcccccc, 1.0f) ];
    
    
//gclee
//#define Appdelegate (((AppDelegate *)[[UIApplication sharedApplication] delegate]))
//#define Appdelegate ((AppDelegate *)[[UIApplication sharedApplication] delegate])
//                  ^----------------------parenthesis--------------------------^
    
//    UIView* roundedView = [[UIView alloc] initWithFrame: CGRectMake(kScreenBoundsWidth-50, kScreenBoundsHeight-50, 50, 50)];
//    roundedView.layer.cornerRadius = 5.0;
//    roundedView.layer.masksToBounds = YES;
//    
//    UIView* shadowView = [[UIView alloc] initWithFrame: CGRectMake(kScreenBoundsWidth-50, kScreenBoundsHeight-50, 50, 50)];
//    shadowView.layer.shadowColor = [UIColor blackColor].CGColor;
//    shadowView.layer.shadowRadius = 5.0;
//    shadowView.layer.shadowOffset = CGSizeMake(3.0, 3.0);
//    shadowView.layer.shadowOpacity = 1.0;
//    [shadowView addSubview: roundedView];
//    
//    //[[[UIApplication sharedApplication] keyWindow] addSubview:shadowView];
//    [self.view addSubview:shadowView];
    
    
//    ////////////////////////////////////////////////////////////////////////////////////////////////////
//    UIView *shadow = [[UIView alloc]init];
//    shadow.layer.cornerRadius = 5.0;
//    shadow.layer.shadowColor = [[UIColor redColor] CGColor];
//    shadow.layer.shadowOpacity = 1.0;
//    shadow.layer.shadowRadius = 10.0;
//    shadow.layer.shadowOffset = CGSizeMake(0.0f, -0.5f);
//    
//    UIButton *btnCompose = [UIButton buttonWithType:UIButtonTypeCustom];
//    [btnCompose setFrame:CGRectMake(kScreenBoundsWidth-80, kScreenBoundsHeight-80, 80, 80)];
//    //[btnCompose setUserInteractionEnabled:YES];
//    btnCompose.layer.cornerRadius = 30;
//    btnCompose.layer.masksToBounds = YES;
//    [btnCompose setImage:[UIImage imageNamed:@"location_icon"] forState:UIControlStateNormal];
//    [btnCompose addTarget:self action:@selector(btnCompose_click) forControlEvents:UIControlEventTouchUpInside];
//    [shadow addSubview:btnCompose];
//    [self.view addSubview:shadow];
//    
//    UIButton *btnEmpty = [UIButton buttonWithType:UIButtonTypeCustom];
//    [btnEmpty setFrame:CGRectMake(kScreenBoundsWidth-80, kScreenBoundsHeight-80, 80, 80)];
//    [btnEmpty setBackgroundColor:[UIColor clearColor]];
//    [btnEmpty addTarget:self action:@selector(btnCompose_click) forControlEvents:UIControlEventTouchUpInside];
//    [self.view addSubview:btnEmpty];
//    ///////////////////////////////////////////////////////////////////////////////////////////////////
    
    //    UIButton *bannerImageButton = [UIButton buttonWithType:UIButtonTypeCustom];
    //    [bannerImageButton setFrame:bannerImageView.frame];
    //    [bannerImageButton setBackgroundColor:[UIColor clearColor]];
    //    [bannerImageButton setBackgroundImage:[UIImage imageWithColor:UIColorFromRGB(0x000000)] forState:UIControlStateHighlighted];
    //    [bannerImageButton addTarget:self action:@selector(touchBannerButton) forControlEvents:UIControlEventTouchUpInside];
    //    [bannerImageButton setAlpha:0.3];
    //    [containerView addSubview:bannerImageButton];


    
    //return shadow;
}

#pragma mark - Selectors

- (void)btnCompose_click
{
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"알림"
                                                    message:@"설정 > 개인 정보 보호 > 연락처 정보를 활성화 해주세요."
                                                   delegate:self
                                          cancelButtonTitle:NSLocalizedString(@"Confirm", nil)
                                          otherButtonTitles:nil];
    [alert setDelegate:self];
    [alert show];
    
    NSLog(@"친구 등록 실패: 권한이 없음");
    
}

    
    
    /////////////////////////////////////////////////

//    - (UIView*)putView:(UIView*)view insideShadowWithColor:(UIColor*)color andRadius:(CGFloat)shadowRadius andOffset:(CGSize)shadowOffset andOpacity:(CGFloat)shadowOpacity
//    {
//        CGRect shadowFrame; // Modify this if needed
//        shadowFrame.size.width = 0.f;
//        shadowFrame.size.height = 0.f;
//        shadowFrame.origin.x = 0.f;
//        shadowFrame.origin.y = 0.f;
//        UIView * shadow = [[UIView alloc] initWithFrame:shadowFrame];
//        shadow.userInteractionEnabled = NO; // Modify this if needed
//        shadow.layer.shadowColor = color.CGColor;
//        shadow.layer.shadowOffset = shadowOffset;
//        shadow.layer.shadowRadius = shadowRadius;
//        shadow.layer.masksToBounds = NO;
//        shadow.clipsToBounds = NO;
//        shadow.layer.shadowOpacity = shadowOpacity;
//        [view.superview insertSubview:shadow belowSubview:view];
//        [shadow addSubview:view];
//        return shadow;
//    }
//}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

//+ (UIView *)genComposeButton:(UIViewController <UIComposeButtonDelegate> *)observer;
//{
//    UIView *shadow = [[UIView alloc]init];
//    shadow.layer.cornerRadius = 5.0;
//    shadow.layer.shadowColor = [[UIColor blackColor] CGColor];
//    shadow.layer.shadowOpacity = 1.0;
//    shadow.layer.shadowRadius = 10.0;
//    shadow.layer.shadowOffset = CGSizeMake(0.0f, -0.5f);
//    
//    UIButton *btnCompose = [[UIButton alloc]initWithFrame:CGRectMake(0, 0,60, 60)];
//    [btnCompose setUserInteractionEnabled:YES];
//    btnCompose.layer.cornerRadius = 30;
//    btnCompose.layer.masksToBounds = YES;
//    [btnCompose setImage:[UIImage imageNamed:@"60x60"] forState:UIControlStateNormal];
//    [btnCompose addTarget:observer action:@selector(btnCompose_click:) forControlEvents:UIControlEventTouchUpInside];
//    [shadow addSubview:btnCompose];
//    return shadow;
//}

#pragma mark - navigaton bar click
-(void)doSomething:(id)sender
{
    NSLog(@"Button pushed");
    
    UIButton *button = (UIButton *)sender;
    
    if(button.tag == MenuLogin){
        
        //gclee
        //[[NSNotificationCenter defaultCenter] postNotificationName:showMenuViewNotification object:self];
        [[NSNotificationCenter defaultCenter] postNotificationName:showLoadingViewNotification object:self];
        
    }
    else if(button.tag == MenuTotal){
        
        // gclee
        //[[NSNotificationCenter defaultCenter] postNotificationName:showMenuViewNotification object:self];
        [[NSNotificationCenter defaultCenter] postNotificationName:showCommonAlertViewNotification object:self];
    }
    
    
    //screenshot = [self screenShot];
//    [self createScreenshotwithComleteAction:^{
//        //self.definesPresentationContext = YES; //self is presenting view controller
//        MenuViewController *viewController = [[MenuViewController alloc] init];
//        [viewController setParentScreenShot:screenshot];
//        [viewController setDelegate:self];
//        //viewController.view.backgroundColor = [UIColor clearColor];
//        
//        //viewController.modalPresentationStyle = UIModalPresentationOverCurrentContext;
//        [self presentViewController:viewController animated:NO completion:nil];
//    }];
    
//    MYDetailViewController *dvc = [[MYDetailViewController alloc] initWithNibName:@"MYDetailViewController" bundle:[NSBundle mainBundle]];
//    [dvc setDelegate:self];
//    [dvc setModalTransitionStyle:UIModalTransitionStyleFlipHorizontal];
//    [self presentViewController:dvc animated:YES completion:nil];
}

#pragma mark - screenshot

-(UIImage*)screenShot{
    //UIGraphicsBeginImageContext(self.view.bounds.size);
    UIGraphicsBeginImageContext([UIScreen mainScreen].bounds.size);
    CGContextRef context = UIGraphicsGetCurrentContext();
    [self.view.layer renderInContext:context];
    UIImage * screenImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData * imageData = UIImageJPEGRepresentation(screenImage, SCREENSHOT_QUALITY);
    screenImage = [UIImage imageWithData:imageData];
    return screenImage;
}

-(UIImage*)screenShotOnScrolViewWithContentOffset:(CGPoint)offset{
//    UIGraphicsBeginImageContext(self.view.bounds.size);
    UIGraphicsBeginImageContext([UIScreen mainScreen].bounds.size);
    CGContextRef context = UIGraphicsGetCurrentContext();
    CGContextTranslateCTM(context, -offset.x, -offset.y);
    [self.view.layer renderInContext:context];
    UIImage * screenImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData * imageData = UIImageJPEGRepresentation(screenImage, SCREENSHOT_QUALITY);
    screenImage = [UIImage imageWithData:imageData];
    return screenImage;
}

-(void)createScreenshotwithComleteAction:(dispatch_block_t)completeAction{
    
    if ([self.view isKindOfClass:[UIScrollView class]]) {
        screenshot = [self screenShotOnScrolViewWithContentOffset:[(UIScrollView*)self.view contentOffset]];
    }else{
        screenshot = [self screenShot];
    }
    
    if (completeAction != nil) {
        completeAction();
    }
}




@end
