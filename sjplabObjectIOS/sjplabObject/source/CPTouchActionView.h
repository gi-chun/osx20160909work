//
//  CPTouchActionView.h
//
//
//  Created by gclee on 2015. 6. 17..
//  Copyright (c) 2015년 gclee. All rights reserved.
//

#import <UIKit/UIKit.h>

typedef NS_ENUM(NSUInteger, CPButtonActionType){
	CPButtonActionTypeNone = 0,
	CPButtonActionTypeOpenSubview,
	CPButtonActionTypeOpenPupup
};

@protocol CPTouchActionViewDelegate;

@interface CPTouchActionView : UIView

@property (nonatomic, weak) id <CPTouchActionViewDelegate> delegate;
@property (nonatomic, assign) CPButtonActionType actionType;
@property (nonatomic, strong) id actionItem;
@property (nonatomic, strong) NSString *wiseLogCode;
@property (nonatomic, strong) NSArray *adClickItems;

@end


@protocol CPTouchActionViewDelegate <NSObject>
@optional
- (void)touchActionView:(CPTouchActionView *)view sendCategoryBest:(NSString *)url;
@end