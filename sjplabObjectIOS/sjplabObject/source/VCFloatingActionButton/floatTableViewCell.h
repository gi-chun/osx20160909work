//
//  floatTableViewCell.h
//  floatingButtonTrial
//
//  Created by gclee on 26/03/15.
//  Copyright (c) 2015 gclee. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface floatTableViewCell : UITableViewCell
@property (weak, nonatomic) IBOutlet UIImageView *imgView;
@property (weak, nonatomic) IBOutlet UILabel *title;
@property (strong,nonatomic) UIView *overlay;
-(void)setTitle:(NSString*)txt andImage:(UIImage*)img;

@end
