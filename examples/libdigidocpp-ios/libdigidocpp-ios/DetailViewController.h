//
//  DetailViewController.h
//  libdigidocpp-ios
//
//  Created by Raul Metsma on 18/07/15.
//  Copyright (c) 2015 RIA. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface DetailViewController : UIViewController

@property (strong, nonatomic) id detailItem;
@property (weak, nonatomic) IBOutlet UILabel *detailDescriptionLabel;

@end

