//
//  AppDelegate.h
//  libdigidocpp-ios
//
//  Created by Raul Metsma on 18/07/15.
//  Copyright (c) 2015 RIA. All rights reserved.
//

#import <UIKit/UIKit.h>

namespace digidoc { class Container; }

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (assign, nonatomic) digidoc::Container *doc;

@end

#define APP ((AppDelegate*)UIApplication.sharedApplication.delegate)
