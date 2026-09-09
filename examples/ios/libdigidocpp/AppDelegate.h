// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#import <UIKit/UIKit.h>

namespace digidoc { class Container; }

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (assign, nonatomic) digidoc::Container *doc;

@end

#define APP ((AppDelegate*)UIApplication.sharedApplication.delegate)
