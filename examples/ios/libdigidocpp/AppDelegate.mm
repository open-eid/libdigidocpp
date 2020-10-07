//
//  AppDelegate.m
//  libdigidocpp-ios
//
//  Created by Raul Metsma on 18/07/15.
//  Copyright (c) 2015 RIA. All rights reserved.
//

#import "AppDelegate.h"

#include <digidocpp/Conf.h>
#include <digidocpp/Container.h>
#include <digidocpp/Exception.h>
#include <digidocpp/crypto/X509Cert.h>

class DigiDocConf: public digidoc::ConfCurrent
{
public:
    int logLevel() const override
    {
        return 4;
    }

    std::string logFile() const override
    {
        return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/libdigidocpp.log"].UTF8String;
    }

    std::string TSLCache() const override
    {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
        NSString *libraryDirectory = paths[0];
        [NSFileManager.defaultManager createFileAtPath:[libraryDirectory stringByAppendingPathComponent:@"EE_T.xml"] contents:nil attributes:nil];
        return libraryDirectory.UTF8String;
    }

    std::string xsdPath() const override
    {
        return [NSBundle.mainBundle pathForResource:@"schema" ofType:NSString.string].UTF8String;
    }
};

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    try {
        digidoc::Conf::init(new DigiDocConf);
        digidoc::initialize("libdigidocpp iOS");
        // Skip URL will be opened in application: openURL:
        if (launchOptions[UIApplicationLaunchOptionsURLKey] == nil) {
            [self openFile:[NSBundle.mainBundle pathForResource:@"test" ofType:@"bdoc"] copy:YES];
        }
    } catch(const digidoc::Exception &e) {
        NSLog(@"%s", e.msg().c_str());
    }
    return YES;
}

- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    delete self.doc;
    self.doc = nullptr;
    BOOL result = [self openFile:url.path copy:YES];
    UITableViewController *master = (UITableViewController*)self.window.rootViewController;
    [master.tableView reloadData];
    return result;
}

- (BOOL)openFile:(NSString*)from copy:(BOOL)copy {
    try {
        NSArray *documentPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *path = [NSString stringWithFormat:@"%@/%@", documentPath.firstObject, from.lastPathComponent];
        NSError *error;
        [NSFileManager.defaultManager removeItemAtPath:path error:&error];
        if (error) {
            NSLog(@"Failed to remove file %@", error);
            error = nil;
        }
        if (copy)
            [NSFileManager.defaultManager copyItemAtPath:from toPath:path error:&error];
        else
            [NSFileManager.defaultManager moveItemAtPath:from toPath:path error:&error];
        if (error) {
            NSLog(@"Failed to copy/move file %@", error);
            return NO;
        }
        self.doc = digidoc::Container::open(path.UTF8String);
        return YES;
    } catch(const digidoc::Exception &e) {
        NSLog(@"%s", e.msg().c_str());
        return NO;
    }
}

- (void)applicationWillTerminate:(UIApplication *)application {
    delete self.doc;
    self.doc = nullptr;
    digidoc::terminate();
}

@end
