// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SignatureInfo;

@interface DocumentViewModel : NSObject

@property (copy, nonatomic, readonly) NSArray<NSString *> *dataFiles;
@property (copy, nonatomic, readonly) NSArray<SignatureInfo *> *signatures;

+ (BOOL)initializeLibraryWithError:(NSError *_Nullable *_Nullable)error
    NS_SWIFT_NAME(initializeLibrary());
+ (NSString *)libraryVersion;

- (nullable instancetype)initWithPath:(NSString *)path
                                error:(NSError *_Nullable *_Nullable)error NS_SWIFT_NAME(init(path:));
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
