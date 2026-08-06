// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#import "DocumentViewModel.h"
#import "libdigidocpp-Swift.h"

#include <digidocpp/Conf.h>
#include <digidocpp/Container.h>
#include <digidocpp/DataFile.h>
#include <digidocpp/Exception.h>
#include <digidocpp/Signature.h>

namespace
{
class DigiDocConf final: public digidoc::ConfCurrent
{
public:
    int logLevel() const final
    {
        return 4;
    }

    std::string logFile() const final
    {
        return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/libdigidocpp.log"].UTF8String;
    }

    std::string TSLCache() const final
    {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
        NSString *libraryDirectory = paths[0];
        [NSFileManager.defaultManager createFileAtPath:[libraryDirectory stringByAppendingPathComponent:@"EE_T.xml"] contents:nil attributes:nil];
        return libraryDirectory.UTF8String;
    }
};

NSString *toNSString(const std::string &value)
{
    return value.empty() ? @"" : @(value.c_str());
}

NSError *digiDocError(NSInteger code, NSString *description)
{
    return [NSError errorWithDomain:@"ee.ria.libdigidocpp.app"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description}];
}

DigidocSignatureStatus validationStatus(digidoc::Signature::Validator::Status status)
{
    using enum digidoc::Signature::Validator::Status;
    switch (status)
    {
    case Valid: return DigidocSignatureStatusValid;
    case Warning: return DigidocSignatureStatusWarning;
    case NonQSCD: return DigidocSignatureStatusNonQSCD;
    case Test: return DigidocSignatureStatusTest;
    case Unknown: return DigidocSignatureStatusUnknown;
    case Invalid: return DigidocSignatureStatusInvalid;
    }
    return DigidocSignatureStatusUnknown;
}

NSString *exceptionMessage(const digidoc::Exception &exception)
{
    NSString *message = toNSString(exception.msg());
    for (const digidoc::Exception &cause: exception.causes())
        message = [NSString stringWithFormat:@"%@\n%@", message, exceptionMessage(cause)];
    return message;
}
}

@implementation DocumentViewModel

+ (BOOL)initializeLibraryWithError:(NSError *_Nullable *_Nullable)error
{
    try
    {
        static const bool loaded = [] {
            digidoc::Conf::init(new DigiDocConf);
            digidoc::initialize("libdigidocpp iOS");
            std::atexit(&digidoc::terminate);
            return true;
        }();
        return loaded ? YES : NO;
    }
    catch (const digidoc::Exception &exception)
    {
        if (error)
            *error = digiDocError(1, exceptionMessage(exception));
    }
    catch (const std::exception &exception)
    {
        if (error)
            *error = digiDocError(2, toNSString(exception.what()));
    }
    catch (...)
    {
        if (error)
            *error = digiDocError(3, @"Could not initialize libdigidocpp.");
    }
    return NO;
}

+ (NSString *)libraryVersion
{
    return toNSString(digidoc::version());
}

- (nullable instancetype)initWithPath:(NSString *)path
                                error:(NSError *_Nullable *_Nullable)error
{
    self = [super init];
    if (!self)
        return nil;

    NSMutableArray<NSString *> *dataFiles = [NSMutableArray array];
    NSMutableArray<SignatureInfo *> *signatures = [NSMutableArray array];

    try
    {
        auto container = digidoc::Container::openPtr(path.UTF8String);

        for (const digidoc::DataFile *dataFile: container->dataFiles())
            [dataFiles addObject:toNSString(dataFile->fileName())];

        NSInteger index = 0;
        for (const digidoc::Signature *signature: container->signatures())
        {
            [signatures addObject:[[SignatureInfo alloc]
                initWithId:index++
                signedBy:toNSString(signature->signedBy())
                status:validationStatus(digidoc::Signature::Validator(signature).status())
                signingTime:toNSString(signature->trustedSigningTime())]];
        }
    }
    catch (const digidoc::Exception &exception)
    {
        if (error)
            *error = digiDocError(1, exceptionMessage(exception));
        return nil;
    }
    catch (const std::exception &exception)
    {
        if (error)
            *error = digiDocError(2, toNSString(exception.what()));
        return nil;
    }
    catch (...)
    {
        if (error)
            *error = digiDocError(3, @"Could not open the document.");
        return nil;
    }

    _dataFiles = [dataFiles copy];
    _signatures = [signatures copy];
    return self;
}

@end
