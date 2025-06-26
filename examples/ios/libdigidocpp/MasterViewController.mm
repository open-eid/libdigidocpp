//
//  MasterViewController.m
//  libdigidocpp-ios
//
//  Created by Raul Metsma on 18/07/15.
//  Copyright (c) 2015 RIA. All rights reserved.
//

#import "AppDelegate.h"

#include <digidocpp/Container.h>
#include <digidocpp/DataFile.h>
#include <digidocpp/Signature.h>
#include <digidocpp/Exception.h>
#include "unzip.h"

#include <array>

@interface NSString (Digidoc)
+ (NSString*)stdstring:(const std::string&)str;
@end

@implementation NSString (Digidoc)
+ (NSString*)stdstring:(const std::string&)str {
    return str.empty() ? [NSString string] : @(str.c_str());
}

+ (NSString*)exception:(const digidoc::Exception&)e {
    NSString *r = [NSString stdstring:e.msg()];
    for(const digidoc::Exception &ex: e.causes())
        r = [NSString stringWithFormat:@"%@\n%@", r, [NSString exception:ex]];
    return r;
}

@end

@interface URLTableViewCell: UITableViewCell
@property (weak, nonatomic) IBOutlet UITextField *search;
@property (weak, nonatomic) IBOutlet UIButton *run;
@end

@implementation URLTableViewCell
@end

@interface MasterViewController : UITableViewController
@end

@implementation MasterViewController
#if TESTING
{
    NSMutableArray *result;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.contentInset = UIEdgeInsetsMake(20, 0, 0, 0);
    URLTableViewCell *urlView = [self.tableView dequeueReusableCellWithIdentifier:@"URL"];
    urlView.isAccessibilityElement = NO;
    urlView.accessibilityElements = @[urlView.search, urlView.run];
    self.tableView.tableHeaderView = urlView;
}

- (IBAction)runTest:(id)sender {
    URLTableViewCell *urlView = (URLTableViewCell *)self.tableView.tableHeaderView;
    [urlView.search endEditing:YES];
    NSURL *url = [NSURL URLWithString:urlView.search.text];
    [[NSURLSession.sharedSession downloadTaskWithURL:url completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
        unzFile open = unzOpen(location.path.UTF8String);
        if (!open)
            return;
        self->result = [[NSMutableArray alloc] init];
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"YYYY-MM-dd hh:mm:ss:SSS"];
        NSDictionary *r = @{
            @"version": [NSString stdstring:digidoc::version()],
            @"start": [formatter stringFromDate:NSDate.date],
            @"result": self->result
        };
        NSString *docPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        for(int pos = unzGoToFirstFile(open); pos == UNZ_OK; pos = unzGoToNextFile(open))
        {
            unz_file_info fileInfo;
            int unzResult = unzGetCurrentFileInfo(open, &fileInfo, nullptr, 0, nullptr, 0, nullptr, 0);
            if(unzResult != UNZ_OK)
                break;
            std::string fileNameTmp(fileInfo.size_filename, 0);
            unzResult = unzGetCurrentFileInfo(open, &fileInfo, fileNameTmp.data(), uLong(fileNameTmp.size()), nullptr, 0, nullptr, 0);
            if(unzResult != UNZ_OK)
                break;

            NSString *fileName = [NSString stdstring:fileNameTmp];
            NSString *file = [docPath stringByAppendingPathComponent:fileName];
            NSLog(@"%@", file);
            if ([fileName hasSuffix:@"asice"] || [fileName hasSuffix:@"sce"] ||
                [fileName hasSuffix:@"asics"] || [fileName hasSuffix:@"scs"] ||
                [fileName hasSuffix:@"bdoc"] || [fileName hasSuffix:@"ddoc"] ||
                [fileName hasSuffix:@"adoc"] || [fileName hasSuffix:@"edoc"] ||
                [fileName hasSuffix:@"pdf"]) {
                unzResult = unzOpenCurrentFile(open);
                if(unzResult != UNZ_OK)
                    break;

                int size = 0;
                std::array<char, 10240> buf{};
                NSMutableData *data = [[NSMutableData alloc] init];
                while((size = unzReadCurrentFile(open, buf.data(), buf.size())) > 0)
                    [data appendBytes:buf.data() length:size];
                unzResult = unzCloseCurrentFile(open);

                [data writeToFile:file atomically:YES];
                NSString *status = @"OK";
                NSString *diagnostics = @"";
                NSMutableArray *dataFiles = [[NSMutableArray alloc] init];
                try {
                    auto d = digidoc::Container::openPtr(file.UTF8String);
                    for (const digidoc::DataFile *f: d->dataFiles()) {
                        [dataFiles addObject:@{
                            @"f": [NSString stdstring:f->fileName()],
                            @"m": [NSString stdstring:f->mediaType()],
                            @"s": @(f->fileSize()),
                        }];
                    }
                    for (const digidoc::Signature *s: d->signatures())
                    {
                        digidoc::Signature::Validator v(s);
                        if (v.status() == digidoc::Signature::Validator::Invalid ||
                            v.status() == digidoc::Signature::Validator::Unknown)
                        {
                            status = @"NOT";
                            diagnostics = [NSString stdstring:v.diagnostics()];
                        }
                    }
                } catch(const digidoc::Exception &e) {
                    NSLog(@"Exception: %s", e.msg().c_str());
                    diagnostics = [NSString exception:e];
                    status = @"NOT";
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self->result addObject:@{@"f": fileName, @"s": status, @"d": diagnostics, @"t": [formatter stringFromDate:NSDate.date], @"c": dataFiles}];
                    [self.tableView reloadData];
                });
            }
        }

        if (self->result.count > 0) {
            NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
            request.HTTPMethod = @"PUT";
            [request setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
            request.HTTPBody = [NSData dataWithContentsOfFile:[docPath stringByAppendingPathComponent:@"libdigidocpp.log"]];
            [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
                NSLog(@"log upload response error: %@", error);
            }] resume];
            request.HTTPBody = [NSJSONSerialization dataWithJSONObject:r options:0 error:nil];
            [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            [request.HTTPBody writeToFile:[docPath stringByAppendingPathComponent:@"result.json"] atomically:NO];
            [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                NSLog(@"result upload response error: %@", error);
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self->result addObject:@{@"f": @"DONE", @"s": @""}];
                    [self.tableView reloadData];
                });
            }] resume];
        }
        [NSFileManager.defaultManager removeItemAtURL:location error:nil];
    }] resume];
}
#endif

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
#if TESTING
    if (result.count > 0) return 1;
#endif
    return 1 + (APP.doc ? APP.doc->signatures().size() : 0);
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case 0:
#if TESTING
            if (result.count > 0) return [result[result.count - 1][@"f"] isEqualToString:@"DONE"] ? 2 : 1;
#endif
            return (APP.doc ? APP.doc->dataFiles().size() : 0);
        default:
            return 3;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    switch (section)
    {
        case 0: return @"Data files";
        default: return [NSString stringWithFormat:@"Signature %ld", (long)section];
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"Cell" forIndexPath:indexPath];
    switch (indexPath.section) {
        case 0:
        {
#if TESTING
            if (result.count > 0) {
                switch (indexPath.row) {
                    case 0:
                    {
                        NSUInteger poscount = 0, count = result.count;
                        for (NSDictionary *r: result) {
                            if ([r[@"s"] isEqualToString:@"OK"])
                                ++poscount;
                            if ([r[@"f"] isEqualToString:@"DONE"])
                                --count;
                        }
                        cell.textLabel.text = [NSString stringWithFormat:@"File count: %lu", (unsigned long)count];
                        cell.detailTextLabel.text = [NSString stringWithFormat:@"Positive count: %lu", (unsigned long)poscount];
                        break;
                    }
                    default:
                        cell.textLabel.text = @"DONE";
                        cell.detailTextLabel.text = @"";
                        break;
                }
                break;
            }
#endif
            const digidoc::DataFile *data = APP.doc->dataFiles().at(indexPath.row);
            cell.textLabel.text = [NSString stdstring:data->fileName()];
            break;
        }
        default:
        {
            const digidoc::Signature *signature = APP.doc->signatures().at(indexPath.section - 1);
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = [NSString stdstring:signature->signedBy()];
                    break;
                case 1:
                    switch (digidoc::Signature::Validator(signature).status()) {
                        using enum digidoc::Signature::Validator::Status;
                    case Valid: cell.textLabel.text = @"Valid"; break;
                    case Warning: cell.textLabel.text = @"Warning"; break;
                    case NonQSCD: cell.textLabel.text = @"NonQSCD"; break;
                    case Test: cell.textLabel.text = @"Test"; break;
                    case Unknown: cell.textLabel.text = @"Unknown"; break;
                    case Invalid: cell.textLabel.text = @"Invalid"; break;
                    }
                    break;
                case 2:
                    cell.textLabel.text = [NSString stdstring:signature->trustedSigningTime()];
                default:
                    break;
            }
            break;
        }
    }
    return cell;
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return NO;
}

@end
