//
//  MasterViewController.m
//  libdigidocpp-ios
//
//  Created by Raul Metsma on 18/07/15.
//  Copyright (c) 2015 RIA. All rights reserved.
//

#import "MasterViewController.h"
#import "DetailViewController.h"

#include <digidocpp/Container.h>
#include <digidocpp/DataFile.h>
#include <digidocpp/Signature.h>
#include <digidocpp/Exception.h>
#include <digidocpp/crypto/X509Cert.h>

#include <sstream>

static void parseException(const digidoc::Exception &e)
{
    NSLog(@"%s", e.msg().c_str());
    for (const digidoc::Exception &ex : e.causes()) {
        parseException(ex);
    }
}

@interface MasterViewController () {
    digidoc::Container *doc;
}

@end

@implementation MasterViewController

- (void)awakeFromNib {
    [super awakeFromNib];
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad) {
        self.clearsSelectionOnViewWillAppear = NO;
        self.preferredContentSize = CGSizeMake(320.0, 600.0);
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    try {
        NSString *path = [[NSBundle mainBundle] pathForResource:@"test" ofType:@"bdoc"];
        doc = digidoc::Container::open(path.UTF8String);
    } catch(const digidoc::Exception &e) {
        NSLog(@"%s", e.msg().c_str());
    }
}

#pragma mark - Segues

/*- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if ([[segue identifier] isEqualToString:@"showDetail"]) {
        NSIndexPath *indexPath = [self.tableView indexPathForSelectedRow];
        NSDate *object = self.objects[indexPath.row];
        DetailViewController *controller = (DetailViewController *)[[segue destinationViewController] topViewController];
        [controller setDetailItem:object];
        controller.navigationItem.leftBarButtonItem = self.splitViewController.displayModeButtonItem;
        controller.navigationItem.leftItemsSupplementBackButton = YES;
    }
}*/

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1 + doc->signatures().size();
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case 0:
            return doc->dataFiles().size();

        default:
            return 2;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    switch (section)
    {
        case 0:
            return @"Data files";

        default:
            return [NSString stringWithFormat:@"Signature %ld", (long)section] ;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"Cell" forIndexPath:indexPath];
    switch (indexPath.section) {
        case 0:
        {
            const digidoc::DataFile *data = doc->dataFiles().at(indexPath.row);
            cell.textLabel.text = [NSString stringWithUTF8String:data->fileName().c_str()];
            break;
        }
        default:
        {
            digidoc::Signature *signature = doc->signatures().at(indexPath.section - 1);
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = [NSString stringWithUTF8String:signature->signingCertificate().subjectName("CN").c_str()];
                    break;
                case 1:
                    switch (digidoc::Signature::Validator(signature).status()) {
                    case digidoc::Signature::Validator::Valid: cell.textLabel.text = @"Valid"; break;
                    case digidoc::Signature::Validator::Warning: cell.textLabel.text = @"Warning"; break;
                    case digidoc::Signature::Validator::NonQSCD: cell.textLabel.text = @"NonQSCD"; break;
                    case digidoc::Signature::Validator::Test: cell.textLabel.text = @"Test"; break;
                    case digidoc::Signature::Validator::Unknown: cell.textLabel.text = @"Unknown"; break;
                    case digidoc::Signature::Validator::Invalid: cell.textLabel.text = @"Invalid"; break;
                    }
                    break;
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
