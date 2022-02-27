//
//  MyInstallerPane.m
//  nimbus-pkg
//
//  Created by zahary on 16.08.21.
//

#import "MyInstallerPane.h"

@implementation MyInstallerPane

- (NSString *)title
{
    [self setNextEnabled: NO];
    return [[NSBundle bundleForClass: [self class]] localizedStringForKey: @"PaneTitle" value: nil table: nil];
}

- (void)comboBoxSelectionDidChange:(NSNotification *)notification{
    self.NetworkChosen = YES;
    self.ChosenNetwork = self.comboBox.intValue;
    [self isInputValid];
}

- (void)controlTextDidChange:(NSNotification *)obj {
    NSURL *url = [NSURL URLWithString: self.EthField.stringValue];
    if (url && url.scheme && url.host) {
        self.EthValid = YES;
    } else {
        self.EthValid = NO;
    }
    [self isInputValid];
}

- (void)isInputValid {
    if(self.NetworkChosen && self.EthValid) {
        [self setNextEnabled: YES];
    } else{
        [self setNextEnabled: NO];
    }
}

- (BOOL)shouldExitPane:(InstallerSectionDirection)dir {
    [self.comboBox.intValue == 1 ? @"prater" : @"pyrmont"
        writeToFile: [NSString stringWithFormat: @"%@%@", @"/tmp", @"/nimbus.server.config"]
        atomically: YES
        encoding: NSUTF8StringEncoding
        error: nil];

    [self.EthField.stringValue
        writeToFile: [NSString stringWithFormat: @"%@%@", @"/tmp", @"/nimbus.eth.config"]
        atomically: YES
        encoding: NSUTF8StringEncoding
        error: nil];

    [self.startServiceCheckbox.state ? @"0" : @"1"
        writeToFile: [NSString stringWithFormat:@"%@%@", @"/tmp", @"/nimbus.launch.config"]
        atomically: YES
        encoding: NSUTF8StringEncoding
        error: nil];

    return YES;
}

@end

