//
//  MyInstallerPane.h
//  nimbus-pkg
//
//  Created by zahary on 16.08.21.
//

#import <InstallerPlugins/InstallerPlugins.h>

@interface MyInstallerPane : InstallerPane
@property BOOL EthValid;
@property BOOL NetworkChosen;
@property int  ChosenNetwork;
@property (weak) IBOutlet NSComboBoxCell *comboBox;
@property (weak) IBOutlet NSTextField *EthField;
@property (weak) IBOutlet NSTextField *descriptionField;
@property (weak) IBOutlet NSButton *startServiceCheckbox;

@end
