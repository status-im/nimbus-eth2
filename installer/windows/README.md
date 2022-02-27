This directory contains a set of files used for building a MSI Windows
installation package for the Nimbus beacon node.

To build the package, you'll need WiX Toolset (V3.11.2 or later):
https://wixtoolset.org/releases/

Make sure the WiX build tools are in your PATH and run `make nimbus-msi`
from the root of this repo. 

WixEdit is recommended for editing the installer dialogs:
https://wixedit.github.io/
