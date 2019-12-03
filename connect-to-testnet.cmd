@echo off

cd /D "%~dp0"

vendor/nimbus-build-system/vendor/Nim/bin/nim scripts/connect_to_testnet.nims %1

