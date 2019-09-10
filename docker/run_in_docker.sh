#!/bin/bash

killall p2pd
rm -rf /tmp/*

beacon_node --nat:none $*

