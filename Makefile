# Copyright (c) 2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# we don't want an error here, so we can explain things later, in the sanity-checks target
-include ../../common.mk

ENV_SCRIPT := "../../env.sh"

TOOLS := beacon_node validator_keygen bench_bls_sig_agggregation state_sim
TOOLS_DIRS := beacon_chain benchmarks research

.PHONY: all sanity-checks deps test $(TOOLS) clean_eth2_network_simulation_files eth2_network_simulation clean-testnet0 testnet0-nocleaning testnet0 clean-testnet1 testnet1-nocleaning testnet1 clean

all: | $(TOOLS)

sanity-checks:
	@ [[ "$$PWD" =~ /vendor/nim-beacon-chain$ && -e ../../Makefile && -e ../../common.mk ]] || \
		{ echo "This Makefile can only be used from the corresponding Git submodule in the Nimbus repository."; exit 1; }

deps: | sanity-checks
	@+ $(MAKE) --silent -C ../../ V=0 deps

build:
	mkdir $@

test: | build deps
	../../nimble.sh test $(NIM_PARAMS)

$(TOOLS): | build deps
	for D in $(TOOLS_DIRS); do [ -e "$${D}/$@.nim" ] && TOOL_DIR="$${D}" && break; done && \
		$(ENV_SCRIPT) nim c $(NIM_PARAMS) -o:build/$@ "$${TOOL_DIR}/$@.nim" && \
		echo -e "\nThe binary is in './build/$@'.\n"

clean_eth2_network_simulation_files:
	rm -rf tests/simulation/data

eth2_network_simulation: | beacon_node validator_keygen clean_eth2_network_simulation_files
	SKIP_BUILDS=1 GIT_ROOT="$$PWD" BUILD_OUTPUTS_DIR="./build" tests/simulation/start.sh

clean-testnet0:
	rm -rf ~/.cache/nimbus/BeaconNode/testnet0

testnet0-nocleaning: | build deps
	../../env.sh scripts/connect_to_testnet.sh testnet0

testnet0: | clean-testnet0 testnet0-nocleaning

clean-testnet1:
	rm -rf ~/.cache/nimbus/BeaconNode/testnet1

testnet1-nocleaning: | build deps
	../../env.sh scripts/connect_to_testnet.sh testnet1

testnet1: | clean-testnet1 testnet1-nocleaning

clean:
	rm -rf build/* nimcache

