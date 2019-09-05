# Copyright (c) 2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# used inside the included makefiles
BUILD_SYSTEM_DIR := vendor/nimbus-build-system

# we don't want an error here, so we can handle things later, in the build-system-checks target
-include $(BUILD_SYSTEM_DIR)/makefiles/variables.mk

TOOLS := beacon_node bench_bls_sig_agggregation state_sim
TOOLS_DIRS := beacon_chain benchmarks research
TOOLS_CSV := $(subst $(SPACE),$(COMMA),$(TOOLS))

.PHONY: all build-system-checks deps update go-checks p2pd test $(TOOLS) clean_eth2_network_simulation_files eth2_network_simulation clean-testnet0 testnet0 clean-testnet1 testnet1 clean

all: | build-system-checks $(TOOLS)

# must be included after the default target
-include $(BUILD_SYSTEM_DIR)/makefiles/targets.mk

GIT_SUBMODULE_UPDATE := export GIT_LFS_SKIP_SMUDGE=1; git submodule update --init --recursive
build-system-checks:
	@[[ -e "$(BUILD_SYSTEM_DIR)/makefiles" ]] || { \
		echo -e "'$(BUILD_SYSTEM_DIR)/makefiles' not found. Running '$(GIT_SUBMODULE_UPDATE)'.\n"; \
		$(GIT_SUBMODULE_UPDATE); \
		echo -e "\nYou can now run '$(MAKE)' again."; \
		exit 1; \
		}

deps: | deps-common beacon_chain.nims

#- deletes and recreates "beacon_chain.nims" which on Windows is a copy instead of a proper symlink
update: | update-common
	rm -rf beacon_chain.nims && \
		$(MAKE) beacon_chain.nims

# symlink
beacon_chain.nims:
	ln -s beacon_chain.nimble $@

MIN_GO_VER := 1.12
DISABLE_GO_CHECKS := 0
go-checks:
ifeq ($(DISABLE_GO_CHECKS), 0)
	which go &>/dev/null || { echo "Go compiler not installed. Aborting."; exit 1; }
	GO_VER="$$(go version | sed -E 's/^.*go([0-9.]+).*$$/\1/')"; \
	       [[ $$(echo -e "$${GO_VER}\n$(MIN_GO_VER)" | sort -t '.' -k 1,1 -k 2,2 -g | head -n 1) == "$(MIN_GO_VER)" ]] || \
	       { echo "Minimum Go compiler version required: $(MIN_GO_VER). Version available: $$GO_VER. Aborting."; exit 1; }
endif

P2PD_CACHE :=
p2pd: | go-checks
	BUILD_MSG="$(BUILD_MSG) $@" \
		V=$(V) \
		$(ENV_SCRIPT) $(BUILD_SYSTEM_DIR)/scripts/build_p2pd.sh "$(P2PD_CACHE)"

# Windows 10 with WSL enabled, but no distro installed, fails if "../../nimble.sh" is executed directly
# in a Makefile recipe but works when prefixing it with `bash`. No idea how the PATH is overridden.
DISABLE_LFS_SCRIPT := 0
test: | build deps p2pd
ifeq ($(DISABLE_LFS_SCRIPT), 0)
	V=$(V) scripts/process_lfs.sh
endif
	$(ENV_SCRIPT) nim test $(NIM_PARAMS) beacon_chain.nims && rm -f 0000-*.json

$(TOOLS): | build deps p2pd
	for D in $(TOOLS_DIRS); do [ -e "$${D}/$@.nim" ] && TOOL_DIR="$${D}" && break; done && \
		echo -e $(BUILD_MSG) "build/$@" && \
		$(ENV_SCRIPT) nim c $(NIM_PARAMS) -o:build/$@ "$${TOOL_DIR}/$@.nim"

clean_eth2_network_simulation_files:
	rm -rf tests/simulation/{data,validators}

eth2_network_simulation: | build deps p2pd clean_eth2_network_simulation_files
	GIT_ROOT="$$PWD" tests/simulation/start.sh

testnet0 testnet1: | build deps p2pd
	NIM_PARAMS="$(NIM_PARAMS)" $(ENV_SCRIPT) scripts/build_testnet_node.sh $@

clean-testnet0:
	rm -rf ~/.cache/nimbus/BeaconNode/testnet0

clean-testnet1:
	rm -rf ~/.cache/nimbus/BeaconNode/testnet1

clean: | clean-common
	rm -rf build/{$(TOOLS_CSV),all_tests,*_node}

