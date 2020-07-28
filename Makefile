# Copyright (c) 2019-2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

SHELL := bash # the shell used internally by "make"

# used inside the included makefiles
BUILD_SYSTEM_DIR := vendor/nimbus-build-system

# we don't want an error here, so we can handle things later, in the ".DEFAULT" target
-include $(BUILD_SYSTEM_DIR)/makefiles/variables.mk

BUILD_LOG_LEVEL := TRACE
LOG_LEVEL := DEBUG
NODE_ID := 0
BASE_PORT := 9000
BASE_RPC_PORT := 9190
BASE_METRICS_PORT := 8008
GOERLI_WEB3_URL := "wss://goerli.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
VALIDATORS := 1

# unconditionally built by the default Make target
TOOLS := \
	beacon_node \
	block_sim \
	deposit_contract \
	inspector \
	logtrace \
	nbench \
	nbench_spec_scenarios \
	ncli_db \
	ncli_hash_tree_root \
	ncli_pretty \
	ncli_query \
	ncli_transition \
	process_dashboard \
	stack_sizes \
	state_sim \
	validator_client

# bench_bls_sig_agggregation TODO reenable after bls v0.10.1 changes

TOOLS_DIRS := \
	beacon_chain \
	benchmarks \
	ncli \
	nbench \
	research \
	tools
TOOLS_CSV := $(subst $(SPACE),$(COMMA),$(TOOLS))

.PHONY: \
	all \
	deps \
	update \
	test \
	$(TOOLS) \
	clean_eth2_network_simulation_all \
	eth2_network_simulation \
	clean-testnet0 \
	testnet0 \
	clean-testnet1 \
	testnet1 \
	clean \
	libbacktrace \
	book \
	publish-book

ifeq ($(NIM_PARAMS),)
# "variables.mk" was not included, so we update the submodules.
GIT_SUBMODULE_UPDATE := git submodule update --init --recursive
.DEFAULT:
	+@ echo -e "Git submodules not found. Running '$(GIT_SUBMODULE_UPDATE)'.\n"; \
		$(GIT_SUBMODULE_UPDATE) && \
		echo
# Now that the included *.mk files appeared, and are newer than this file, Make will restart itself:
# https://www.gnu.org/software/make/manual/make.html#Remaking-Makefiles
#
# After restarting, it will execute its original goal, so we don't have to start a child Make here
# with "$(MAKE) $(MAKECMDGOALS)". Isn't hidden control flow great?

else # "variables.mk" was included. Business as usual until the end of this file.

# default target, because it's the first one that doesn't start with '.'
all: | $(TOOLS) libnfuzz.so libnfuzz.a

# must be included after the default target
-include $(BUILD_SYSTEM_DIR)/makefiles/targets.mk

ifeq ($(OS), Windows_NT)
  ifeq ($(ARCH), x86)
    # 32-bit Windows is not supported by libbacktrace/libunwind
    USE_LIBBACKTRACE := 0
  endif
endif

CHRONICLES_PARAMS := -d:chronicles_log_level=$(BUILD_LOG_LEVEL)

# "--define:release" implies "--stacktrace:off" and it cannot be added to config.nims
ifeq ($(USE_LIBBACKTRACE), 0)
NIM_PARAMS := $(NIM_PARAMS) $(CHRONICLES_PARAMS) -d:debug -d:disable_libbacktrace
else
NIM_PARAMS := $(NIM_PARAMS) $(CHRONICLES_PARAMS) -d:release
endif

deps: | deps-common nat-libs beacon_chain.nims
ifneq ($(USE_LIBBACKTRACE), 0)
deps: | libbacktrace
endif

#- deletes and recreates "beacon_chain.nims" which on Windows is a copy instead of a proper symlink
update: | update-common
	rm -f beacon_chain.nims && \
		$(MAKE) beacon_chain.nims $(HANDLE_OUTPUT)

# symlink
beacon_chain.nims:
	ln -s beacon_chain.nimble $@

# nim-libbacktrace
libbacktrace:
	+ $(MAKE) -C vendor/nim-libbacktrace --no-print-directory BUILD_CXX_LIB=0

# Windows 10 with WSL enabled, but no distro installed, fails if "../../nimble.sh" is executed directly
# in a Makefile recipe but works when prefixing it with `bash`. No idea how the PATH is overridden.
DISABLE_TEST_FIXTURES_SCRIPT := 0
test: | build deps
ifeq ($(DISABLE_TEST_FIXTURES_SCRIPT), 0)
	V=$(V) scripts/setup_official_tests.sh
endif
	$(ENV_SCRIPT) nim test $(NIM_PARAMS) beacon_chain.nims && rm -f 0000-*.json

$(TOOLS): | build deps
	for D in $(TOOLS_DIRS); do [ -e "$${D}/$@.nim" ] && TOOL_DIR="$${D}" && break; done && \
		echo -e $(BUILD_MSG) "build/$@" && \
		$(ENV_SCRIPT) nim c -o:build/$@ $(NIM_PARAMS) "$${TOOL_DIR}/$@.nim"

clean_eth2_network_simulation_data:
	rm -rf tests/simulation/data

clean_eth2_network_simulation_all:
	rm -rf tests/simulation/{data,validators}

GOERLI_TESTNETS_PARAMS := \
  --dump \
  --web3-url=$(GOERLI_WEB3_URL) \
  --tcp-port=$$(( $(BASE_PORT) + $(NODE_ID) )) \
  --udp-port=$$(( $(BASE_PORT) + $(NODE_ID) )) \
  --metrics \
  --metrics-port=$$(( $(BASE_METRICS_PORT) + $(NODE_ID) )) \
  --rpc \
  --rpc-port=$$(( $(BASE_RPC_PORT) +$(NODE_ID) ))

eth2_network_simulation: | build deps clean_eth2_network_simulation_all
	+ GIT_ROOT="$$PWD" NIMFLAGS="$(NIMFLAGS)" LOG_LEVEL="$(LOG_LEVEL)" tests/simulation/start-in-tmux.sh
	killall prometheus &>/dev/null

clean-testnet0:
	rm -rf build/data/testnet0*

clean-testnet1:
	rm -rf build/data/testnet1*

testnet0 testnet1: | beacon_node
	build/beacon_node \
		--network=$@ \
		--log-level="$(LOG_LEVEL)" \
		--data-dir=build/data/$@_$(NODE_ID) \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS)

medalla: | beacon_node
	build/beacon_node \
		--network=medalla \
		--log-level="$(LOG_LEVEL)" \
		--log-file=build/data/shared_medalla_$(NODE_ID)/nbc_bn_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_medalla_$(NODE_ID) \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS)

medalla-vc: | beacon_node validator_client
	# if launching a VC as well - send the BN looking nowhere for validators/secrets
	mkdir build/data/shared_medalla_$(NODE_ID)/empty_dummy_folder -p
	build/beacon_node \
		--network=medalla \
		--log-level="$(LOG_LEVEL)" \
		--log-file=nbc_bn_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_medalla_$(NODE_ID) \
		--validators-dir=build/data/shared_medalla_$(NODE_ID)/empty_dummy_folder \
		--secrets-dir=build/data/shared_medalla_$(NODE_ID)/empty_dummy_folder \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS) &
	sleep 4
	build/validator_client \
		--log-level="$(LOG_LEVEL)" \
		--log-file=nbc_vc_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_medalla_$(NODE_ID) \
		--rpc-port=$$(( $(BASE_RPC_PORT) +$(NODE_ID) ))

medalla-dev: | beacon_node
	build/beacon_node \
		--network=medalla \
		--log-level="DEBUG; TRACE:discv5,networking; REQUIRED:none; DISABLED:none" \
		--data-dir=build/data/shared_medalla_$(NODE_ID) \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS)

medalla-deposit-data: | beacon_node deposit_contract
	build/beacon_node deposits create \
		--network=medalla \
		--new-wallet-file=build/data/shared_medalla_$(NODE_ID)/wallet.json \
		--out-deposits-dir=build/data/shared_medalla_$(NODE_ID)/validators \
		--out-secrets-dir=build/data/shared_medalla_$(NODE_ID)/secrets \
		--out-deposits-file=medalla-deposits_data-$$(date +"%Y%m%d%H%M%S").json \
		--count=$(VALIDATORS)

clean-medalla:
	rm -rf build/data/shared_medalla*

altona: | beacon_node
	build/beacon_node \
		--network=altona \
		--log-level="$(LOG_LEVEL)" \
		--log-file=build/data/shared_altona_$(NODE_ID)/nbc_bn_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_altona_$(NODE_ID) \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS)

altona-vc: | beacon_node validator_client
	# if launching a VC as well - send the BN looking nowhere for validators/secrets
	mkdir build/data/shared_altona_$(NODE_ID)/empty_dummy_folder -p
	build/beacon_node \
		--network=altona \
		--log-level="$(LOG_LEVEL)" \
		--log-file=nbc_bn_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_altona_$(NODE_ID) \
		--validators-dir=build/data/shared_altona_$(NODE_ID)/empty_dummy_folder \
		--secrets-dir=build/data/shared_altona_$(NODE_ID)/empty_dummy_folder \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS) &
	sleep 4
	build/validator_client \
		--log-level="$(LOG_LEVEL)" \
		--log-file=nbc_vc_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_altona_$(NODE_ID) \
		--rpc-port=$$(( $(BASE_RPC_PORT) +$(NODE_ID) ))

altona-dev: | beacon_node
	build/beacon_node \
		--network=altona \
		--log-level="DEBUG; TRACE:discv5,networking; REQUIRED:none; DISABLED:none" \
		--data-dir=build/data/shared_altona_$(NODE_ID) \
		$(GOERLI_TESTNETS_PARAMS) $(NODE_PARAMS)

altona-deposit: | beacon_node deposit_contract
	build/beacon_node deposits create \
		--out-deposits-file=nbc-altona-deposits.json \
		--count=$(VALIDATORS)

	# TODO
	# The --min-delay is needed only until we fix the invalid
	# nonce generation on multiple transactions in web3
	build/deposit_contract sendDeposits \
		--web3-url=$(GOERLI_WEB3_URL) \
		--deposit-contract=$$(cat vendor/eth2-testnets/shared/altona/deposit_contract.txt) \
		--deposits-file=nbc-altona-deposits.json \
		--ask-for-key \
		--min-delay=60

clean-altona:
	rm -rf build/data/shared_altona*

ctail: | build deps
	mkdir -p vendor/.nimble/bin/
	$(ENV_SCRIPT) nim -d:danger -o:vendor/.nimble/bin/ctail c vendor/nim-chronicles-tail/ctail.nim

ntu: | build deps
	mkdir -p vendor/.nimble/bin/
	$(ENV_SCRIPT) nim -d:danger -o:vendor/.nimble/bin/ntu c vendor/nim-testutils/ntu.nim

clean: | clean-common
	rm -rf build/{$(TOOLS_CSV),all_tests,*_node,*ssz*,beacon_node_*,block_sim,state_sim,transition*}
ifneq ($(USE_LIBBACKTRACE), 0)
	+ $(MAKE) -C vendor/nim-libbacktrace clean $(HANDLE_OUTPUT)
endif

libnfuzz.so: | build deps
	echo -e $(BUILD_MSG) "build/$@" && \
		$(ENV_SCRIPT) nim c -d:release --app:lib --noMain --nimcache:nimcache/libnfuzz -o:build/$@.0 $(NIM_PARAMS) nfuzz/libnfuzz.nim && \
		rm -f build/$@ && \
		ln -s $@.0 build/$@

libnfuzz.a: | build deps
	echo -e $(BUILD_MSG) "build/$@" && \
		rm -f build/$@ && \
		$(ENV_SCRIPT) nim c -d:release --app:staticlib --noMain --nimcache:nimcache/libnfuzz_static -o:build/$@ $(NIM_PARAMS) nfuzz/libnfuzz.nim && \
		[[ -e "$@" ]] && mv "$@" build/ # workaround for https://github.com/nim-lang/Nim/issues/12745

book:
	cd docs/the_nimbus_book && \
	mdbook build

auditors-book:
	cd docs/the_auditors_handbook && \
	mdbook build

publish-book: | book auditors-book
	git branch -D gh-pages && \
	git branch --track gh-pages origin/gh-pages && \
	git worktree add tmp-book gh-pages && \
	rm -rf tmp-book/* && \
	mkdir -p tmp-book/auditors-book && \
	cp -a docs/the_nimbus_book/book/* tmp-book/ && \
	cp -a docs/the_auditors_handbook/book/* tmp-book/auditors-book/ && \
	cd tmp-book && \
	git add . && { \
		git commit -m "make publish-book" && \
		git push origin gh-pages || true; } && \
	cd .. && \
	git worktree remove -f tmp-book && \
	rm -rf tmp-book

endif # "variables.mk" was not included
