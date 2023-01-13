# Copyright (c) 2019-2022 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

SHELL := bash # the shell used internally by "make"

# used inside the included makefiles
BUILD_SYSTEM_DIR := vendor/nimbus-build-system

# we set its default value before LOG_LEVEL is used in "variables.mk"
LOG_LEVEL := DEBUG

# used by Make targets that launch a beacon node
RUNTIME_LOG_LEVEL := INFO

LINK_PCRE := 0

# we don't want an error here, so we can handle things later, in the ".DEFAULT" target
-include $(BUILD_SYSTEM_DIR)/makefiles/variables.mk

NODE_ID := 0
BASE_PORT := 9000
BASE_REST_PORT := 5052
BASE_METRICS_PORT := 8008
# WARNING: Use lazy assignment to allow CI to override.
EXECUTOR_NUMBER ?= 0

SEPOLIA_WEB3_URL := "--web3-url=https://rpc.sepolia.dev --web3-url=https://www.sepoliarpc.space"
GOERLI_WEB3_URL := "--web3-url=wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a"
GNOSIS_WEB3_URLS := "--web3-url=https://rpc.gnosischain.com/"

VALIDATORS := 1
CPU_LIMIT := 0
BUILD_END_MSG := "\\x1B[92mBuild completed successfully:\\x1B[39m"

TEST_MODULES_FLAGS := -d:chronicles_log_level=TRACE -d:chronicles_sinks=json[file]

ifeq ($(CPU_LIMIT), 0)
	CPU_LIMIT_CMD :=
else
	CPU_LIMIT_CMD := cpulimit --limit=$(CPU_LIMIT) --foreground --
endif

# TODO: move this to nimbus-build-system
ifeq ($(shell uname), Darwin)
	# Scary warnings in large volume: https://github.com/status-im/nimbus-eth2/issues/3076
	SILENCE_WARNINGS := 2>&1 | grep -v "failed to insert symbol" | grep -v "could not find object file symbol for symbol" || true
else
	SILENCE_WARNINGS :=
endif

# unconditionally built by the default Make target
# TODO re-enable ncli_query if/when it works again
TOOLS := \
	nimbus_beacon_node \
	deposit_contract \
	resttest \
	logtrace \
	ncli \
	ncli_db \
	ncli_split_keystore \
	fakeee \
	wss_sim \
	stack_sizes \
	nimbus_light_client \
	nimbus_validator_client \
	nimbus_signing_node \
	validator_db_aggregator
.PHONY: $(TOOLS)

# bench_bls_sig_agggregation TODO reenable after bls v0.10.1 changes

TOOLS_DIRS := \
	beacon_chain \
	beacon_chain/eth1 \
	ncli \
	research \
	tools
TOOLS_CSV := $(subst $(SPACE),$(COMMA),$(TOOLS))

.PHONY: \
	all \
	deps \
	update \
	test \
	clean_eth2_network_simulation_all \
	eth2_network_simulation \
	clean \
	libbacktrace \
	book \
	publish-book \
	dist-amd64 \
	dist-arm64 \
	dist-arm \
	dist-win64 \
	dist-macos \
	dist-macos-arm64 \
	dist \
	local-testnet-minimal \
	local-testnet-mainnet

ifeq ($(NIM_PARAMS),)
# "variables.mk" was not included, so we update the submodules.
#
# The `git reset ...` will try to fix a `make update` that was interrupted
# with Ctrl+C after deleting the working copy and before getting a chance to
# restore it in $(BUILD_SYSTEM_DIR).
GIT_SUBMODULE_UPDATE := git submodule update --init --recursive
.DEFAULT:
	+@ echo -e "Git submodules not found. Running '$(GIT_SUBMODULE_UPDATE)'.\n"; \
		$(GIT_SUBMODULE_UPDATE) && \
		git submodule foreach --quiet 'git reset --quiet --hard' && \
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

DEPOSITS_DELAY := 0

#- "--define:release" cannot be added to "config.nims"
#- disable Nim's default parallelisation because it starts too many processes for too little gain
#- https://github.com/status-im/nim-libp2p#use-identify-metrics
NIM_PARAMS += -d:release --parallelBuild:1 -d:libp2p_agents_metrics -d:KnownLibP2PAgents=nimbus,lighthouse,lodestar,prysm,teku

ifeq ($(USE_LIBBACKTRACE), 0)
NIM_PARAMS += -d:disable_libbacktrace
endif

deps: | deps-common nat-libs build/generate_makefile
ifneq ($(USE_LIBBACKTRACE), 0)
deps: | libbacktrace
endif

#- deletes binaries that might need to be rebuilt after a Git pull
update: | update-common
	rm -f build/generate_makefile
	rm -fr nimcache/

# nim-libbacktrace
libbacktrace:
	+ "$(MAKE)" -C vendor/nim-libbacktrace --no-print-directory BUILD_CXX_LIB=0

# Make sure ports don't overlap to support concurrent execution of tests
# Avoid selecting ephemeral ports that may be used by others; safe = 5001-9999
#
# EXECUTOR_NUMBER: [0, 1] (depends on max number of concurrent CI jobs)
#
# The following port ranges are allocated (entire continuous range):
#
# Unit tests:
# - NIMBUS_TEST_KEYMANAGER_BASE_PORT + [0, 4)
#
# REST tests:
# - --base-port
# - --base-rest-port
# - --base-metrics-port
#
# Local testnets (entire continuous range):
# - --base-port + [0, --nodes + --light-clients)
# - --base-rest-port + [0, --nodes)
# - --base-metrics-port + [0, --nodes)
# - --base-vc-keymanager-port + [0, --nodes)
# - --base-vc-metrics-port + [0, --nodes]
# - --base-remote-signer-port + [0, --remote-signers)
#
# Local testnets with --run-geth or --run-nimbus (only these ports):
# - --base-el-net-port + --el-port-offset * [0, --nodes + --light-clients)
# - --base-el-http-port + --el-port-offset * [0, --nodes + --light-clients)
# - --base-el-ws-port + --el-port-offset * [0, --nodes + --light-clients)
# - --base-el-auth-rpc-port + --el-port-offset * [0, --nodes + --light-clients)
UNIT_TEST_BASE_PORT := 9950

restapi-test:
	./tests/simulation/restapi.sh \
		--data-dir resttest0_data \
		--base-port $$(( 5001 + EXECUTOR_NUMBER * 500 )) \
		--base-rest-port $$(( 5031 + EXECUTOR_NUMBER * 500 )) \
		--base-metrics-port $$(( 5061 + EXECUTOR_NUMBER * 500 )) \
		--resttest-delay 30 \
		--kill-old-processes

ifneq ($(shell uname -p), arm)
TESTNET_EXTRA_FLAGS := --run-geth --dl-geth
else
TESTNET_EXTRA_FLAGS :=
endif

local-testnet-minimal:
	./scripts/launch_local_testnet.sh \
		--data-dir $@ \
		--preset minimal \
		--nodes 4 \
		--stop-at-epoch 6 \
		--disable-htop \
		--enable-logtrace \
		--base-port $$(( 6001 + EXECUTOR_NUMBER * 500 )) \
		--base-rest-port $$(( 6031 + EXECUTOR_NUMBER * 500 )) \
		--base-metrics-port $$(( 6061 + EXECUTOR_NUMBER * 500 )) \
		--base-vc-keymanager-port $$(( 6131 + EXECUTOR_NUMBER * 500 )) \
		--base-vc-metrics-port $$(( 6161 + EXECUTOR_NUMBER * 500 )) \
		--base-remote-signer-port $$(( 6201 + EXECUTOR_NUMBER * 500 )) \
		--base-el-net-port $$(( 6301 + EXECUTOR_NUMBER * 500 )) \
		--base-el-http-port $$(( 6302 + EXECUTOR_NUMBER * 500 )) \
		--base-el-ws-port $$(( 6303 + EXECUTOR_NUMBER * 500 )) \
		--base-el-auth-rpc-port $$(( 6304 + EXECUTOR_NUMBER * 500 )) \
		--el-port-offset 5 \
		--timeout 648 \
		--kill-old-processes \
		$(TESTNET_EXTRA_FLAGS) \
		-- \
		--verify-finalization \
		--discv5:no

local-testnet-mainnet:
	./scripts/launch_local_testnet.sh \
		--data-dir $@ \
		--nodes 4 \
		--stop-at-epoch 6 \
		--disable-htop \
		--enable-logtrace \
		--base-port $$(( 7001 + EXECUTOR_NUMBER * 500 )) \
		--base-rest-port $$(( 7031 + EXECUTOR_NUMBER * 500 )) \
		--base-metrics-port $$(( 7061 + EXECUTOR_NUMBER * 500 )) \
		--base-vc-keymanager-port $$(( 7131 + EXECUTOR_NUMBER * 500 )) \
		--base-vc-metrics-port $$(( 7161 + EXECUTOR_NUMBER * 500 )) \
		--base-remote-signer-port $$(( 7201 + EXECUTOR_NUMBER * 500 )) \
		--base-el-net-port $$(( 7301 + EXECUTOR_NUMBER * 500 )) \
		--base-el-http-port $$(( 7302 + EXECUTOR_NUMBER * 500 )) \
		--base-el-ws-port $$(( 7303 + EXECUTOR_NUMBER * 500 )) \
		--base-el-auth-rpc-port $$(( 7304 + EXECUTOR_NUMBER * 500 )) \
		--el-port-offset 5 \
		--timeout 2784 \
		--kill-old-processes \
		$(TESTNET_EXTRA_FLAGS) \
		-- \
		--verify-finalization \
		--discv5:no

# test binaries that can output an XML report
XML_TEST_BINARIES := \
	consensus_spec_tests_mainnet \
	consensus_spec_tests_minimal \
	all_tests

# test suite
TEST_BINARIES := \
	state_sim \
	block_sim
.PHONY: $(TEST_BINARIES) $(XML_TEST_BINARIES)

# Preset-dependent tests
consensus_spec_tests_mainnet: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"tests/consensus_spec/consensus_spec_tests_preset.nim" \
			$(NIM_PARAMS) -d:const_preset=mainnet $(TEST_MODULES_FLAGS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

consensus_spec_tests_minimal: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"tests/consensus_spec/consensus_spec_tests_preset.nim" \
			$(NIM_PARAMS) -d:const_preset=minimal $(TEST_MODULES_FLAGS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

# Tests we only run for the default preset
proto_array: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"beacon_chain/fork_choice/$@.nim" \
			$(NIM_PARAMS) $(TEST_MODULES_FLAGS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

fork_choice: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"beacon_chain/fork_choice/$@.nim" \
			$(NIM_PARAMS) $(TEST_MODULES_FLAGS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

all_tests: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"tests/$@.nim" \
			$(NIM_PARAMS) $(TEST_MODULES_FLAGS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

# State and block sims; getting to 4th epoch triggers consensus checks
state_sim: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"research/$@.nim" \
			$(NIM_PARAMS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

block_sim: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			$@ \
			"research/$@.nim" \
			$(NIM_PARAMS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

DISABLE_TEST_FIXTURES_SCRIPT := 0
# This parameter passing scheme is ugly, but short.
test: | $(XML_TEST_BINARIES) $(TEST_BINARIES)
ifeq ($(DISABLE_TEST_FIXTURES_SCRIPT), 0)
	V=$(V) scripts/setup_scenarios.sh
endif
	for TEST_BINARY in $(XML_TEST_BINARIES); do \
		PARAMS="--xml:build/$${TEST_BINARY}.xml --console"; \
		echo -e "\nRunning $${TEST_BINARY} $${PARAMS}\n"; \
		NIMBUS_TEST_KEYMANAGER_BASE_PORT=$$(( $(UNIT_TEST_BASE_PORT) + EXECUTOR_NUMBER * 25 )) \
			build/$${TEST_BINARY} $${PARAMS} || { \
				echo -e "\n$${TEST_BINARY} $${PARAMS} failed; Last 50 lines from the log:"; \
				tail -n50 "$${TEST_BINARY}.log"; exit 1; \
			}; \
		done; \
		rm -rf 0000-*.json t_slashprot_migration.* *.log block_sim_db
	for TEST_BINARY in $(TEST_BINARIES); do \
		PARAMS=""; \
		if [[ "$${TEST_BINARY}" == "state_sim" ]]; then PARAMS="--validators=8000 --slots=160"; \
		elif [[ "$${TEST_BINARY}" == "block_sim" ]]; then PARAMS="--validators=8000 --slots=160"; \
		fi; \
		echo -e "\nRunning $${TEST_BINARY} $${PARAMS}\n"; \
		build/$${TEST_BINARY} $${PARAMS} || { \
			echo -e "\n$${TEST_BINARY} $${PARAMS} failed; Last 50 lines from the log:"; \
			tail -n50 "$${TEST_BINARY}.log"; exit 1; \
		}; \
		done; \
		rm -rf 0000-*.json t_slashprot_migration.* *.log block_sim_db

# It's OK to only build this once. `make update` deletes the binary, forcing a rebuild.
ifneq ($(USE_LIBBACKTRACE), 0)
build/generate_makefile: | libbacktrace
endif
build/generate_makefile: tools/generate_makefile.nim | deps-common
	+ echo -e $(BUILD_MSG) "$@" && \
	$(ENV_SCRIPT) $(NIMC) c -o:$@ $(NIM_PARAMS) tools/generate_makefile.nim $(SILENCE_WARNINGS) && \
	echo -e $(BUILD_END_MSG) "$@"

# GCC's LTO parallelisation is able to detect a GNU Make jobserver and get its
# maximum number of processes from there, but only if we use the "+" prefix.
# Without it, it will default to the number of CPU cores, which can be a
# problem on low-memory systems.
# It also requires Make to pass open file descriptors to the GCC process,
# which is not possible if we let Nim handle this, so we generate and use a
# makefile instead.
$(TOOLS): | build deps
	+ for D in $(TOOLS_DIRS); do [ -e "$${D}/$@.nim" ] && TOOL_DIR="$${D}" && break; done && \
		echo -e $(BUILD_MSG) "build/$@" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh $@ "$${TOOL_DIR}/$@.nim" $(NIM_PARAMS) && \
		echo -e $(BUILD_END_MSG) "build/$@"

clean_eth2_network_simulation_data:
	rm -rf tests/simulation/data

clean_eth2_network_simulation_all:
	rm -rf tests/simulation/{data,validators}

GOERLI_TESTNETS_PARAMS := \
	--tcp-port=$$(( $(BASE_PORT) + $(NODE_ID) )) \
	--udp-port=$$(( $(BASE_PORT) + $(NODE_ID) )) \
	--metrics \
	--metrics-port=$$(( $(BASE_METRICS_PORT) + $(NODE_ID) )) \
	--rest \
	--rest-port=$$(( $(BASE_REST_PORT) + $(NODE_ID) ))

eth2_network_simulation: | build deps clean_eth2_network_simulation_all
	+ GIT_ROOT="$$PWD" NIMFLAGS="$(NIMFLAGS)" LOG_LEVEL="$(LOG_LEVEL)" tests/simulation/start-in-tmux.sh
	killall prometheus &>/dev/null

#- https://www.gnu.org/software/make/manual/html_node/Multi_002dLine.html
#- macOS doesn't support "=" at the end of "define FOO": https://stackoverflow.com/questions/13260396/gnu-make-3-81-eval-function-not-working
define CONNECT_TO_NETWORK
	scripts/makedir.sh build/data/shared_$(1)_$(NODE_ID)

	scripts/make_prometheus_config.sh \
		--nodes 1 \
		--base-metrics-port $$(($(BASE_METRICS_PORT) + $(NODE_ID))) \
		--config-file "build/data/shared_$(1)_$(NODE_ID)/prometheus.yml"

	$(CPU_LIMIT_CMD) build/$(2) \
		--network=$(1) $(3) $(GOERLI_TESTNETS_PARAMS) \
		--log-level="$(RUNTIME_LOG_LEVEL)" \
		--log-file=build/data/shared_$(1)_$(NODE_ID)/nbc_bn_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_$(1)_$(NODE_ID) \
		$(NODE_PARAMS)
endef

define CONNECT_TO_NETWORK_IN_DEV_MODE
	scripts/makedir.sh build/data/shared_$(1)_$(NODE_ID)

	scripts/make_prometheus_config.sh \
		--nodes 1 \
		--base-metrics-port $$(($(BASE_METRICS_PORT) + $(NODE_ID))) \
		--config-file "build/data/shared_$(1)_$(NODE_ID)/prometheus.yml"

	$(CPU_LIMIT_CMD) build/$(2) \
		--network=$(1) $(3) $(GOERLI_TESTNETS_PARAMS) \
		--log-level="DEBUG; TRACE:discv5,networking; REQUIRED:none; DISABLED:none" \
		--data-dir=build/data/shared_$(1)_$(NODE_ID) \
		--sync-light-client=on \
		--dump $(NODE_PARAMS)
endef

define CONNECT_TO_NETWORK_WITH_VALIDATOR_CLIENT
	# if launching a VC as well - send the BN looking nowhere for validators/secrets
	scripts/makedir.sh build/data/shared_$(1)_$(NODE_ID)
	scripts/makedir.sh build/data/shared_$(1)_$(NODE_ID)/empty_dummy_folder

	scripts/make_prometheus_config.sh \
		--nodes 1 \
		--base-metrics-port $$(($(BASE_METRICS_PORT) + $(NODE_ID))) \
		--config-file "build/data/shared_$(1)_$(NODE_ID)/prometheus.yml"

	$(CPU_LIMIT_CMD) build/$(2) \
		--network=$(1) $(3) $(GOERLI_TESTNETS_PARAMS) \
		--log-level="$(RUNTIME_LOG_LEVEL)" \
		--log-file=build/data/shared_$(1)_$(NODE_ID)/nbc_bn_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_$(1)_$(NODE_ID) \
		--validators-dir=build/data/shared_$(1)_$(NODE_ID)/empty_dummy_folder \
		--secrets-dir=build/data/shared_$(1)_$(NODE_ID)/empty_dummy_folder \
		$(NODE_PARAMS) &

	sleep 4

	build/nimbus_validator_client \
		--log-level="$(RUNTIME_LOG_LEVEL)" \
		--log-file=build/data/shared_$(1)_$(NODE_ID)/nbc_vc_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_$(1)_$(NODE_ID) \
		--rest-port=$$(( $(BASE_REST_PORT) + $(NODE_ID) ))
endef

define CONNECT_TO_NETWORK_WITH_LIGHT_CLIENT
	scripts/makedir.sh build/data/shared_$(1)_$(NODE_ID)

	$(CPU_LIMIT_CMD) build/nimbus_light_client \
		--network=$(1) \
		--log-level="$(RUNTIME_LOG_LEVEL)" \
		--log-file=build/data/shared_$(1)_$(NODE_ID)/nbc_lc_$$(date +"%Y%m%d%H%M%S").log \
		--data-dir=build/data/shared_$(1)_$(NODE_ID) \
		--trusted-block-root="$(LC_TRUSTED_BLOCK_ROOT)"
endef

define MAKE_DEPOSIT_DATA
	build/nimbus_beacon_node deposits createTestnetDeposits \
		--network=$(1) \
		--new-wallet-file=build/data/shared_$(1)_$(NODE_ID)/wallet.json \
		--out-validators-dir=build/data/shared_$(1)_$(NODE_ID)/validators \
		--out-secrets-dir=build/data/shared_$(1)_$(NODE_ID)/secrets \
		--out-deposits-file=$(1)-deposits_data-$$(date +"%Y%m%d%H%M%S").json \
		--count=$(VALIDATORS)
endef

define MAKE_DEPOSIT
	build/nimbus_beacon_node deposits createTestnetDeposits \
		--network=$(1) \
		--out-deposits-file=nbc-$(1)-deposits.json \
		--new-wallet-file=build/data/shared_$(1)_$(NODE_ID)/wallet.json \
		--out-validators-dir=build/data/shared_$(1)_$(NODE_ID)/validators \
		--out-secrets-dir=build/data/shared_$(1)_$(NODE_ID)/secrets \
		--count=$(VALIDATORS)

	build/deposit_contract sendDeposits \
		$(2) \
		--deposit-contract=$$(cat vendor/eth2-networks/shared/$(1)/deposit_contract.txt) \
		--deposits-file=nbc-$(1)-deposits.json \
		--min-delay=$(DEPOSITS_DELAY) \
		--max-delay=$(DEPOSITS_DELAY) \
		--ask-for-key
endef

define CLEAN_NETWORK
	rm -rf build/data/shared_$(1)*/db
	rm -rf build/data/shared_$(1)*/dump
	rm -rf build/data/shared_$(1)*/*.log
endef

###
### Prater
###
prater-build: | nimbus_beacon_node nimbus_signing_node

# https://www.gnu.org/software/make/manual/html_node/Call-Function.html#Call-Function
prater: | prater-build
	$(call CONNECT_TO_NETWORK,prater,nimbus_beacon_node,$(GOERLI_WEB3_URL))

prater-vc: | prater-build nimbus_validator_client
	$(call CONNECT_TO_NETWORK_WITH_VALIDATOR_CLIENT,prater,nimbus_beacon_node,$(GOERLI_WEB3_URL))

prater-lc: | nimbus_light_client
	$(call CONNECT_TO_NETWORK_WITH_LIGHT_CLIENT,prater)

ifneq ($(LOG_LEVEL), TRACE)
prater-dev:
	+ "$(MAKE)" LOG_LEVEL=TRACE $@
else
prater-dev: | prater-build
	$(call CONNECT_TO_NETWORK_IN_DEV_MODE,prater,nimbus_beacon_node,$(GOERLI_WEB3_URL))
endif

prater-dev-deposit: | prater-build deposit_contract
	$(call MAKE_DEPOSIT,prater,$(GOERLI_WEB3_URL))

clean-prater:
	$(call CLEAN_NETWORK,prater)


###
### Goerli
###
goerli-build: | nimbus_beacon_node nimbus_signing_node

# https://www.gnu.org/software/make/manual/html_node/Call-Function.html#Call-Function
goerli: | goerli-build
	$(call CONNECT_TO_NETWORK,goerli,nimbus_beacon_node,$(GOERLI_WEB3_URL))

goerli-vc: | goerli-build nimbus_validator_client
	$(call CONNECT_TO_NETWORK_WITH_VALIDATOR_CLIENT,goerli,nimbus_beacon_node,$(GOERLI_WEB3_URL))

goerli-lc: | nimbus_light_client
	$(call CONNECT_TO_NETWORK_WITH_LIGHT_CLIENT,goerli)

ifneq ($(LOG_LEVEL), TRACE)
goerli-dev:
	+ "$(MAKE)" LOG_LEVEL=TRACE $@
else
goerli-dev: | goerli-build
	$(call CONNECT_TO_NETWORK_IN_DEV_MODE,goerli,nimbus_beacon_node,$(GOERLI_WEB3_URL))
endif

goerli-dev-deposit: | goerli-build deposit_contract
	$(call MAKE_DEPOSIT,goerli,$(GOERLI_WEB3_URL))

clean-goerli:
	$(call CLEAN_NETWORK,goerli)


###
### Sepolia
###
sepolia-build: | nimbus_beacon_node nimbus_signing_node

# https://www.gnu.org/software/make/manual/html_node/Call-Function.html#Call-Function
sepolia: | sepolia-build
	$(call CONNECT_TO_NETWORK,sepolia,nimbus_beacon_node,$(SEPOLIA_WEB3_URL))

sepolia-vc: | sepolia-build nimbus_validator_client
	$(call CONNECT_TO_NETWORK_WITH_VALIDATOR_CLIENT,sepolia,nimbus_beacon_node,$(SEPOLIA_WEB3_URL))

sepolia-lc: | nimbus_light_client
	$(call CONNECT_TO_NETWORK_WITH_LIGHT_CLIENT,sepolia)

ifneq ($(LOG_LEVEL), TRACE)
sepolia-dev:
	+ "$(MAKE)" LOG_LEVEL=TRACE $@
else
sepolia-dev: | sepolia-build
	$(call CONNECT_TO_NETWORK_IN_DEV_MODE,sepolia,nimbus_beacon_node,$(SEPOLIA_WEB3_URL))
endif

sepolia-dev-deposit: | sepolia-build deposit_contract
	$(call MAKE_DEPOSIT,sepolia,$(SEPOLIA_WEB3_URL))

clean-sepolia:
	$(call CLEAN_NETWORK,sepolia)

###
### Gnosis chain binary
###

# TODO The `-d:gnosisChainBinary` override can be removed if the web3 library
#      gains support for multiple "Chain Profiles" that consist of a set of
#      consensus object (such as blocks and transactions) that are specific
#      to the chain.
gnosis-build gnosis-chain-build: | build deps
	+ echo -e $(BUILD_MSG) "build/nimbus_beacon_node_gnosis" && \
		MAKE="$(MAKE)" V="$(V)" $(ENV_SCRIPT) scripts/compile_nim_program.sh \
			nimbus_beacon_node_gnosis \
			beacon_chain/nimbus_beacon_node.nim \
			$(NIM_PARAMS) \
			-d:gnosisChainBinary \
			-d:const_preset=gnosis \
			&& \
		echo -e $(BUILD_END_MSG) "build/nimbus_beacon_node_gnosis"

gnosis: | gnosis-build
	$(call CONNECT_TO_NETWORK,gnosis,nimbus_beacon_node_gnosis,$(GNOSIS_WEB3_URLS))

ifneq ($(LOG_LEVEL), TRACE)
gnosis-dev:
	+ "$(MAKE)" --no-print-directory LOG_LEVEL=TRACE $@
else
gnosis-dev: | gnosis-build
	$(call CONNECT_TO_NETWORK_IN_DEV_MODE,gnosis,nimbus_beacon_node_gnosis,$(GNOSIS_WEB3_URLS))
endif

gnosis-dev-deposit: | gnosis-build deposit_contract
	$(call MAKE_DEPOSIT,gnosis,$(GNOSIS_WEB3_URLS))

clean-gnosis:
	$(call CLEAN_NETWORK,gnosis)

# v22.3 names
gnosis-chain: | gnosis-build
	echo `gnosis-chain` is deprecated, use `gnosis` after migrating data folder
	$(call CONNECT_TO_NETWORK,gnosis-chain,nimbus_beacon_node_gnosis,$(GNOSIS_WEB3_URLS))

ifneq ($(LOG_LEVEL), TRACE)
gnosis-chain-dev:
	+ "$(MAKE)" --no-print-directory LOG_LEVEL=TRACE $@
else
gnosis-chain-dev: | gnosis-build
	echo `gnosis-chain-dev` is deprecated, use `gnosis-dev` instead
	$(call CONNECT_TO_NETWORK_IN_DEV_MODE,gnosis-chain,nimbus_beacon_node_gnosis,$(GNOSIS_WEB3_URLS))
endif

gnosis-chain-dev-deposit: | gnosis-build deposit_contract
	echo `gnosis-chain-dev-deposit` is deprecated, use `gnosis-chain-dev-deposit` instead
	$(call MAKE_DEPOSIT,gnosis-chain,$(GNOSIS_WEB3_URLS))

clean-gnosis-chain:
	$(call CLEAN_NETWORK,gnosis-chain)

###
### Other
###

nimbus-msi: | nimbus_beacon_node
	"$(WIX)/bin/candle" -ext WixUIExtension -ext WixUtilExtension installer/windows/*.wxs -o installer/windows/obj/
	"$(WIX)/bin/light" -ext WixUIExtension -ext WixUtilExtension -cultures:"en-us;en-uk;neutral" installer/windows/obj/*.wixobj -out build/NimbusBeaconNode.msi

nimbus-pkg: | nimbus_beacon_node
	xcodebuild -project installer/macos/nimbus-pkg.xcodeproj -scheme nimbus-pkg build
	packagesbuild installer/macos/nimbus-pkg.pkgproj

ntu: | build deps
	mkdir -p vendor/.nimble/bin/
	+ $(ENV_SCRIPT) $(NIMC) -d:danger -o:vendor/.nimble/bin/ntu c vendor/nim-testutils/ntu.nim

clean: | clean-common
	rm -rf build/{$(TOOLS_CSV),all_tests,test_*,proto_array,fork_choice,*.a,*.so,*_node,*ssz*,nimbus_*,beacon_node*,block_sim,state_sim,transition*,generate_makefile,nimbus-wix/obj}
ifneq ($(USE_LIBBACKTRACE), 0)
	+ "$(MAKE)" -C vendor/nim-libbacktrace clean $(HANDLE_OUTPUT)
endif

libnfuzz.so: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		$(ENV_SCRIPT) $(NIMC) c -d:release --app:lib --noMain --nimcache:nimcache/libnfuzz -o:build/$@.0 $(NIM_PARAMS) nfuzz/libnfuzz.nim $(SILENCE_WARNINGS) && \
		echo -e $(BUILD_END_MSG) "build/$@" && \
		rm -f build/$@ && \
		ln -s $@.0 build/$@

libnfuzz.a: | build deps
	+ echo -e $(BUILD_MSG) "build/$@" && \
		rm -f build/$@ && \
		$(ENV_SCRIPT) $(NIMC) c -d:release --app:staticlib --noMain --nimcache:nimcache/libnfuzz_static -o:build/$@ $(NIM_PARAMS) nfuzz/libnfuzz.nim $(SILENCE_WARNINGS) && \
		echo -e $(BUILD_END_MSG) "build/$@" && \
		[[ -e "$@" ]] && mv "$@" build/ || true # workaround for https://github.com/nim-lang/Nim/issues/12745

book:
	"$(MAKE)" -C docs book

auditors-book:
	[[ "$$(mdbook --version)" = "mdbook v0.4.18" ]] || { echo "'mdbook v0.4.18' not found in PATH. See 'docs/README.md'. Aborting."; exit 1; }
	[[ "$$(mdbook-toc --version)" == "mdbook-toc 0.8.0" ]] || { echo "'mdbook-toc 0.8.0' not found in PATH. See 'docs/README.md'. Aborting."; exit 1; }
	[[ "$$(mdbook-open-on-gh --version)" == "mdbook-open-on-gh 2.1.0" ]] || { echo "'mdbook-open-on-gh 2.1.0' not found in PATH. See 'docs/README.md'. Aborting."; exit 1; }
	[[ "$$(mdbook-admonish --version)" == "mdbook-admonish 1.7.0" ]] || { echo "'mdbook-open-on-gh 1.7.0' not found in PATH. See 'docs/README.md'. Aborting."; exit 1; }
	cd docs/the_auditors_handbook && \
	mdbook build

publish-book: | book auditors-book
	CURRENT_BRANCH="$$(git rev-parse --abbrev-ref HEAD)"; \
		if [[ "$${CURRENT_BRANCH}" != "stable" && "$${CURRENT_BRANCH}" != "unstable" ]]; then \
			echo -e "\nWarning: you're publishing the books from a branch that is neither 'stable' nor 'unstable'!\n"; \
		fi
	git branch -D gh-pages && \
	git branch --track gh-pages origin/gh-pages && \
	git worktree add tmp-book gh-pages && \
	rm -rf tmp-book/* && \
	mkdir -p tmp-book/auditors-book && \
	cp -a docs/the_nimbus_book/CNAME tmp-book/ && \
	cp -a docs/the_nimbus_book/site/* tmp-book/ && \
	cp -a docs/the_auditors_handbook/book/* tmp-book/auditors-book/ && \
	cd tmp-book && \
	git add . && { \
		git commit -m "make publish-book $$(git rev-parse --short HEAD)" && \
		git push origin gh-pages || true; } && \
	cd .. && \
	git worktree remove -f tmp-book && \
	rm -rf tmp-book

dist-amd64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh amd64

dist-arm64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh arm64

dist-arm:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh arm

dist-win64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh win64

dist-macos:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh macos

dist-macos-arm64:
	+ MAKE="$(MAKE)" \
		scripts/make_dist.sh macos-arm64

dist:
	+ $(MAKE) dist-amd64
	+ $(MAKE) dist-arm64
	+ $(MAKE) dist-arm
	+ $(MAKE) dist-win64
	+ $(MAKE) dist-macos
	+ $(MAKE) dist-macos-arm64

#- Build and run benchmarks using an external repo (which can be used easily on
#  older commits, before this Make target was added).
#- It's up to the user to create a benchmarking environment that minimises the
#  results spread. We're showing a 95% CI bar to help visualise that.
benchmarks:
	+ vendor/nimbus-benchmarking/run_nbc_benchmarks.sh --output-type d3

endif # "variables.mk" was not included
