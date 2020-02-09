SHELL := bash # the shell used internally by "make"

# These default settings can be overriden by exporting env variables

GIT_REVISION      ?= $(shell git rev-parse HEAD)
NETWORK           ?= testnet1
NETWORK_NIM_FLAGS ?= $(shell ../scripts/load-testnet-nim-flags.sh $(NETWORK))
# Get the required GCC flags by running `gcc -v -E - -march=native </dev/null 2>&1 | grep cc1` on the server.
MARCH_NIM_FLAGS   ?= -d:disableMarchNative --passC:'-march=znver1 --param l1-cache-size=32 --param l1-cache-line-size=64 --param l2-cache-size=512'

IMAGE_TAG       ?= $(NETWORK)
IMAGE_NAME      ?= statusteam/nimbus_beacon_node:$(IMAGE_TAG)

CURRENT_BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
COMPUTER_SAYS_NO = { echo "I'm sorry, Dave. I'm afraid I can't do that."; exit 1; }

.PHONY: build push push-last

build:
	@ DOCKER_BUILDKIT=1 \
	docker build \
		--build-arg="GIT_REVISION=$(GIT_REVISION)" \
		--build-arg="NETWORK_NIM_FLAGS=$(NETWORK_NIM_FLAGS)" \
		--build-arg="MARCH_NIM_FLAGS=$(MARCH_NIM_FLAGS)" \
		-t $(IMAGE_NAME) \
		--progress=plain \
		.

push: build
	+@ $(MAKE) push-last

push-last:
	@ [[ "$(CURRENT_BRANCH)" != "master" && "$(NETWORK)" == "testnet0" ]] && $(COMPUTER_SAYS_NO) || true
	@ [[ "$(CURRENT_BRANCH)" != "devel" && "$(NETWORK)" == "testnet1" ]] && $(COMPUTER_SAYS_NO) || true
	docker push $(IMAGE_NAME)

