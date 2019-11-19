SHELL := bash # the shell used internally by "make"

# These default settings can be overriden by exporting env variables

GIT_REVISION      ?= $(shell git rev-parse HEAD)
NETWORK           ?= testnet1
NETWORK_NIM_FLAGS ?= $(shell ../scripts/load-testnet-nim-flags.sh $(NETWORK))

IMAGE_TAG       ?= $(NETWORK)
IMAGE_NAME      ?= statusteam/nimbus_beacon_node:$(IMAGE_TAG)

CURRENT_BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
COMPUTER_SAYS_NO = { echo "I'm sorry, Dave. I'm afraid I can't do that."; exit 1; }

build:
	@ DOCKER_BUILDKIT=1 \
	docker build \
		--build-arg="GIT_REVISION=$(GIT_REVISION)" \
		--build-arg="NETWORK_NIM_FLAGS=$(NETWORK_NIM_FLAGS)" \
		-t $(IMAGE_NAME) \
		--progress=plain \
		.

push: build
	+@ $(MAKE) push-last

push-last:
	@ [[ "$(CURRENT_BRANCH)" != "master" && "$(NETWORK)" == "testnet0" ]] && $(COMPUTER_SAYS_NO) || true
	@ [[ "$(CURRENT_BRANCH)" != "devel" && "$(NETWORK)" == "testnet1" ]] && $(COMPUTER_SAYS_NO) || true
	docker push $(IMAGE_NAME)

