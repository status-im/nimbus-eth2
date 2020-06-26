SHELL := bash # the shell used internally by "make"

# These default settings can be overriden by exporting env variables

NETWORK         ?= witti
IMAGE_TAG       ?= testnet2
IMAGE_NAME      ?= statusteam/nimbus_beacon_node:$(IMAGE_TAG)

CURRENT_BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
COMPUTER_SAYS_NO = { echo "I'm sorry, Dave. I'm afraid I can't do that."; exit 1; }

.PHONY: build push push-last

build:
	@ DOCKER_BUILDKIT=1 \
	docker build \
		--build-arg="NETWORK=$(NETWORK)" \
		-t $(IMAGE_NAME) \
		--progress=plain \
		.

push: build
	+@ $(MAKE) push-last

push-last:
	@ [[ "$(CURRENT_BRANCH)" != "devel" ]] && $(COMPUTER_SAYS_NO) || true
	docker push $(IMAGE_NAME)

