# These default settings can be overriden by exporting env variables

GIT_REVISION      ?= $(shell git rev-parse HEAD)
NETWORK           ?= testnet1
NETWORK_NIM_FLAGS ?= $(shell ../scripts/load-testnet-nim-flags.sh $(NETWORK))

IMAGE_TAG       ?= $(NETWORK)
IMAGE_NAME      ?= statusteam/nimbus_beacon_node:$(IMAGE_TAG)

build:
	docker build \
		--build-arg="GIT_REVISION=$(GIT_REVISION)" \
		--build-arg="NETWORK=$(NETWORK)" \
		--build-arg="NETWORK_NIM_FLAGS=$(NETWORK_NIM_FLAGS)" \
		-t $(IMAGE_NAME) .

push: build
	docker push $(IMAGE_NAME)

push-last:
	docker push $(IMAGE_NAME)

