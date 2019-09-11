# These default settings can be overriden by exporting env variables

GIT_REVISION    ?= $(git rev-parse HEAD)

NETWORK         ?= testnet1
NETWORK_TYPE    ?= libp2p

IMAGE_TAG       ?= $(NETWORK)
IMAGE_NAME      ?= statusteam/nimbus_beacon_node:$(IMAGE_TAG)

build: $(NIX_INSTALL)
	docker build \
		--build-arg="GIT_REVISION=$(GIT_REVISION)" \
		--build-arg="NETWORK=$(NETWORK)" \
		--build-arg="NETWORK_TYPE=$(NETWORK_TYPE)" \
		-t $(IMAGE_NAME) .

push: build
	docker push $(IMAGE_NAME)

