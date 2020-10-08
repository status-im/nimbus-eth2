SHELL := bash

IMAGE_TAG := dist_base_$(shell date --utc +"%Y%m%d%H%M%S")
IMAGE_NAME := statusteam/nimbus_beacon_node:$(IMAGE_TAG)

.PHONY: build push

build:
	@ DOCKER_BUILDKIT=1 \
	docker build \
		-t $(IMAGE_NAME) \
		--progress=plain \
		.

push: build
	docker push $(IMAGE_NAME)

