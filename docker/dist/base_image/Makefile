SHELL := bash

IMAGE_TAG := dist_base_$(shell date --utc +"%Y%m%d%H%M%S")
IMAGE_NAME := statusteam/nimbus_beacon_node:$(IMAGE_TAG)

.PHONY: \
	build-amd64 \
	build-arm64 \
	build-arm \
	push-amd64 \
	push-arm64 \
	push-arm

build-amd64:
	$(CURDIR)/make_base_image.sh amd64 "$(IMAGE_NAME)"

build-arm64:
	$(CURDIR)/make_base_image.sh arm64 "$(IMAGE_NAME)_arm64"

build-arm:
	$(CURDIR)/make_base_image.sh arm "$(IMAGE_NAME)_arm"

# You probably don't want to recreate and push these base images to Docker Hub,
# because when older images expire and get deleted, it will no longer be possible
# to reproduce old releases.

#push-amd64: build-amd64
#	docker push $(IMAGE_NAME)

#push-arm64: build-arm64
#	docker push $(IMAGE_NAME)_arm64

#push-arm: build-arm
#	docker push $(IMAGE_NAME)_arm

