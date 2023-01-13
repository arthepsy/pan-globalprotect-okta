export DOCKERHUB_USER=mslocrian
export DOCKERHUB_REPO=pan-globalprotect-okta
export DOCKERHUB_VERSION=1.5.0

build:
	@docker build -f Dockerfile -t $(DOCKERHUB_REPO):$(DOCKERHUB_VERSION) .

push: DOCKER_IMAGE_ID = $(shell docker images -q $(DOCKERHUB_REPO):$(DOCKERHUB_VERSION))
push:
	docker tag $(DOCKER_IMAGE_ID) $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):latest
	docker push $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):latest
	docker tag $(DOCKER_IMAGE_ID) $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):$(DOCKERHUB_VERSION)
	docker push $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):$(DOCKERHUB_VERSION)

start:
	bash -c "source openconnect.env && docker-compose up vpn"

