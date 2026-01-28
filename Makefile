.PHONY: generate manifests build run test docker-build docker-push install uninstall deploy undeploy

# Image URL to use for building/pushing image targets
IMG ?= registry-operator:latest

# Source directory
SRC_DIR = images/registry-operator/src

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
CONTAINER_TOOL ?= docker

##@ General

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen ## Generate CRD manifests.
	$(CONTROLLER_GEN) crd paths="./$(SRC_DIR)/apis/..." output:crd:dir=./crds

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object paths="./$(SRC_DIR)/apis/..."

fmt: ## Run go fmt against code.
	cd $(SRC_DIR) && go fmt ./...

vet: ## Run go vet against code.
	cd $(SRC_DIR) && go vet ./...

lint: golangci-lint ## Run golangci-lint.
	cd $(SRC_DIR) && $(GOLANGCI_LINT) run --config ../../../.golangci.yml ./...

lint-fix: golangci-lint ## Run golangci-lint with auto-fix.
	cd $(SRC_DIR) && $(GOLANGCI_LINT) run --config ../../../.golangci.yml --fix ./...

test: fmt vet ## Run tests.
	cd $(SRC_DIR) && go test ./... -v

##@ Build

build: generate fmt vet ## Build manager binary.
	cd $(SRC_DIR) && go build -o ../../../bin/registry-operator ./cmd/main.go

run: manifests generate fmt vet ## Run from your host.
	cd $(SRC_DIR) && go run ./cmd/main.go

docker-build: ## Build docker image.
	$(CONTAINER_TOOL) build -t ${IMG} -f images/registry-operator/Dockerfile .

docker-push: ## Push docker image.
	$(CONTAINER_TOOL) push ${IMG}

##@ Dependency Management

mod-tidy: ## Run go mod tidy.
	cd $(SRC_DIR) && go mod tidy

##@ Deployment

install: manifests ## Install CRDs into the K8s cluster.
	kubectl apply -f crds/

uninstall: manifests ## Uninstall CRDs from the K8s cluster.
	kubectl delete -f crds/

##@ Build Dependencies

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	@test -s $(CONTROLLER_GEN) || \
	GOBIN=$(shell pwd)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest

GOLANGCI_LINT = $(shell pwd)/bin/golangci-lint
.PHONY: golangci-lint
golangci-lint: ## Download golangci-lint locally if necessary.
	@test -s $(GOLANGCI_LINT) || \
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell pwd)/bin
