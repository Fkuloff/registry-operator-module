.PHONY: help generate manifests build run test test-race test-coverage test-coverage-html \
        fmt vet lint lint-fix mod-tidy docker-build docker-push install uninstall \
        controller-gen golangci-lint

# Image URL to use for building/pushing image targets
IMG ?= registry-operator:latest

# Source directory
SRC_DIR = images/registry-operator/src

# CONTAINER_TOOL defines the container tool to be used for building images.
CONTAINER_TOOL ?= docker

# Detect OS for binary extensions
ifeq ($(OS),Windows_NT)
	BINARY_EXT = .exe
else
	BINARY_EXT =
endif

##@ General

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen ## Generate CRD manifests.
	$(CONTROLLER_GEN) crd paths="./$(SRC_DIR)/apis/registry.kubecontroller.io/v1alpha1" output:crd:dir=./crds

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object paths="./$(SRC_DIR)/apis/registry.kubecontroller.io/v1alpha1"

fmt: ## Run go fmt against code.
	cd $(SRC_DIR) && go fmt ./...

vet: ## Run go vet against code.
	cd $(SRC_DIR) && go vet ./...

lint: golangci-lint ## Run golangci-lint.
	cd $(SRC_DIR) && $(GOLANGCI_LINT) run --config ../../../.golangci.yml ./...

lint-fix: golangci-lint ## Run golangci-lint with auto-fix.
	cd $(SRC_DIR) && $(GOLANGCI_LINT) run --config ../../../.golangci.yml --fix ./...

test: ## Run tests.
	cd $(SRC_DIR) && go test ./... -v

test-race: ## Run tests with race detector (requires CGO).
	cd $(SRC_DIR) && CGO_ENABLED=1 go test ./... -v -race

test-coverage: ## Run tests with coverage report.
	cd $(SRC_DIR) && go test ./... -coverprofile=coverage.out -covermode=atomic
	cd $(SRC_DIR) && go tool cover -func=coverage.out

test-coverage-html: test-coverage ## Run tests with HTML coverage report.
	cd $(SRC_DIR) && go tool cover -html=coverage.out

##@ Build

build: generate ## Build manager binary.
	cd $(SRC_DIR) && go build -o ../../../bin/registry-operator ./cmd/main.go

run: manifests generate ## Run from your host.
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

uninstall: ## Uninstall CRDs from the K8s cluster.
	kubectl delete -f crds/

##@ Build Dependencies

CONTROLLER_GEN = $(CURDIR)/bin/controller-gen$(BINARY_EXT)
controller-gen: ## Download controller-gen locally if necessary.
ifeq (,$(wildcard $(CONTROLLER_GEN)))
	GOBIN=$(CURDIR)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
endif

GOLANGCI_LINT = $(CURDIR)/bin/golangci-lint$(BINARY_EXT)
GOLANGCI_LINT_VERSION = 2.8.0
golangci-lint: ## Download golangci-lint locally if necessary.
ifeq (,$(wildcard $(GOLANGCI_LINT)))
	@echo "Downloading golangci-lint v$(GOLANGCI_LINT_VERSION)..."
ifeq ($(OS),Windows_NT)
	@powershell -Command "Invoke-WebRequest -Uri 'https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-windows-amd64.zip' -OutFile 'golangci-lint.zip'"
	@powershell -Command "Expand-Archive -Path 'golangci-lint.zip' -DestinationPath 'bin/temp' -Force"
	@powershell -Command "Move-Item -Path 'bin/temp/golangci-lint-$(GOLANGCI_LINT_VERSION)-windows-amd64/golangci-lint.exe' -Destination '$(GOLANGCI_LINT)' -Force"
	@powershell -Command "Remove-Item -Path 'golangci-lint.zip','bin/temp' -Recurse -Force"
else
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(CURDIR)/bin v$(GOLANGCI_LINT_VERSION)
endif
endif
