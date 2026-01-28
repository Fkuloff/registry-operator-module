# Development Guide

## Prerequisites

- Go 1.24+
- kubectl
- A Kubernetes cluster (minikube, kind, or remote)
- (Optional) [Trivy](https://trivy.dev) for vulnerability scanning
- (Optional) [Syft](https://github.com/anchore/syft) for SBOM generation
- (Optional) [controller-gen](https://book.kubebuilder.io/reference/controller-gen) for code generation

## Project Setup

```bash
# Clone repository
git clone https://github.com/your-org/registry-operator.git
cd registry-operator

# Navigate to source directory
cd images/registry-operator/src

# Install dependencies
go mod tidy
```

## Building

### Binary

```bash
# From images/registry-operator/src/
go build -o ../../../bin/registry-operator ./cmd/main.go

# Or from project root (if make available)
make build
```

### Docker Image

```bash
# Using werf (for Deckhouse module)
werf build --repo your-registry.io/registry-operator

# Using plain Docker
docker build -t registry-operator:dev -f images/registry-operator/Dockerfile .
```

## Running Locally

### 1. Start a Cluster

```bash
# minikube
minikube start

# or kind
kind create cluster
```

### 2. Install CRD

```bash
kubectl apply -f crds/registry.kubecontroller.io_registries.yaml
```

### 3. Run Operator

```bash
cd images/registry-operator/src

# Development mode (verbose logging)
go run ./cmd/main.go --development=true

# With custom addresses
go run ./cmd/main.go \
  --metrics-bind-address=:8080 \
  --health-probe-bind-address=:8081
```

### 4. Create Test Resource

```bash
kubectl apply -f examples/basic.yaml
```

### 5. Check Results

```bash
kubectl get registries
kubectl get registry nginx -o yaml
```

## Code Generation

After modifying CRD types in `registry_types.go`:

```bash
# Generate DeepCopy methods
make generate
# or manually:
# controller-gen object paths="./apis/..."

# Generate CRD manifests
make manifests
# or manually:
# controller-gen crd paths="./apis/..." output:crd:dir=../../../crds
```

## Testing

### Run All Tests

```bash
cd images/registry-operator/src
go test ./... -v
```

### Run Specific Package

```bash
go test ./internal/controller/... -v
# Add tests for other packages as needed
```

### With Race Detection

```bash
go test -race ./...
```

### Coverage

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Linting

```bash
# Format code
go fmt ./...

# Static analysis
go vet ./...

# golangci-lint (recommended)
golangci-lint run
```

## Debugging

### Enable Verbose Logging

```bash
go run ./cmd/main.go --development=true
```

### Check Resource Status

```bash
# Full status
kubectl get registry <name> -o yaml

# Just error message
kubectl get registry <name> -o jsonpath='{.status.message}'

# Watch changes
kubectl get registry -w
```

### Inspect Events

```bash
kubectl describe registry <name>
```

### Port Forward Metrics

```bash
# If running in cluster
kubectl port-forward deploy/registry-operator 8080:8080
curl localhost:8080/metrics
```

## Common Tasks

### Add a New Field to CRD

1. Edit `apis/.../v1alpha1/registry_types.go`
2. Add field to appropriate struct with JSON tags
3. Run `make generate` (DeepCopy)
4. Run `make manifests` (CRD YAML)
5. Apply new CRD: `kubectl apply -f crds/registry.kubecontroller.io_registries.yaml`

### Add a New Controller Method

1. Add method to `RegistryReconciler` in `internal/controller/registry_controller.go`
2. Use `log.FromContext(ctx)` for logging
3. Return `(ctrl.Result, error)` for reconciliation control:
   - `ctrl.Result{}` — success, no requeue
   - `ctrl.Result{Requeue: true}` — requeue immediately
   - `ctrl.Result{RequeueAfter: duration}` — requeue after delay
   - `error` — requeue with backoff

### Test Against Real Registry

```yaml
# examples/dockerhub.yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: test-dockerhub
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 60
  tagFilter:
    limit: 3
```

```bash
kubectl apply -f examples/dockerhub.yaml
kubectl get registry test-dockerhub -o yaml
```

### Test SBOM Generation

Requires [Syft](https://github.com/anchore/syft) installed:

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
syft version
```

Create test resource with SBOM enabled:

```yaml
# examples/test-sbom.yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: test-sbom
spec:
  url: https://registry-1.docker.io
  repository: library/alpine
  scanInterval: 120
  tagFilter:
    limit: 2
  sbomGeneration:
    enabled: true
    format: syft-json
    includeLicenses: true
    scanInterval: 300
```

```bash
kubectl apply -f examples/test-sbom.yaml

# Wait for scan to complete
kubectl wait --for=condition=Ready registry/test-sbom --timeout=300s

# View SBOM data
kubectl get registry test-sbom -o jsonpath='{.status.images[0].sbom}' | jq .

# Check packages
kubectl get registry test-sbom -o jsonpath='{.status.images[0].sbom.packages[*].name}'

# Check licenses
kubectl get registry test-sbom -o jsonpath='{.status.images[0].sbom.licenses}' | jq .
```

### Test SBOM + Vulnerability Enrichment

```yaml
# examples/test-sbom-vuln.yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: test-sbom-vuln
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 180
  tagFilter:
    limit: 1
  vulnerabilityScanning:
    enabled: true
    severityThreshold: HIGH
    scanInterval: 300
  sbomGeneration:
    enabled: true
    format: syft-json
    includeLicenses: true
    scanInterval: 300
```

```bash
kubectl apply -f examples/test-sbom-vuln.yaml

# View enriched packages with CVE counts
kubectl get registry test-sbom-vuln -o json | \
  jq '.status.images[0].sbom.packages[] | select(.vulnerabilityCount > 0)'

# Find critical packages
kubectl get registry test-sbom-vuln -o json | \
  jq '.status.images[0].sbom.packages[] | select(.critical == true)'
```

### Test Drift Detection

```bash
# Create test deployments
kubectl create deployment nginx-old --image=nginx:1.24.0
kubectl create deployment nginx-new --image=nginx:1.26.0

# Create registry with drift detection
cat <<EOF | kubectl apply -f -
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: test-drift
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  tagFilter:
    include: "^[0-9]+\\.[0-9]+\\.[0-9]+$"
    limit: 10
    sortBy: newest
  vulnerabilityScanning:
    enabled: true
    severityThreshold: MEDIUM
  driftDetection:
    enabled: true
    checkInterval: 300
EOF

# Wait for scan
kubectl wait --for=condition=Ready registry/test-drift --timeout=300s

# View drift summary
kubectl get registry test-drift -o jsonpath='{.status.drift.summary}' | jq .

# Find vulnerable workloads
kubectl get registry test-drift -o json | \
  jq '.status.drift.workloads[] | select(.status=="VULNERABLE")'

# Check outdated workloads
kubectl get registry test-drift -o json | \
  jq '.status.drift.workloads[] | select(.status=="OUTDATED")'

# View available updates
kubectl get registry test-drift -o json | \
  jq '.status.drift.workloads[0].availableUpdates'
```

### Test Private Registry

```bash
# Create credentials secret
kubectl create secret generic my-creds \
  --from-literal=username=myuser \
  --from-literal=password=mypass

# Apply registry with credentials
kubectl apply -f examples/private-registry.yaml
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build binary to `bin/` |
| `make run` | Run operator locally |
| `make test` | Run tests |
| `make generate` | Generate DeepCopy code |
| `make manifests` | Generate CRD YAML |
| `make fmt` | Format code |
| `make vet` | Static analysis |
| `make mod-tidy` | Tidy go modules |

## IDE Setup

### VS Code

Recommended extensions:
- Go (official)
- YAML
- Kubernetes

`.vscode/settings.json`:
```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.formatTool": "goimports"
}
```

### GoLand

- Enable Go Modules integration
- Set GOROOT and GOPATH
- Enable "Format on Save"
