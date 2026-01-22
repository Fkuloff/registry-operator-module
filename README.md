# Registry Operator - Deckhouse Module

Kubernetes operator for scanning Docker registries and tracking available image versions. Packaged as a Deckhouse module.

## Features

- **Automatic Registry Scanning**: Periodically polls Docker registries for new image versions
- **Image Metadata Collection**: Extracts tags, digests (SHA256), and sizes for each image
- **Private Registry Support**: Works with authenticated registries using Kubernetes Secrets
- **Flexible Configuration**: Configurable scan intervals and TLS settings
- **Deckhouse Integration**: Full integration with Deckhouse Kubernetes Platform

## Quick Start

### Prerequisites

- Kubernetes 1.27+
- Deckhouse Kubernetes Platform 1.61+
- werf 2.x (for building)
- crane (for publishing)
- Go 1.24+ (for local development)

### Local Development

```bash
# Install dependencies
cd images/registry-operator/src
go mod tidy

# Build binary
go build -o ../../../bin/registry-operator ./cmd/main.go

# Run locally (requires kubeconfig)
go run ./cmd/main.go

# Run tests
go test ./... -v
```

Or using Makefile from project root:

```bash
make mod-tidy    # Install dependencies
make build       # Build binary
make run         # Run locally
make test        # Run tests
```

### Deployment to Deckhouse

See the Quick deployment section below.

**Quick deployment:**

```bash
# 1. Set variables
export VERSION="v1.0.0"
export REGISTRY_IP=$(hostname -I | awk '{print $1}')
export REGISTRY="${REGISTRY_IP}:5000/modules/registry-operator"

# 2. Build module
MODULES_MODULE_TAG=${VERSION} werf build \
  --repo $REGISTRY \
  --save-build-report \
  --build-report-path images_tags_werf.json \
  --dev

# 3. Publish to registry
BUNDLE_IMAGE=$(cat images_tags_werf.json | jq -r '.Images.bundle.DockerImageName')
RELEASE_IMAGE=$(cat images_tags_werf.json | jq -r '.Images."release-channel-version".DockerImageName')

crane copy $BUNDLE_IMAGE $REGISTRY:${VERSION}
crane copy $RELEASE_IMAGE $REGISTRY/release:${VERSION}
crane copy $REGISTRY/release:${VERSION} $REGISTRY/release:stable

# 4. Install in cluster
kubectl apply -f - <<EOF
apiVersion: deckhouse.io/v1alpha1
kind: ModuleSource
metadata:
  name: registry-operator
spec:
  registry:
    repo: ${REGISTRY_IP}:5000/modules
    scheme: HTTP
EOF

kubectl apply -f - <<EOF
apiVersion: deckhouse.io/v1alpha2
kind: ModuleUpdatePolicy
metadata:
  name: registry-operator
spec:
  releaseChannel: Stable
  update:
    mode: Auto
EOF

kubectl apply -f - <<EOF
apiVersion: deckhouse.io/v1alpha1
kind: ModuleConfig
metadata:
  name: registry-operator
spec:
  enabled: true
  version: 1
EOF

# 5. Check status
kubectl get modulereleases | grep registry
kubectl get pods -n d8-registry-operator
```

## Architecture

The operator consists of three main components:

1. **Registry Controller** (`images/registry-operator/src/internal/controller/registry_controller.go`)
   - Watches Registry custom resources
   - Triggers scans at configured intervals
   - Updates resource status with scan results

2. **Registry HTTP Client** (`images/registry-operator/src/internal/registry/client.go`)
   - Communicates with Docker Registry API v2
   - Handles authentication (Basic, Bearer tokens)
   - Retrieves image manifests and metadata

3. **CRD Definition** (`images/registry-operator/src/apis/registry.kubecontroller.io/v1alpha1/registry_types.go`)
   - Defines the Registry resource schema
   - Spec: user-defined configuration
   - Status: scan results and metadata

The module integrates with Deckhouse through werf build stages, Helm templates, and the deckhouse_lib_helm library.

## Usage Examples

### Scanning Docker Hub

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 300  # seconds
```

### Scanning Private Registry

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: registry-creds
stringData:
  username: myuser
  password: mypass
---
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: private-app
spec:
  url: https://registry.example.com
  repository: company/app
  scanInterval: 600
  credentialsSecret:
    name: registry-creds
```

### Check Status

```bash
kubectl get registries

# NAME      URL                              REPOSITORY      STATUS    AGE
# nginx     https://registry-1.docker.io     library/nginx   Success   5m

kubectl get registry nginx -o yaml
```

Status output:
```yaml
status:
  lastScanStatus: Success
  lastScanTime: "2026-01-21T10:30:00Z"
  images:
  - tag: latest
    digest: sha256:abc123...
    size: 142857392
  - tag: "1.25.3"
    digest: sha256:def456...
    size: 142834512
```

## Configuration

### Registry Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | Registry URL (e.g., `https://registry-1.docker.io`) |
| `repository` | string | yes | Repository to scan (e.g., `library/nginx`) |
| `scanInterval` | int64 | no | Scan interval in seconds (default: 300) |
| `credentialsSecret` | object | no | Reference to Secret with credentials |
| `insecureSkipVerify` | bool | no | Skip TLS certificate verification |

### Module Configuration

When deployed as a Deckhouse module, configure via ModuleConfig:

```yaml
apiVersion: deckhouse.io/v1alpha1
kind: ModuleConfig
metadata:
  name: registry-operator
spec:
  enabled: true
  version: 1
  settings:
    logLevel: info              # debug, info, warn, error
    nodeSelector:               # Optional pod placement
      node-role: control-plane
```

See [openapi/config-values.yaml](openapi/config-values.yaml) for all available settings.

## Monitoring

```bash
# Module status
kubectl get modulesource registry-operator
kubectl get modulereleases | grep registry
kubectl get moduleconfig registry-operator

# Pod status
kubectl get pods -n d8-registry-operator
kubectl get all -n d8-registry-operator

# Logs
kubectl logs -n d8-registry-operator -l app=registry-operator -f

# Registry resources
kubectl get registries -A

# Events
kubectl get events -n d8-registry-operator --sort-by='.lastTimestamp'

# Registry images in repository
crane ls ${REGISTRY_IP}:5000/modules/registry-operator | grep -E "^v[0-9]"
crane ls ${REGISTRY_IP}:5000/modules/registry-operator/release
```

## Troubleshooting

### Controller Issues

```bash
# Check controller logs
kubectl logs -n d8-registry-operator -l app=registry-operator --tail=100

# Check pod status
kubectl describe pod -n d8-registry-operator -l app=registry-operator

# Check deployment
kubectl get deployment -n d8-registry-operator -o wide
```

### Registry Scan Issues

```bash
# Check Registry status
kubectl get registry <name> -o yaml

# Look for error message
kubectl get registry <name> -o jsonpath='{.status.message}'

# Check scan status
kubectl get registry <name> -o jsonpath='{.status.lastScanStatus}'
```

### Module Issues

```bash
# Check ModuleSource status
kubectl get modulesource registry-operator -o yaml | grep -A 20 "status:"

# Check ModuleRelease
kubectl get modulereleases | grep registry

# Check Deckhouse logs
kubectl logs -n d8-system -l app=deckhouse --tail=100 | grep registry-operator
```

### Common Errors

| Error | Solution |
|-------|----------|
| `http: server gave HTTP response to HTTPS client` | Configure containerd for insecure registry on cluster nodes |
| `no template helm_lib_module_labels` | Ensure `charts/deckhouse_lib_helm-*.tgz` is committed to git |
| `MODULES_MODULE_TAG must be set` | Pass env variable: `MODULES_MODULE_TAG=v1.0.0 werf build ...` |
| `repository name not known to registry` | Check ModuleSource repo path matches published path |
| ModuleSource doesn't see new version | Update `stable` tag: `crane copy .../release:vX.X.X .../release:stable` |

## Development

### Commands

From project root:
```bash
make mod-tidy    # Install dependencies
make generate    # Generate DeepCopy methods
make manifests   # Generate CRD manifests
make build       # Build binary to bin/registry-operator
make run         # Run locally
make test        # Run tests
make fmt         # Format code
make vet         # Static analysis
```

From `images/registry-operator/src/`:
```bash
go mod tidy                                    # Install dependencies
go build -o ../../../bin/registry-operator ./cmd/main.go  # Build binary
go run ./cmd/main.go                           # Run locally
go test ./... -v                               # Run tests
go fmt ./...                                   # Format code
go vet ./...                                   # Static analysis
```

### Build Module

```bash
# Build with werf
MODULES_MODULE_TAG=v1.0.0 werf build \
  --repo $REGISTRY \
  --save-build-report \
  --build-report-path images_tags_werf.json \
  --dev

# Publish images
crane copy <bundle-image> $REGISTRY:v1.0.0
crane copy <release-image> $REGISTRY/release:v1.0.0
crane copy $REGISTRY/release:v1.0.0 $REGISTRY/release:stable
```

## License

MIT
