<p align="center">
  <img src="https://kubernetes.io/images/kubernetes-horizontal-color.png" width="300" alt="Kubernetes">
</p>

<h1 align="center">Registry Operator</h1>

<p align="center">
  <strong>Kubernetes operator for automated container registry scanning and vulnerability detection</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/kubernetes-1.27+-blue?logo=kubernetes&logoColor=white" alt="Kubernetes 1.27+">
  <img src="https://img.shields.io/badge/go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go 1.24+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT">
  <img src="https://img.shields.io/badge/deckhouse-compatible-orange" alt="Deckhouse Compatible">
</p>

---

## Overview

Registry Operator is a Kubernetes-native solution for comprehensive container registry management. It automatically discovers image tags, collects metadata, scans for vulnerabilities, and generates Software Bill of Materials (SBOM) for complete visibility into your container images.

## Features

| Feature | Description |
|---------|-------------|
| **Registry Scanning** | Periodically polls Docker registries for image tags |
| **Metadata Collection** | Extracts digests (SHA256) and sizes for each image |
| **Vulnerability Detection** | Integrates with Trivy for CVE scanning with severity filtering |
| **SBOM Generation** | Generates Software Bill of Materials using Syft for dependency tracking |
| **Dependency Analysis** | Distinguishes direct vs transitive dependencies |
| **Drift Detection** | Compares running workloads (Deployments/StatefulSets/DaemonSets) with registry images using semantic versioning |
| **Tag Filtering** | Include/exclude by regex, limit count, sort order |
| **Private Registries** | Supports authentication via Kubernetes Secrets |
| **Worker Pool Pattern** | Efficient concurrent processing with configurable parallelism |
| **Deckhouse Integration** | Deploy as a Deckhouse module |

## Installation

```bash
# Apply CRD
kubectl apply -f crds/registry.kubecontroller.io_registries.yaml

# Run operator locally
cd images/registry-operator/src
go run ./cmd/main.go
```

## Usage

### Basic Example

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 300
```

### With Tag Filtering

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx-stable
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  tagFilter:
    include: "^[0-9]+\\.[0-9]+\\.[0-9]+$"
    limit: 10
    sortBy: newest
```

### Private Registry

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
  credentialsSecret:
    name: registry-creds
```

### Vulnerability Scanning

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx-secure
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  tagFilter:
    limit: 5
  vulnerabilityScanning:
    enabled: true
    severityThreshold: HIGH
    ignoreUnfixed: true
```

### SBOM Generation

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx-sbom
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  tagFilter:
    limit: 3

  # Generate SBOM for compliance and security
  sbomGeneration:
    enabled: true
    format: syft-json              # Options: spdx-json, cyclonedx-json, syft-json
    scanInterval: 3600             # Regenerate every hour

  # Combine with vulnerability scanning
  vulnerabilityScanning:
    enabled: true
    severityThreshold: MEDIUM
```

### Complete Example with All Features

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: production-app
spec:
  url: https://registry.example.com
  repository: company/myapp
  scanInterval: 600

  credentialsSecret:
    name: registry-creds

  tagFilter:
    include: "^v[0-9]+\\.[0-9]+\\.[0-9]+$"  # Semantic versions only
    limit: 10
    sortBy: newest

  scanConfig:
    timeout: 60s
    retryAttempts: 3
    concurrency: 5                  # Process 5 images in parallel

  vulnerabilityScanning:
    enabled: true
    scanner: trivy
    severityThreshold: HIGH
    ignoreUnfixed: false
    scanInterval: 7200

  sbomGeneration:
    enabled: true
    format: spdx-json
    scanInterval: 7200

  driftDetection:
    enabled: true
    namespaces:
      - production
      - staging
    checkInterval: 600
```

**Note:** For a fully annotated production-ready example, see [examples/production.yaml](examples/production.yaml)

### Drift Detection

```yaml
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx-drift
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 300

  tagFilter:
    limit: 10

  vulnerabilityScanning:
    enabled: true
    severityThreshold: HIGH

  # Monitor running workloads (Deployments, StatefulSets, DaemonSets)
  driftDetection:
    enabled: true
    namespaces:
      - production
      - staging
    checkInterval: 600      # Check every 10 minutes
```

### Check Status

```bash
# List all registries
kubectl get registries

# Full status with SBOM and vulnerabilities
kubectl get registry nginx -o yaml

# Quick view of vulnerabilities
kubectl get registry nginx -o jsonpath='{.status.images[0].vulnerabilities}'

# View SBOM summary
kubectl get registry nginx -o jsonpath='{.status.images[0].sbom}' | jq .

# Find packages with critical CVEs
kubectl get registry nginx -o json | jq '.status.images[].sbom.packages[] | select(.critical==true)'

# View drift detection summary
kubectl get registry nginx -o jsonpath='{.status.drift.summary}' | jq .

# List outdated workloads
kubectl get registry nginx -o json | jq '.status.drift.workloads[] | select(.status=="OUTDATED")'

# Find workloads with critical vulnerabilities
kubectl get registry nginx -o json | jq '.status.drift.workloads[] | select(.status=="VULNERABLE")'

# Check which workloads need urgent updates
kubectl get registry nginx -o json | jq '.status.drift.workloads[] | select(.recommendation=="URGENT_UPDATE")'
```

## Configuration

| Field | Type | Required | Default | Description |
|-------|------|:--------:|---------|-------------|
| `url` | string | ✓ | - | Registry URL |
| `repository` | string | ✓ | - | Repository path |
| `scanInterval` | int64 | | 300 | Scan interval (seconds) |
| `credentialsSecret.name` | string | | - | Secret with credentials |
| `insecureSkipVerify` | bool | | false | Skip TLS verification |
| `tagFilter.include` | string | | - | Include regex |
| `tagFilter.exclude` | string | | - | Exclude regex |
| `tagFilter.limit` | int | | 0 | Max tags (0=unlimited) |
| `tagFilter.sortBy` | string | | alphabetical | newest/oldest/alphabetical |
| `vulnerabilityScanning.enabled` | bool | | false | Enable Trivy scanning |
| `vulnerabilityScanning.severityThreshold` | string | | MEDIUM | CRITICAL/HIGH/MEDIUM/LOW |
| `vulnerabilityScanning.ignoreUnfixed` | bool | | false | Skip unfixed CVEs |
| `vulnerabilityScanning.scanInterval` | int64 | | 3600 | Vulnerability scan interval (seconds) |
| `sbomGeneration.enabled` | bool | | false | Enable SBOM generation |
| `sbomGeneration.format` | string | | syft-json | spdx-json/cyclonedx-json/syft-json |
| `sbomGeneration.scanInterval` | int64 | | 3600 | SBOM generation interval (seconds) |
| `driftDetection.enabled` | bool | | false | Enable drift detection (tracks Deployments/StatefulSets/DaemonSets) |
| `driftDetection.namespaces` | []string | | [] | Namespaces to monitor (empty=all) |
| `driftDetection.checkInterval` | int64 | | scanInterval | Drift check interval (seconds) |
| `scanConfig.timeout` | string | | 30s | HTTP request timeout |
| `scanConfig.retryAttempts` | int | | 3 | Retry attempts on failure |
| `scanConfig.concurrency` | int | | 1 | Parallel image processing |

## Documentation

- [Architecture](docs/architecture.md) - System architecture and components
- [Development Guide](docs/development.md) - Development setup and workflows
- [Deckhouse Integration](docs/deckhouse.md) - Deploy as Deckhouse module

## Prerequisites

### For Basic Operation
- Kubernetes 1.27+
- kubectl configured

### For Vulnerability Scanning
- [Trivy](https://trivy.dev) installed on the operator pod or host

### For SBOM Generation
- [Syft](https://github.com/anchore/syft) installed on the operator pod or host

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installations
trivy --version
syft version
```

## Quick Start

```bash
# 1. Install CRDs
kubectl apply -f crds/registry.kubecontroller.io_registries.yaml

# 2. Run operator (in separate terminal)
cd images/registry-operator/src
go run ./cmd/main.go

# 3. Create a registry resource
kubectl apply -f examples/basic.yaml

# 4. Check results
kubectl get registries
kubectl get registry nginx -o yaml
```

## License

MIT
