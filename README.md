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

Registry Operator is a Kubernetes-native solution for monitoring container registries. It automatically discovers image tags, collects metadata, and optionally scans for vulnerabilities using [Trivy](https://trivy.dev).

## Features

| Feature | Description |
|---------|-------------|
| **Registry Scanning** | Periodically polls Docker registries for image tags |
| **Metadata Collection** | Extracts digests (SHA256) and sizes for each image |
| **Vulnerability Detection** | Integrates with Trivy for CVE scanning |
| **Tag Filtering** | Include/exclude by regex, limit count, sort order |
| **Private Registries** | Supports authentication via Kubernetes Secrets |
| **Deckhouse Integration** | Deploy as a Deckhouse module |

## Installation

```bash
# Apply CRD
kubectl apply -f crds/registry.yaml

# Run operator
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

### Check Status

```bash
kubectl get registries
kubectl get registry nginx -o yaml
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

## License

MIT
