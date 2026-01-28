# Deckhouse Module Guide

This guide explains how to build, publish, and deploy Registry Operator as a [Deckhouse](https://deckhouse.io) module.

## Overview

Deckhouse modules are packaged as OCI artifacts and deployed via `ModuleSource`, `ModuleUpdatePolicy`, and `ModuleConfig` resources.

## Prerequisites

- [werf](https://werf.io) 2.x
- [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
- Docker registry (local or remote)
- Deckhouse Kubernetes Platform 1.61+

## Building

### 1. Set Environment Variables

```bash
export VERSION="v1.0.0"
export REGISTRY_IP=$(hostname -I | awk '{print $1}')
export REGISTRY="${REGISTRY_IP}:5000/modules/registry-operator"
```

### 2. Build with werf

```bash
# Development build
MODULES_MODULE_TAG=${VERSION} werf build \
  --repo $REGISTRY \
  --save-build-report \
  --build-report-path images_tags_werf.json \
  --dev

# Production build (without --dev)
MODULES_MODULE_TAG=${VERSION} werf build \
  --repo $REGISTRY \
  --save-build-report \
  --build-report-path images_tags_werf.json
```

### 3. Publish Module

```bash
# Extract image names from build report
BUNDLE_IMAGE=$(cat images_tags_werf.json | jq -r '.Images.bundle.DockerImageName')
RELEASE_IMAGE=$(cat images_tags_werf.json | jq -r '.Images."release-channel-version".DockerImageName')

# Copy to versioned tags
crane copy $BUNDLE_IMAGE $REGISTRY:${VERSION}
crane copy $RELEASE_IMAGE $REGISTRY/release:${VERSION}

# Update stable release channel
crane copy $REGISTRY/release:${VERSION} $REGISTRY/release:stable
```

## Deploying

### 1. Create ModuleSource

```yaml
apiVersion: deckhouse.io/v1alpha1
kind: ModuleSource
metadata:
  name: registry-operator
spec:
  registry:
    repo: ${REGISTRY_IP}:5000/modules
    scheme: HTTP  # Use HTTPS for production
```

```bash
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
```

### 2. Create ModuleUpdatePolicy

```yaml
apiVersion: deckhouse.io/v1alpha2
kind: ModuleUpdatePolicy
metadata:
  name: registry-operator
spec:
  moduleReleaseSelector:
    labelSelector:
      matchLabels:
        source: registry-operator
  releaseChannel: Stable
  update:
    mode: Auto
```

```bash
kubectl apply -f - <<EOF
apiVersion: deckhouse.io/v1alpha2
kind: ModuleUpdatePolicy
metadata:
  name: registry-operator
spec:
  moduleReleaseSelector:
    labelSelector:
      matchLabels:
        source: registry-operator
  releaseChannel: Stable
  update:
    mode: Auto
EOF
```

### 3. Enable Module

```yaml
apiVersion: deckhouse.io/v1alpha1
kind: ModuleConfig
metadata:
  name: registry-operator
spec:
  enabled: true
  version: 1
```

```bash
kubectl apply -f - <<EOF
apiVersion: deckhouse.io/v1alpha1
kind: ModuleConfig
metadata:
  name: registry-operator
spec:
  enabled: true
  version: 1
EOF
```

## Verification

### Check Module Release

```bash
kubectl get modulereleases | grep registry
```

Expected output:
```
registry-operator-v1.0.0   registry-operator   v1.0.0   Deployed   5m
```

### Check Pods

```bash
kubectl get pods -n d8-registry-operator
```

Expected output:
```
NAME                                 READY   STATUS    RESTARTS   AGE
registry-operator-5d4f8c9b7-x2k9m   1/1     Running   0          5m
```

### Check Logs

```bash
kubectl logs -n d8-registry-operator -l app=registry-operator -f
```

## Using Registry Resources

After deploying the module, create Registry resources to scan container registries:

### Basic Registry Scanning

```bash
kubectl apply -f - <<EOF
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx-registry
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 300
  tagFilter:
    limit: 5
EOF
```

### Registry with Vulnerability Scanning

```bash
kubectl apply -f - <<EOF
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: secure-nginx
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 600
  tagFilter:
    limit: 10
  vulnerabilityScanning:
    enabled: true
    severityThreshold: HIGH
    ignoreUnfixed: false
    scanInterval: 3600
EOF
```

### Registry with SBOM Generation

```bash
kubectl apply -f - <<EOF
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: nginx-sbom
spec:
  url: https://registry-1.docker.io
  repository: library/nginx
  scanInterval: 600
  tagFilter:
    limit: 5
  sbomGeneration:
    enabled: true
    format: syft-json
    includeLicenses: true
    scanInterval: 3600
EOF
```

### Full-Featured Registry

```bash
kubectl apply -f - <<EOF
apiVersion: registry.kubecontroller.io/v1alpha1
kind: Registry
metadata:
  name: production-app
spec:
  url: https://registry.example.com
  repository: company/app
  scanInterval: 600

  credentialsSecret:
    name: registry-credentials

  tagFilter:
    include: "^v[0-9]+\\.[0-9]+\\.[0-9]+$"
    limit: 10
    sortBy: newest

  scanConfig:
    timeout: 60s
    retryAttempts: 3
    concurrency: 5

  vulnerabilityScanning:
    enabled: true
    scanner: trivy
    severityThreshold: MEDIUM
    ignoreUnfixed: false
    scanInterval: 7200

  sbomGeneration:
    enabled: true
    format: spdx-json
    includeLicenses: true
    scanInterval: 7200
EOF
```

### Check Registry Status

```bash
# List all registries
kubectl get registries

# View full status
kubectl get registry nginx-sbom -o yaml

# View SBOM summary
kubectl get registry nginx-sbom -o jsonpath='{.status.images[0].sbom}' | jq .

# Check for critical packages
kubectl get registry nginx-sbom -o json | \
  jq '.status.images[].sbom.packages[] | select(.critical==true)'

# View vulnerability summary
kubectl get registry secure-nginx -o jsonpath='{.status.images[0].vulnerabilities}' | jq .
```

## Module Configuration

### module.yaml

Defines configuration schema for `ModuleConfig`:

```yaml
# module.yaml
x-config-version: 1
type: object
additionalProperties: false
properties:
  logLevel:
    type: string
    enum: ["debug", "info", "warn", "error"]
    default: "info"
    description: "Operator log level"
```

### Using Configuration

In Helm templates, access via `.Values`:

```yaml
# templates/deployment.yaml
spec:
  template:
    spec:
      containers:
      - name: registry-operator
        args:
        {{- if eq .Values.logLevel "debug" }}
        - --development=true
        {{- end }}
```

## Helm Templates

### Deployment

```yaml
# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry-operator
  namespace: d8-{{ .Chart.Name }}
  {{- include "helm_lib_module_labels" (list .) | nindent 2 }}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry-operator
  template:
    metadata:
      labels:
        app: registry-operator
    spec:
      {{- include "helm_lib_node_selector" (tuple . "system") | nindent 6 }}
      {{- include "helm_lib_tolerations" (tuple . "system") | nindent 6 }}
      serviceAccountName: registry-operator
      containers:
      - name: registry-operator
        image: {{ include "helm_lib_module_image" (list . "registryOperator") }}
        args:
        - --metrics-bind-address=:8080
        - --health-probe-bind-address=:8081
        ports:
        - containerPort: 8080
          name: metrics
        - containerPort: 8081
          name: health
        livenessProbe:
          httpGet:
            path: /healthz
            port: health
        readinessProbe:
          httpGet:
            path: /readyz
            port: health
```

### RBAC

```yaml
# templates/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: registry-operator
  namespace: d8-{{ .Chart.Name }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: d8:registry-operator
rules:
- apiGroups: ["registry.kubecontroller.io"]
  resources: ["registries"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: ["registry.kubecontroller.io"]
  resources: ["registries/status"]
  verbs: ["get", "update", "patch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: d8:registry-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: d8:registry-operator
subjects:
- kind: ServiceAccount
  name: registry-operator
  namespace: d8-{{ .Chart.Name }}
```

## Troubleshooting

### Module Not Appearing

```bash
# Check ModuleSource status
kubectl get modulesources registry-operator -o yaml

# Check for pull errors
kubectl describe modulesource registry-operator
```

### Module Not Deploying

```bash
# Check ModuleRelease
kubectl get modulereleases -l module=registry-operator

# Check release status
kubectl describe modulerelease registry-operator-v1.0.0
```

### Operator Not Starting

```bash
# Check pod status
kubectl get pods -n d8-registry-operator

# Check events
kubectl get events -n d8-registry-operator --sort-by='.lastTimestamp'

# Check logs
kubectl logs -n d8-registry-operator -l app=registry-operator --previous
```

### Common Issues

| Issue | Solution |
|-------|----------|
| `ImagePullBackOff` | Check registry URL in ModuleSource, verify image exists |
| `CrashLoopBackOff` | Check operator logs for startup errors |
| `No endpoints` | Verify RBAC permissions, check ServiceAccount |
| Module stuck in `Pending` | Check ModuleUpdatePolicy, verify release channel |

## Upgrading

### 1. Build New Version

```bash
export VERSION="v1.1.0"
MODULES_MODULE_TAG=${VERSION} werf build --repo $REGISTRY ...
```

### 2. Publish

```bash
crane copy $BUNDLE_IMAGE $REGISTRY:${VERSION}
crane copy $RELEASE_IMAGE $REGISTRY/release:${VERSION}
crane copy $REGISTRY/release:${VERSION} $REGISTRY/release:stable
```

### 3. Wait for Auto-Update

If `ModuleUpdatePolicy.spec.update.mode: Auto`, Deckhouse will automatically deploy the new version.

### Manual Update

```bash
# Check available releases
kubectl get modulereleases -l module=registry-operator

# Force update
kubectl annotate modulerelease registry-operator-v1.1.0 \
  modules.deckhouse.io/force-deploy=true
```

## Local Registry Setup

For testing, run a local Docker registry:

```bash
# Start registry
docker run -d -p 5000:5000 --name registry registry:2

# Verify
curl http://localhost:5000/v2/_catalog
```

Configure Docker to allow insecure registry:

```json
// /etc/docker/daemon.json
{
  "insecure-registries": ["192.168.1.100:5000"]
}
```

```bash
sudo systemctl restart docker
```
