# Registry Operator Examples

## Quick Start

### 1. Basic Example (Minimal)

Simple registry scanning without any extra features:

```bash
kubectl apply -f basic.yaml
```

**Features:**
- Registry scanning
- Tag discovery
- Image metadata (digest, size)

**Use case:** Quick testing, simple image tracking

---

### 2. Production Example (Full-Featured)

Complete configuration with all features enabled:

```bash
kubectl apply -f production.yaml
```

**Features:**
- Registry scanning with tag filtering
- Vulnerability scanning (Trivy)
- SBOM generation (Syft)
- Drift detection (Deployments/StatefulSets/DaemonSets)
- Provenance tracking (SLSA attestations)
- Private registry authentication
- Concurrent processing
- Advanced scan configuration

**Use case:** Production environments, security compliance, drift monitoring, supply chain security

---

## View Results

```bash
# List registries
kubectl get registries

# View full status
kubectl get registry <name> -o yaml

# Quick vulnerability check
kubectl get registry <name> -o json | jq '.status.images[].vulnerabilities'

# Check drift detection
kubectl get registry <name> -o json | jq '.status.drift.summary'

# Check provenance info
kubectl get registry <name> -o json | jq '.status.images[].provenance'
```

---

## Configuration Options

For detailed field reference, see [README.md](../README.md#configuration) in the project root.
