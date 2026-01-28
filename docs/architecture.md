# Architecture

## Overview

Registry Operator is a Kubernetes controller built with [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime). It watches `Registry` custom resources and periodically scans container registries for image metadata and vulnerabilities.

## Components

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Kubernetes API                                │
└──────────────────────────────────────────────────────────────────────┘
                                 │
                   Watch Registry CR / Update Status
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Registry Operator                              │
│                                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │Reconciler│  │ Registry │  │   Vuln   │  │   SBOM   │            │
│  │          │─▶│  Client  │  │ Scanner  │  │ Scanner  │            │
│  │- Watch CR│  │- List    │  │- Trivy   │  │- Syft    │            │
│  │- Orch.   │  │- Manifest│  │- CVEs    │  │- Packages│            │
│  │- Status  │  │- Auth    │  │- Summary │  │- Licenses│            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │
│                      │             │             │                   │
│                      │         ┌───┴─────────────┴───┐              │
│                      │         │   SBOM Analyzer     │              │
│                      │         │ - Dependencies      │              │
│                      │         │ - Enrichment        │              │
│                      │         │ - Top packages      │              │
│                      │         └─────────────────────┘              │
└──────────────────────┼─────────────────┬────────────────────────────┘
                       │                 │
                       ▼                 ▼
            ┌────────────────┐  ┌──────────────────┐
            │ Docker Registry│  │  Trivy + Syft    │
            │ (v2 API)       │  │  (CLI tools)     │
            └────────────────┘  └──────────────────┘
```

## Reconciliation Loop

```
┌─────────────────────────────────────────────────────────────┐
│                    Reconcile(ctx, req)                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Get Registry CR       │
                │ (return if not found) │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Handle deletion?      │──Yes──▶ Remove finalizer
                │ (DeletionTimestamp)   │         Return
                └───────────────────────┘
                            │ No
                            ▼
                ┌───────────────────────┐
                │ Add finalizer         │
                │ (if not present)      │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Get credentials       │
                │ (from Secret)         │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ List tags             │
                │ (with retry)          │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Filter tags           │
                │ (include/exclude/     │
                │  limit/sort)          │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Fetch image details   │
                │ (digest, size)        │
                │ (concurrent if cfg)   │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Vulnerability scan?   │──No───┐
                │ (if enabled & due)    │       │
                └───────────────────────┘       │
                            │ Yes               │
                            ▼                   │
                ┌───────────────────────┐       │
                │ Run Trivy scan        │       │
                │ (for each image)      │       │
                └───────────────────────┘       │
                            │                   │
                            ▼◀──────────────────┘
                ┌───────────────────────┐
                │ SBOM generation?      │──No───┐
                │ (if enabled & due)    │       │
                └───────────────────────┘       │
                            │ Yes               │
                            ▼                   │
                ┌───────────────────────┐       │
                │ Run Syft scan         │       │
                │ + analyze deps        │       │
                │ + enrich with CVEs    │       │
                └───────────────────────┘       │
                            │                   │
                            ▼◀──────────────────┘
                ┌───────────────────────┐
                │ Update status         │
                │ (Success/Failed)      │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │ Requeue after         │
                │ scanInterval          │
                └───────────────────────┘
```

## Key Components

### RegistryReconciler

Main controller logic in `internal/controller/registry_controller.go`.

Responsibilities:
- Watch `Registry` custom resources
- Manage finalizers for cleanup
- Orchestrate scanning workflow
- Update CR status

Key methods:
- `Reconcile()` — main loop entry
- `scanRegistry()` — fetch tags and image details
- `scanVulnerabilities()` — run Trivy scans
- `scanSBOM()` — generate SBOM with Syft
- `filterTags()` — apply include/exclude/limit filters
- `fetchImageDetails()` — worker pool for parallel processing

### Registry Client

Docker Registry v2 API client in `internal/registry/client.go`.

Uses [go-containerregistry](https://github.com/google/go-containerregistry) library.

Features:
- Anonymous and basic authentication
- TLS configuration (insecure option)
- Configurable timeout
- List tags and fetch manifests

### Vulnerability Scanner

Trivy CLI wrapper in `internal/vulnerability/scanner.go`.

Features:
- Executes `trivy image` as subprocess
- Parses JSON output
- Configurable severity threshold
- Aggregates results into summary
- Extracts top critical CVEs

### SBOM Scanner

Syft CLI wrapper in `internal/sbom/scanner.go`.

Features:
- Executes `syft scan` as subprocess
- Supports multiple formats (SPDX, CycloneDX, Syft JSON)
- License extraction and analysis
- Identifies risky copyleft licenses (GPL, AGPL)

### SBOM Analyzer

Dependency analysis in `internal/sbom/analyzer.go`.

Features:
- Distinguishes direct vs transitive dependencies
- Calculates package importance scores
- Identifies top-level packages (base OS, runtimes)
- Enriches packages with vulnerability data
- Links CVEs to specific packages

## CRD Schema

### Registry Spec

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Registry URL (e.g., `https://registry-1.docker.io`) |
| `repository` | string | Repository path (e.g., `library/nginx`) |
| `scanInterval` | int64 | Seconds between scans (default: 300) |
| `credentialsSecret` | object | Reference to Secret with credentials |
| `insecureSkipVerify` | bool | Skip TLS certificate verification |
| `scanConfig` | object | Timeout, retries, concurrency settings |
| `tagFilter` | object | Include/exclude patterns, limit, sort |
| `vulnerabilityScanning` | object | Trivy scan configuration |

### Registry Status

| Field | Type | Description |
|-------|------|-------------|
| `lastScanTime` | Time | Timestamp of last scan |
| `lastScanStatus` | string | "Success" or "Failed" |
| `message` | string | Error message if failed |
| `images` | []ImageInfo | List of discovered images |

### ImageInfo

| Field | Type | Description |
|-------|------|-------------|
| `tag` | string | Image tag |
| `digest` | string | SHA256 digest |
| `size` | int64 | Total size in bytes |
| `vulnerabilities` | object | CVE summary (if scanned) |
| `sbom` | object | SBOM data with packages, licenses, dependencies |

## Concurrency Model

### Image Detail Fetching

Uses **worker pool pattern** for optimal resource usage:
- Fixed number of workers (`scanConfig.concurrency`)
- Job queue via buffered channel
- Direct result writing (no result channel overhead)
- Early cancellation support via context

**Benefits:**
- For 100 tags with concurrency=5: creates 5 workers (not 100 goroutines)
- Predictable memory usage
- Efficient context cancellation

### Vulnerability Scanning

Sequential per image. Each scan:
- Spawns Trivy subprocess
- Timeout via context
- Independent of other scans

### SBOM Generation

Sequential per image. Each generation:
- Spawns Syft subprocess
- Processes artifacts and packages
- Runs dependency analysis
- Enriches with vulnerability data

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Registry unreachable | Retry with backoff, then fail status |
| Invalid credentials | Fail status with error message |
| Trivy not installed | Skip vuln scan, log warning |
| Trivy timeout | Skip image, continue with others |
| Syft not installed | Skip SBOM generation, log warning |
| Syft timeout | Skip image, continue with others |
| Status update conflict | Retry once with fresh resource version |
| Context cancelled | Graceful shutdown, drain worker pool |
