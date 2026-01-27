# Architecture

## Overview

Registry Operator is a Kubernetes controller built with [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime). It watches `Registry` custom resources and periodically scans container registries for image metadata and vulnerabilities.

## Components

```
┌─────────────────────────────────────────────────────────────┐
│                      Kubernetes API                          │
└─────────────────────────────────────────────────────────────┘
                            │
              Watch Registry CR / Update Status
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Registry Operator                         │
│                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────────┐  │
│  │ Reconciler     │  │ Registry Client│  │ Vuln Scanner  │  │
│  │                │─▶│                │  │               │  │
│  │ - Watch CR     │  │ - List tags    │  │ - Trivy CLI   │  │
│  │ - Orchestrate  │  │ - Get manifest │  │ - Parse JSON  │  │
│  │ - Update status│  │ - Auth         │  │ - Summarize   │  │
│  └────────────────┘  └────────────────┘  └───────────────┘  │
│                              │                    │          │
└──────────────────────────────│────────────────────│──────────┘
                               │                    │
                               ▼                    ▼
                      ┌────────────────┐   ┌───────────────┐
                      │ Docker Registry│   │     Trivy     │
                      │ (v2 API)       │   │ (CLI + DB)    │
                      └────────────────┘   └───────────────┘
```

## Project Structure

```
images/registry-operator/src/
├── cmd/
│   └── main.go                     # Entrypoint, manager setup
├── apis/
│   └── registry.kubecontroller.io/
│       └── v1alpha1/
│           ├── groupversion_info.go  # Scheme registration
│           ├── registry_types.go     # CRD type definitions
│           └── zz_generated.deepcopy.go
└── internal/
    ├── controller/
    │   └── registry_controller.go  # RegistryReconciler
    ├── registry/
    │   └── client.go               # Docker Registry v2 client
    └── vulnerability/
        └── scanner.go              # Trivy scanner wrapper
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
- `filterTags()` — apply include/exclude/limit filters

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

## Concurrency Model

### Tag Scanning

Sequential by default. When `scanConfig.concurrency > 1`:
- Worker pool with semaphore
- Context cancellation support
- Results collected via channel

### Vulnerability Scanning

Sequential per image. Each scan:
- Spawns Trivy subprocess
- Timeout via context
- Independent of other scans

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Registry unreachable | Retry with backoff, then fail status |
| Invalid credentials | Fail status with error message |
| Trivy not installed | Skip vuln scan, log warning |
| Trivy timeout | Skip image, continue with others |
| Status update conflict | Retry once with fresh resource version |
