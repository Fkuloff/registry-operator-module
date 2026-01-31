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
│  │- Status  │  │- Auth    │  │- Summary │  │- Types   │            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │
│       │                │             │             │                 │
│       │                │         ┌───┴─────────────┴───┐            │
│       │                │         │   SBOM Analyzer     │            │
│       │                │         │ - Dependencies      │            │
│       │                │         │ - Enrichment        │            │
│       │                │         │ - Top packages      │            │
│       │                │         └─────────────────────┘            │
│       │                │                                             │
│       │      ┌─────────┴─────────────────┐  ┌─────────────────────┐│
│       └─────▶│   Drift Detection         │  │ Provenance Scanner  ││
│              │ - Workload Scanner        │  │ - OCI Referrers API ││
│              │ - Drift Analyzer          │  │ - SLSA attestations ││
│              │ - Semver Comparison       │  │ - Builder/Source    ││
│              └───────────────────────────┘  └─────────────────────┘│
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
                │ (digest, size,        │
                │  platforms, config,   │
                │  timestamps)          │
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
                │ Provenance tracking?  │──No───┐
                │ (if enabled & due)    │       │
                └───────────────────────┘       │
                            │ Yes               │
                            ▼                   │
                ┌───────────────────────┐       │
                │ Fetch attestations    │       │
                │ via OCI Referrers API │       │
                │ + parse SLSA provenance│      │
                └───────────────────────┘       │
                            │                   │
                            ▼◀──────────────────┘
                ┌───────────────────────┐
                │ Drift detection?      │──No───┐
                │ (if enabled & due)    │       │
                └───────────────────────┘       │
                            │ Yes               │
                            ▼                   │
                ┌───────────────────────┐       │
                │ Scan workloads        │       │
                │ + analyze drift       │       │
                │ + semver comparison   │       │
                │ + enrich image usage  │       │
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

### Vulnerability & SBOM Scanning

Sequential per image. Each scan spawns a subprocess (Trivy/Syft) with timeout via context.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Registry unreachable | Retry with backoff, then fail status |
| Invalid credentials | Fail status with error message |
| Trivy not installed | Skip vuln scan, log warning |
| Trivy timeout | Skip image, continue with others |
| Syft not installed | Skip SBOM generation, log warning |
| Syft timeout | Skip image, continue with others |
| Provenance API not supported | Return empty provenance (no error) |
| No attestations found | Return empty provenance with timestamp |
| Status update conflict | Retry once with fresh resource version |
| Context cancelled | Graceful shutdown, drain worker pool |
