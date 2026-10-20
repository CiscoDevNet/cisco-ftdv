# Cisco Secure Firewall Threat Defense Containerized (FTDc)

## Overview

**FTDc** (Firepower Threat Defense Containerized) is a Kubernetes-native deployment of Cisco Secure Firewall, enabling enterprise-grade network security within containerized environments. This solution packages the Cisco Secure Firewall Threat Defense Virtual (FTDv) as a container workload, allowing seamless integration with Kubernetes orchestration and cloud-native infrastructure.

### Key Features

- **Container-Native Firewall**: Run Cisco Secure Firewall as a Kubernetes pod with full NGFW capabilities
- **Centralized Management**: Integrate with Cisco Secure Firewall Management Center (FMC) for policy management, monitoring, and reporting
- **Flexible Networking**: Support for multiple CNI options including Macvlan and SR-IOV for high-performance data plane
- **Helm-Based Deployment**: Simplified installation and configuration using Helm charts

### What's New in 10.1

Secure Firewall 10.1 brings two major enhancements to FTDc:

- **Upgrade Support**: FTDc now supports in-service upgrades, allowing you to move to newer software versions. This capability is available starting with fresh 10.1 deployments.
- **High Availability (HA)**: FTDc 10.1 introduces active/standby High Availability, enabling resilient, failover-capable deployments across separate worker nodes for production-grade reliability.

> **Note:** Upgrade and HA for FTDc are new capabilities introduced in Secure Firewall 10.1 and require a fresh 10.1 deployment. These features are not available in earlier FTDc releases.

### Use Cases

- **Kubernetes Cluster Security**: Protect east-west and north-south traffic in Kubernetes environments
- **Multi-Tenant Isolation**: Provide network segmentation and security policies per namespace or workload
- **Edge Computing**: Deploy firewall capabilities at edge locations with Kubernetes infrastructure
- **Hybrid Cloud Security**: Consistent security posture across on-premises and cloud Kubernetes clusters

---

## Deployment Options

This repository supports two deployment modes:

- **Helm (Kubernetes)**: Two Helm charts are provided under `helm-deploy-FTDc/`:
  - `helm-deploy-FTDc/ftdc-helm-eks/` — use this for **AWS EKS** clusters.
  - `helm-deploy-FTDc/ftdc-helm/` — use this for **all other Kubernetes** environments (on-prem, generic K8s).
- **Docker (standalone VM)**: For standalone Docker-based deployment on a single VM, see [`docker-deploy-FTDc/README.md`](docker-deploy-FTDc/README.md).

---

## Quick Start (Helm)

```bash
# For AWS EKS:
cd helm-deploy-FTDc/ftdc-helm-eks

# For other Kubernetes environments:
cd helm-deploy-FTDc/ftdc-helm

# Install FTDc with default values
helm install ftdc . -n default

# Or install with custom values
helm install ftdc . -f my-values.yaml -n default
```

---

## Repository Structure

```
FTDc/
├── helm-deploy-FTDc/                # Helm charts for FTDc deployment on Kubernetes
│   ├── ftdc-helm/                   # Helm chart for generic Kubernetes (non-EKS)
│   └── ftdc-helm-eks/               # Helm chart for AWS EKS
├── docker-deploy-FTDc/              # Standalone Docker deployment scripts
│   ├── README.md
│   ├── deploy_ftdc_docker_network.sh
│   └── ftdc_shared/
└── Readme.md
```

### Key Components

| Component | Description |
|-----------|-------------|
| `helm-deploy-FTDc/ftdc-helm/` | Helm chart for deploying FTDc on generic Kubernetes clusters (on-prem, non-EKS) |
| `helm-deploy-FTDc/ftdc-helm-eks/` | Helm chart for deploying FTDc on AWS EKS |
| `docker-deploy-FTDc/` | Standalone Docker deployment scripts |


## Prerequisites

### Kubernetes Cluster Requirements

- Kubernetes v1.20+ with API server access
- **Multus CNI** installed for multi-network support
- **MetalLB** installed for LoadBalancer services
- **Hugepages** enabled on worker nodes (2Mi pages)

### Worker Node Requirements

- Sufficient CPU and memory (default: 4 CPUs, 8GB RAM per FTDc pod)
- For Macvlan: Host interfaces available with MTU 9000
- For SR-IOV: SR-IOV Network Operator installed and VFs configured

#### Hugepages Requirements

FTDc requires 2Mi hugepages for its data plane (DPDK). The amount of hugepages each pod
reserves scales with the number of **data NICs** attached to the pod and the number of
**CPU cores** assigned to it.

The Helm chart computes the per-pod hugepages request automatically as the larger of the
following two terms, rounded up to the nearest 256Mi:

- a **DPDK queue term**, scaling with the number of data NICs and CPU cores
- a **minimum baseline**, determined by the number of CPU cores and data NICs

```
queues_Mi   = numInterfaces * cpus * 40
baseline_Mi = (cpus * 200) + (numInterfaces * 200)
hugepages_Mi = roundUp256( max( queues_Mi, baseline_Mi ) )
```

Where `numInterfaces` is the length of the configured data networks list —
`worker_nodes.cni.macvlan.networks` or `worker_nodes.cni.sriov.networks`, selected by
`worker_nodes.cni.type` (`macvlan` or `sriov`) — and `cpus` is `ftdc.cpus` in `values.yaml`.
The `baseline_Mi` term (200Mi per CPU core plus 200Mi per data NIC) acts as the minimum,
so the queue term only dominates at high NIC-to-core ratios. The final value is rounded up
to the nearest 256Mi. See [`templates/_helpers.tpl`](helm-deploy-FTDc/ftdc-helm/templates/_helpers.tpl)
for the exact logic.

Examples (per pod):

| CPUs | Data NICs | queues_Mi | baseline_Mi | Raw max (Mi) | Reserved (Mi) | 2Mi pages |
|------|-----------|-----------|-------------|--------------|---------------|-----------|
| 4    | 4         | 640       | 1600        | 1600         | 1792          | 896       |
| 4    | 6         | 960       | 2000        | 2000         | 2048          | 1024      |
| 8    | 4         | 1280      | 2400        | 2400         | 2560          | 1280      |
| 16   | 8         | 5120      | 4800        | 5120         | 5120          | 2560      |
| 16   | 9         | 5760      | 5000        | 5760         | 5888          | 2944      |

**Hugepages must be allocated on each worker node before scheduling FTDc pods.**
Kubernetes only exposes hugepages it finds already reserved by the kernel; it will not
allocate them on demand. If a node has insufficient `hugepages-2Mi` capacity, the pod
will stay `Pending` with an `Insufficient hugepages-2Mi` scheduling error.


Reserve at runtime (lost on reboot):

```bash
# Example: 1024 pages = 2048Mi, enough for 2 pods at 4 CPUs / 6 NICs
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

Reserve persistently via `/etc/sysctl.conf`:

```
vm.nr_hugepages = 1024
```

Then reboot the worker node so the kernel reserves the pages early in boot (large
contiguous allocations are unreliable on a long-running system):

```bash
sudo reboot
```

After the node comes back up, verify the capacity is advertised to the scheduler:

```bash
kubectl describe node <worker> | grep hugepages-2Mi
```

### FMC Requirements

- Cisco Secure Firewall Management Center (FMC) accessible from the cluster
- Security zones created (`inside`, `outside`)
- Access policy created (e.g., `allowall`)
- Valid admin credentials

---

## How It Works

### Components

- **FTDc Pod**: A containerized firewall pod with data plane interfaces via Macvlan or SR-IOV. Supports standalone (single pod) and HA (primary + secondary pods on separate worker nodes) deployments.
- **FMC**: Centralized management for policies, monitoring, and reporting.

### Lifecycle Flow

1. Helm deploys the FTDc pod with day0 configuration
2. FTDc initializes and becomes ready (lina process starts)
3. FMC applies access policies and security zones
4. FTDc begins processing traffic

---

## Support

For issues and feature requests, please refer to the project documentation or contact the development team.

---
