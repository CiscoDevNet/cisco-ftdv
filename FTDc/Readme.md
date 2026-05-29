# Cisco Secure Firewall Threat Defense Containerized (FTDc)

## Overview

**FTDc** (Firepower Threat Defense Containerized) is a Kubernetes-native deployment of Cisco Secure Firewall, enabling enterprise-grade network security within containerized environments. This solution packages the Cisco Secure Firewall Threat Defense Virtual (FTDv) as a container workload, allowing seamless integration with Kubernetes orchestration and cloud-native infrastructure.

### Key Features

- **Container-Native Firewall**: Run Cisco Secure Firewall as a Kubernetes pod with full NGFW capabilities
- **Centralized Management**: Integrate with Cisco Secure Firewall Management Center (FMC) for policy management, monitoring, and reporting
- **Flexible Networking**: Support for multiple CNI options including Macvlan and SR-IOV for high-performance data plane
- **Helm-Based Deployment**: Simplified installation and configuration using Helm charts

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
- Hugepages configured: `echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`
- For Macvlan: Host interfaces available with MTU 9000
- For SR-IOV: SR-IOV Network Operator installed and VFs configured

### FMC Requirements

- Cisco Secure Firewall Management Center (FMC) accessible from the cluster
- Security zones created (`inside`, `outside`)
- Access policy created (e.g., `allowall`)
- Valid admin credentials

---

## How It Works

### Components

- **FTDc Pod**: A single containerized firewall pod with data plane interfaces via Macvlan or SR-IOV. Only one FTDc pod per deployment is supported.
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
