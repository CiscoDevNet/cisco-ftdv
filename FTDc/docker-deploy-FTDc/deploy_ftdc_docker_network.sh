#!/bin/bash
# Copyright (c) 2026 Cisco Systems Inc or its affiliates.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


usage() {
    echo "Usage (macvlan mode):"
    echo "  $0 --version <version> --mgmt-net <network> --mgmt-ip <ip> --data-net <network> --data-net <network> [--cpus <num>] [--memory <mb>]"
    echo "  $0 -v <version> -m <network> -i <ip> -d <network> -d <network> [-C <num>] [-M <mb>]"
    echo ""
    echo "Usage (SR-IOV mode):"
    echo "  $0 --version <version> --mgmt-net <network> --mgmt-ip <ip> --enable-sriov-cni [--cpus <num>] [--memory <mb>]"
    echo "  $0 -v <version> -m <network> -i <ip> -sriov [-C <num>] [-M <mb>]"
    echo ""
    echo "Description:"
    echo "  Creates the 'ftdc' container using management_net at create time, then starts it and"
    echo "  connects each data_net in the order provided. Requires 1 management network and"
    echo "  2 data networks (mandatory), with up to 7 additional optional data networks."
    echo "  Total: 3-10 networks (1 management + 2-9 data)."
    echo ""
    echo "  In SR-IOV mode, data networks are NOT used. Instead, /dev/vfio and /sys/bus/pci"
    echo "  are bind-mounted into the container for direct VF passthrough."
    echo ""
    echo "Required Options:"
    echo "  --version, -v <ver>          Docker image version tag"
    echo "  --mgmt-net, -m <network>     Management network name"
    echo "  --mgmt-ip, -i <ip>           Management interface IP address"
    echo "  --data-net, -d <network>     Data network name (use multiple times, min 2 required)"
    echo ""
    echo "SR-IOV Option (mutually exclusive with --data-net):"
    echo "  --enable-sriov-cni, -sriov   Enable SR-IOV mode (no data networks needed)"
    echo ""
    echo "Optional Settings:"
    echo "  --cpus, -C <num>             Number of CPUs to allocate (default: 4)"
    echo "  --memory, -M <mb>            Memory in MB to allocate (default: 8192)"
    echo "  --shm-size, -S <size>        Shared memory size for /dev/shm (default: 128m)"
    echo "  -h, --help                   Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Macvlan mode"
    echo "  $0 --version 10.0.0-1000 --mgmt-net mgmt0 --mgmt-ip 192.168.1.100 --data-net data0 --data-net data1"
    echo "  $0 -v latest -m br-mgmt -i 192.168.1.100 -d br-data0 -d br-data1"
    echo "  $0 -v latest -m br-mgmt -i 192.168.1.100 -d br-data0 -d br-data1 -C 8 -M 16384"
    echo ""
    echo "  # SR-IOV mode"
    echo "  $0 --version latest --mgmt-net mgmt0 --mgmt-ip 192.168.1.100 --enable-sriov-cni"
    echo "  $0 -v latest -m mgmt0 -i 192.168.1.100 -sriov"
    echo "  $0 -v latest -m mgmt0 -i 192.168.1.100 -sriov -C 8 -M 16384"
}

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
    exit 0
fi

# Initialize variables
VERSION=""
MANAGEMENT_NET=""
MGMT_IP=""
DATA_NETS=()
FTDC_CPUS=4
FTDC_MEMORY=8192
SHM_SIZE="128m"
ENABLE_SRIOV=false

# Parse all arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version|-v)
            VERSION="$2"
            shift 2
            ;;
        --mgmt-net|-m)
            MANAGEMENT_NET="$2"
            shift 2
            ;;
        --mgmt-ip|-i)
            MGMT_IP="$2"
            shift 2
            ;;
        --data-net|-d)
            DATA_NETS+=("$2")
            shift 2
            ;;
        --cpus|-C)
            FTDC_CPUS="$2"
            shift 2
            ;;
        --memory|-M)
            FTDC_MEMORY="$2"
            shift 2
            ;;
        --shm-size|-S)
            SHM_SIZE="$2"
            shift 2
            ;;
        --enable-sriov-cni|-sriov)
            ENABLE_SRIOV=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            echo
            usage
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$VERSION" ]; then
    echo "Error: --version is required"
    echo
    usage
    exit 1
fi

if [ -z "$MANAGEMENT_NET" ]; then
    echo "Error: --mgmt-net is required"
    echo
    usage
    exit 1
fi

if [ -z "$MGMT_IP" ]; then
    echo "Error: --mgmt-ip is required"
    echo
    usage
    exit 1
fi

# Validate SR-IOV vs data-net mutual exclusivity
if [ "$ENABLE_SRIOV" = true ] && [ "${#DATA_NETS[@]}" -gt 0 ]; then
    echo "Error: --data-net must not be used with --enable-sriov-cni. SR-IOV mode uses VF passthrough, not docker networks."
    echo
    usage
    exit 1
fi

if [ "$ENABLE_SRIOV" = false ]; then
    if [ "${#DATA_NETS[@]}" -lt 2 ]; then
        echo "Error: at least 2 data networks (data_net1 and data_net2) must be provided"
        echo
        usage
        exit 1
    fi

    TOTAL_NETS=$((1 + ${#DATA_NETS[@]}))
    if [ "$TOTAL_NETS" -gt 10 ]; then
        echo "Error: no more than 10 total networks allowed (1 management + up to 9 data nets); received $TOTAL_NETS"
        echo
        usage
        exit 1
    fi
fi

# Build SR-IOV volume mounts if enabled
SRIOV_VOLUMES=""
IFACE_CONFIG="$(pwd)/ftdc_shared/interface-config"
IS_MLX5=false

# Auto-detect mlx5: any interface entry with uio_driver = mlx5_core in interface-config
if [ "$ENABLE_SRIOV" = true ]; then
    if grep -qE 'uio_driver[[:space:]]*=[[:space:]]*mlx5_core[[:space:]]*;' "$IFACE_CONFIG" 2>/dev/null; then
        IS_MLX5=true
    fi
fi

if [ "$ENABLE_SRIOV" = true ]; then
    if [ "$IS_MLX5" = true ]; then
        SRIOV_VOLUMES="-v /sys/bus/pci:/sys/bus/pci"
        echo "MLX5 SR-IOV mode detected"
    else
        SRIOV_VOLUMES="-v /dev/vfio:/dev/vfio -v /sys/bus/pci:/sys/bus/pci"
        echo "SR-IOV mode enabled: mounting /dev/vfio and /sys/bus/pci"
    fi
fi

docker create -it \
    --name ftdc \
    --hostname="ftdc" \
    --network="$MANAGEMENT_NET" \
    --ip="$MGMT_IP" \
    --cpus="${FTDC_CPUS}" \
    --memory="${FTDC_MEMORY}m" \
    --shm-size="${SHM_SIZE}" \
    -v "$(pwd)/ftdc_shared/interface-config:/mnt/disk0/interface-config/interface-config:Z" \
    -v "$(pwd)/ftdc_shared/day0.json:/mnt/disk0/day0.json:Z" \
    -v "$(pwd)/ftdc_shared/lina-path:/mnt/disk0/.private:Z" \
    -v "$(pwd)/ftdc_shared/ngfw-path:/ftd/app_data/Volume/root2:Z" \
    $SRIOV_VOLUMES \
    --privileged --cap-add=NET_RAW \
    -e FTDC_CPUS="${FTDC_CPUS}" \
    -e FTDC_MEMORY="${FTDC_MEMORY}" \
    -e PATH=/ngfw/bin:/ngfw/sbin:/ngfw/usr/bin:/ngfw/usr/sbin:/ngfw/usr/local/bin:/ngfw/usr/local/sbin:/ngfw/usr/local/sf/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    -e LD_LIBRARY_PATH=/ngfw/lib64:/ngfw/usr/lib64:/ngfw/lib:/ngfw/usr/lib:/ngfw/usr/local/lib:/ngfw/usr/local/sf/lib:/ngfw/usr/local/sf/lib64:/ngfw/usr/local/asa/lib:/lib64:/usr/lib64 \
    ftdc:${VERSION}

docker start ftdc

if [ "$ENABLE_SRIOV" = true ] && [ "$IS_MLX5" = true ]; then
    CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' ftdc)
    if [ -z "$CONTAINER_PID" ] || [ "$CONTAINER_PID" = "0" ]; then
        echo "Error: could not get container PID for namespace handoff"
        exit 1
    fi
    echo "Moving configured Mellanox VF interfaces into container namespace (PID $CONTAINER_PID)..."
    while IFS= read -r cfg_line; do
        bdf_short=$(echo "$cfg_line" | sed 's/.*iface_id *= *\([^;]*\);.*/\1/' | tr -d ' ')
        [ -n "$bdf_short" ] || continue
        bdf_full="0000:${bdf_short}"
        devpath="/sys/bus/pci/devices/${bdf_full}/"
        [ -L "${devpath}physfn" ] || continue
        for netdir in "${devpath}net/"*/; do
            [ -d "$netdir" ] || continue
            vf_if=$(basename "$netdir")
            ip link set dev "$vf_if" netns "$CONTAINER_PID" && \
                echo "  Moved $vf_if ($bdf_full) into container namespace" || \
                echo "  Warning: failed to move $vf_if ($bdf_full) into container namespace"
        done
    done < <(grep 'iface_id' "$IFACE_CONFIG")
fi

if [ "$ENABLE_SRIOV" = false ]; then
    for net in "${DATA_NETS[@]}"; do
        [ -z "$net" ] && continue
        docker network connect "$net" ftdc
    done
fi
