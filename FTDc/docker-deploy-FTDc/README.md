FTDc deploy steps:

FTDc can be deployed on any VM with atleast 4 interfaces and 128 hugepages

### Prerequisites

1. Add `ip6_tables` to `/etc/modules` to ensure IPv6 tables module is loaded on boot:
```
echo "ip6_tables" >> /etc/modules
```

2. Configure hugepages by setting `vm.nr_hugepages=x` in `/etc/sysctl.conf` (where x is the number of hugepages required, minimum 128):
```
echo "vm.nr_hugepages=128" >> /etc/sysctl.conf
sysctl -p
```

3. Set MTU 9000 on each data interface used by FTDc for all functionality to work:
   - The parent interfaces of the data networks used in `docker network create` (e.g., `-o parent=eth1`, `-o parent=eth2`).
```
sudo ip link set dev <data-interface> mtu 9000
```
Repeat for every data interface assigned to FTDc.

Copy this "docker-deploy-FTDc" folder into the VM where FTDc should be deployed

Inside that folder,
1) Edit `ftdc_shared/interface-config` to set lina interfaces (see interface-config notes below)
2) Edit `ftdc_shared/day0.json` to set day0 parameters
3) Load the FTDc docker image:
```
docker load < ftdc-<version>.tar
```

4) Deploy the FTDc container using docker network:

Two modes are supported: **macvlan** (a) for standard docker network interfaces, or **SR-IOV** (b) for direct VF passthrough.

Create the management docker network (required for both macvlan and SR-IOV):

```
docker network create -d macvlan \
     --subnet=10.10.4.0/24 \
     -o parent=eth0 \
     mgmt0
```
The management interface IP will be assigned via the `--mgmt-ip` or `-i` parameter in the deploy command.

#### a) Macvlan mode:

1. Create 2-9 data networks (minimum 2 mandatory) — use `--ipv4=false` since data interfaces get IPs assigned from FMC:
```
docker network create -d macvlan \
     --subnet=10.10.10.0/24 \
     --ipv4=false \
     -o parent=eth1 \
     data0

docker network create -d macvlan \
     --subnet=10.10.20.0/24 \
     --ipv4=false \
     -o parent=eth2 \
     data1
```

**Note:** 
- The subnet configured for each docker network must match the subnet of the parent interface in the host.
- Ensure each data network's parent interface has MTU 9000 set before creating the network (see Prerequisites step 3) for all FTDc functionality to work.

2. Edit `ftdc_shared/interface-config` for macvlan mode:
```
[interface0]
  iface_id = eth1;
  uio_driver = afpacket;
[interface1]
  iface_id = eth2;
  uio_driver = afpacket;
```
`iface_id` is the interface name inside the container. `uio_driver` must be `afpacket` for macvlan.

3. Run this command:
```
./deploy_ftdc_docker_network.sh --version <version> --mgmt-net <network> --mgmt-ip <ip> --data-net <network> --data-net <network> [--data-net ... up to 7 more] [--cpus <num>] [--memory <mb>]
./deploy_ftdc_docker_network.sh -v <version> -m <network> -i <ip> -d <network> -d <network> [-d ... up to 7 more] [-C <num>] [-M <mb>]
```

**Examples:**
```
./deploy_ftdc_docker_network.sh --version latest --mgmt-net mgmt0 --mgmt-ip 192.168.1.100 --data-net data0 --data-net data1
./deploy_ftdc_docker_network.sh -v latest -m mgmt0 -i 192.168.1.100 -d data0 -d data1
./deploy_ftdc_docker_network.sh -v latest -m mgmt0 -i 192.168.1.100 -d data0 -d data1 -C 8 -M 16384
```

- Default: 4 CPUs, 8192 MB memory
- Required: 1 management network + 2 data networks
- Optional: Up to 7 additional data networks
- Total: 3-10 networks (1 management + 2-9 data)

#### b) SR-IOV mode:

1. Data networks are **not** needed in SR-IOV mode — only the management network created above is required.

2. Edit `ftdc_shared/interface-config` for SR-IOV mode.
a) vfio
Set `iface_id` to the PCI ID of the desired VF and `uio_driver` to `vfio-pci`:
```
[interface0]
  iface_id = 0b:0a.0;
  uio_driver = vfio-pci;
[interface1]
  iface_id = 0b:0a.1;
  uio_driver = vfio-pci;
```
b) mlx5
Set `iface_id` to the PCI ID of the desired VF and `uio_driver` to `mlx5_core`:
```
[interface0]
  iface_id = 61:02.0;
  uio_driver = mlx5_core;
[interface1]
  iface_id = 61:04.0;
  uio_driver = mlx5_core;
```
Replace the PCI IDs with the actual VF PCI addresses assigned to your SR-IOV interfaces (use `lspci | grep Virtual` to identify them).

3. Run this command with `--enable-sriov-cni` (no `--data-net` flags):
```
./deploy_ftdc_docker_network.sh --version <version> --mgmt-net <network> --mgmt-ip <ip> --enable-sriov-cni [--cpus <num>] [--memory <mb>]
./deploy_ftdc_docker_network.sh -v <version> -m <network> -i <ip> -sriov [-C <num>] [-M <mb>]
```

**Examples:**
```
./deploy_ftdc_docker_network.sh --version latest --mgmt-net mgmt0 --mgmt-ip 192.168.1.100 --enable-sriov-cni
./deploy_ftdc_docker_network.sh -v latest -m mgmt0 -i 192.168.1.100 -sriov
./deploy_ftdc_docker_network.sh -v latest -m mgmt0 -i 192.168.1.100 -sriov -C 8 -M 16384
```

The script will bind-mount `/dev/vfio` and `/sys/bus/pci` into the container for VF passthrough.

Both modes (macvlan and SR-IOV) create and start FTDc with the specified configuration.
- Default: 4 CPUs, 8192 MB memory

5) Attach to the container:
```
docker attach ftdc
```

You can access the clish prompt 

### Note: FTDc Persistence

FTDc has persistence enabled by default. The container state is stored in `ftdc_shared/lina-path` and `ftdc_shared/ngfw-path` directories on the host. This means that after a `docker stop` and `docker rm`, new deployments will come up with the original state, preventing re-registration.

To perform a fresh deployment, manually remove these directories before starting a new container:
```
sudo rm -rf ftdc_shared/lina-path ftdc_shared/ngfw-path
```

**Important:** Deploying a different FTDc image version over existing `lina-path` and `ngfw-path` directories is not supported. A new version should always be a fresh deployment — remove these directories before deploying with a newer image.