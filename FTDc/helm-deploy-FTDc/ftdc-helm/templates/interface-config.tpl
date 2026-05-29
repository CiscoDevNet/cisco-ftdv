{{/*
Generate interface-config dynamically based on CNI type and networks defined in values.yaml.

For macvlan (cni.type: "macvlan"), generates:
  [interface0]
    iface_id = net1;
    uio_driver = afpacket;
  [interface1]
    iface_id = net2;
    uio_driver = afpacket;
  [interface2]
    iface_id = net3;
    uio_driver = afpacket;

For SR-IOV (cni.type: "sriov"), generates:
  [interface0]
    iface_id = net1;
    uio_driver = vfio-pci;
  [interface1]
    iface_id = net2;
    uio_driver = vfio-pci;

Number of interfaces is determined by the length of:
  - worker_nodes.cni.macvlan.networks (for macvlan)
  - worker_nodes.cni.sriov.networks (for sriov)
*/}}
{{- define "ftdc.interface-config" -}}
{{- $driver := "afpacket" -}}
{{- if eq .Values.worker_nodes.cni.type "sriov" -}}
{{- $driver = "vfio-pci" -}}
{{- end -}}
{{- $networks := .Values.worker_nodes.cni.macvlan.networks -}}
{{- if eq .Values.worker_nodes.cni.type "sriov" -}}
{{- $networks = .Values.worker_nodes.cni.sriov.networks -}}
{{- end -}}
{{- range $i, $net := $networks }}
[interface{{ $i }}]
  iface_id = net{{ add $i 1 }};
  uio_driver = {{ $driver }};
{{- end }}
{{- end -}}
