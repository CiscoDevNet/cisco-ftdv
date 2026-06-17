{{/*
Calculate hugepages based on CPUs and interfaces
Formula: (cpus * 128) + (numInterfaces * 64) Mi, rounded up to nearest 256Mi
numInterfaces is auto-calculated from the networks list based on CNI type
*/}}
{{- define "ftdc.hugepages" -}}
{{- if eq .Values.ftdc.hugepages "auto" -}}
{{- $cpus := .Values.ftdc.cpus | int -}}
{{- $numInterfaces := 0 -}}
{{- if eq .Values.worker_nodes.cni.type "sriov" -}}
{{- $numInterfaces = len .Values.worker_nodes.cni.sriov.networks -}}
{{- else -}}
{{- $numInterfaces = len .Values.worker_nodes.cni.macvlan.networks -}}
{{- end -}}
{{- $rawMi := add (mul $cpus 128) (mul $numInterfaces 64) -}}
{{- $rounded := mul (div (add $rawMi 255) 256) 256 -}}
{{- printf "%dMi" $rounded -}}
{{- else -}}
{{- .Values.ftdc.hugepages -}}
{{- end -}}
{{- end -}}
