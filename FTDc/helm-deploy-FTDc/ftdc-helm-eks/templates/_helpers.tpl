{{/*
Calculate hugepages based on CPUs and interfaces
Formula: max(numInterfaces * cpus * 40, (cpus * 200) + (numInterfaces * 200)) Mi, rounded up to nearest 256Mi
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
{{- $queuesMi := mul (mul $numInterfaces $cpus) 40 -}}
{{- $coresMi := mul $cpus 200 -}}
{{- $nicsMi := mul $numInterfaces 200 -}}
{{- $minMi := add $coresMi $nicsMi -}}
{{- $rawMi := max $queuesMi $minMi -}}
{{- $rounded := mul (div (add $rawMi 255) 256) 256 -}}
{{- printf "%dMi" $rounded -}}
{{- else -}}
{{- .Values.ftdc.hugepages -}}
{{- end -}}
{{- end -}}
