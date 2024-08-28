{{- /*
Function for copying VolumeClaimTemplate (VCT) labels and annotations
(version: 1.0.0)

The function can be applied to StatefulSets, and its behaviour depends on
whether the StatefulSet already exists in the cluster:
  - If the StatefulSet does not already exist (e.g., during a new install, or an
    upgrade that adds the StatefulSet), it will add statically defined key-value
    pairs from customKeys, and the app.kubernetes.io/instance label to comply
    with DR-D1121-145.
  - If the StatefulSet already exists in the cluster the labels and annotations
    are copied from the cluster to maintain immutability enforced by Kubernetes.

Parameters:
  - vctName[Mandatory]:     The name of the VCT to copy key-value pairs from
  - release[Mandatory]:     The built-in .Release object
  - name[Mandatory]:        Name of the StatefulSet in the cluster
  - customKeys[Optional]:   Dict of labels or annotations for new VCTs

IMPORTANT: This function is distributed between services verbatim.
Fixes and updates to this function will require services to reapply
this function to their codebase. Until usage of library charts is
supported in ADP, we will keep the function hardcoded here.
*/ -}}
{{- define "eric-enm-permissions-mgr.copyVCTMetadataFields" -}}
  {{- $statefulSet := lookup "apps/v1" "StatefulSet" .release.Namespace .name -}}
  {{- $currentVCT := dict -}}
  {{- range $volumeClaimTemplate := ($statefulSet.spec).volumeClaimTemplates -}}
    {{- if eq ($volumeClaimTemplate.metadata.name) ($.vctName) -}}
      {{- $_ := set $currentVCT "content" $volumeClaimTemplate -}}
    {{- end -}}
  {{- end -}}

  {{- if $currentVCT -}}
    {{- $fieldValue := get $currentVCT.content.metadata $.metadataField -}}
    {{- if $fieldValue -}}
      {{ range $key, $value := $fieldValue }}
        {{- printf "%s: %s" $key ($value | quote) | nindent 0 -}}
      {{ end }}
    {{- end -}}
  {{- else -}}
    {{- range $key, $value := .customKeys }}
      {{- printf "%s: %s" $key ($value | quote) | nindent 0 -}}
    {{- end -}}
  {{- end }}
{{- end -}}

{{- /*
Wrapper functions to set the fields: annotations, labels
*/ -}}
{{- define "eric-enm-permissions-mgr.copyVCTAnnotations" -}}
  {{- include "eric-enm-permissions-mgr.copyVCTMetadataFields" (dict "metadataField" "annotations" "vctName" .vctName "customKeys" .customKeys "release" .release "name" .name) | trim -}}
{{- end -}}

{{- define "eric-enm-permissions-mgr.copyVCTLabels" -}}
  {{- $defaultLabels := dict "app.kubernetes.io/instance" .release.Name -}}
  {{- $mergedLabels := include "eric-enm-permissions-mgr.mergeLabels" (dict "location" (printf "%s.copyVCT" .name) "sources" (list $defaultLabels .customKeys)) | fromYaml -}}
  {{- include "eric-enm-permissions-mgr.copyVCTMetadataFields" (dict "metadataField" "labels" "vctName" .vctName "customKeys" $mergedLabels "release" .release "name" .name) | trim -}}
{{- end -}}
