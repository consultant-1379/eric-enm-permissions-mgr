{{/*
The mainImage path (DR-D1121-067)
*/}}
{{- define "eric-enm-permissions-mgr.mainImagePath" }}
    {{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
    {{- $registryUrl := $productInfo.images.mainImage.registry -}}
    {{- $repoPath := $productInfo.images.mainImage.repoPath -}}
    {{- $name := $productInfo.images.mainImage.name -}}
    {{- $tag := .Chart.Version -}}
    {{- if .Values.global -}}
        {{- if .Values.global.registry -}}
            {{- if .Values.global.registry.url -}}
                {{- $registryUrl = .Values.global.registry.url -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials -}}
        {{- if .Values.imageCredentials.mainImage -}}
            {{- if .Values.imageCredentials.mainImage.registry -}}
                {{- if .Values.imageCredentials.mainImage.registry.url -}}
                    {{- $registryUrl = .Values.imageCredentials.mainImage.registry.url -}}
                {{- end -}}
            {{- end -}}
            {{- if not (kindIs "invalid" .Values.imageCredentials.mainImage.repoPath) -}}
                {{- $repoPath = .Values.imageCredentials.mainImage.repoPath -}}
            {{- end -}}
        {{- end -}}
        {{- if not (kindIs "invalid" .Values.imageCredentials.repoPath) -}}
            {{- $repoPath = .Values.imageCredentials.repoPath -}}
        {{- end -}}
    {{- end -}}
    {{- if $repoPath -}}
        {{- $repoPath = printf "%s/" $repoPath -}}
    {{- end -}}
    {{- printf "%s/%s%s:%s" $registryUrl $repoPath $name $tag -}}
{{- end -}}

{{/*
Create a map from ".Values.global" with defaults if missing in values file.
This hides defaults from values file.
*/}}
{{ define "eric-enm-permissions-mgr.global" }}
  {{- $globalDefaults := dict "security" (dict "tls" (dict "enabled" true)) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "nodeSelector" (dict)) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "registry" (dict "pullSecret" "eric-adp-example-secret")) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "externalIPv4" (dict "enabled")) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "externalIPv6" (dict "enabled")) -}}
  {{ if .Values.global }}
    {{- mergeOverwrite $globalDefaults .Values.global | toJson -}}
  {{ else }}
    {{- $globalDefaults | toJson -}}
  {{ end }}
{{ end }}

{{/*
Create annotation for the product information (DR-D1121-064, DR-D1121-067)
*/}}
{{- define "eric-enm-permissions-mgr.product-info" }}
ericsson.com/product-name: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productName | quote }}
ericsson.com/product-number: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productNumber | quote }}
ericsson.com/product-revision: {{ regexReplaceAll "(.*)[+|-].*" .Chart.Version "${1}" | quote }}
{{- end}}

{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-enm-permissions-mgr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart version as used by the chart label.
*/}}
{{- define "eric-enm-permissions-mgr.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-enm-permissions-mgr.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-enm-permissions-mgr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{/*
Create image registry url
*/}}
{{- define "eric-enm-permissions-mgr.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-enm-permissions-mgr.pullSecrets" -}}
    {{- $globalPullSecret := "" -}}
    {{- if .Values.global -}}
        {{- if .Values.global.pullSecret -}}
            {{- $globalPullSecret = .Values.global.pullSecret -}}
        {{- end -}}
        {{- if .Values.global.registry.pullSecret -}}
            {{- $globalPullSecret = .Values.global.registry.pullSecret -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials.pullSecret -}}
        {{- print .Values.imageCredentials.pullSecret -}}
    {{- else if $globalPullSecret -}}
        {{- print $globalPullSecret -}}
    {{- end -}}
{{- end -}}

{{- define "eric-enm-permissions-mgr.registryImagePullPolicy" -}}
    {{- $globalRegistryPullPolicy := "IfNotPresent" -}}
    {{- if .Values.global -}}
        {{- if .Values.global.registry -}}
            {{- if .Values.global.registry.imagePullPolicy -}}
                {{- $globalRegistryPullPolicy = .Values.global.registry.imagePullPolicy -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials.mainImage.registry -}}
        {{- if .Values.imageCredentials.mainImage.registry.imagePullPolicy -}}
        {{- $globalRegistryPullPolicy = .Values.imageCredentials.mainImage.registry.imagePullPolicy -}}
        {{- end -}}
    {{- end -}}
    {{- print $globalRegistryPullPolicy -}}
{{- end -}}


{{/*
Create annotation for the product information (DR-D1121-064, DR-D1121-067)
*/}}

{{/*
Create a user defined annotation (DR-D1121-065, DR-D1121-060)
*/}}
{{ define "eric-enm-permissions-mgr.config-annotations" }}
  {{- $global := (.Values.global).annotations -}}
  {{- $service := .Values.annotations -}}
  {{- include "eric-enm-permissions-mgr.mergeAnnotations" (dict "location" .Template.Name "sources" (list $global $service)) }}
{{- end }}

{{/*
Merged annotations for Default, which includes productInfo and config
*/}}
{{- define "eric-enm-permissions-mgr.annotations" -}}
  {{- $productInfo := include "eric-enm-permissions-mgr.product-info" . | fromYaml -}}
  {{- $config := include "eric-enm-permissions-mgr.config-annotations" . | fromYaml -}}
  {{- include "eric-enm-permissions-mgr.mergeAnnotations" (dict "location" .Template.Name "sources" (list $productInfo $config)) | trim }}
{{- end -}}

{{/*
Standard labels of Helm and Kubernetes
*/}}
{{- define "eric-enm-permissions-mgr.standard-labels" -}}
app.kubernetes.io/name: {{ include "eric-enm-permissions-mgr.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ include "eric-enm-permissions-mgr.version" . }}
helm.sh/chart: {{ include "eric-enm-permissions-mgr.chart" . }}
chart: {{ include "eric-enm-permissions-mgr.chart" . }}
{{- end -}}

{{/*
Standard labels of Helm and Kubernetes for standalone
*/}}
{{- define "eric-enm-permissions-mgr.standard-labels-singleton" -}}
app.kubernetes.io/name: {{ include "eric-enm-permissions-mgr.name" . }}-singleton
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ include "eric-enm-permissions-mgr.version" . }}
helm.sh/chart: {{ include "eric-enm-permissions-mgr.chart" . }}
chart: {{ include "eric-enm-permissions-mgr.chart" . }}
{{- end -}}

{{/*
Stateful labels of Helm and Kubernetes for standalone
*/}}
{{- define "eric-enm-permissions-mgr.standard-labels-stateful" -}}
app.kubernetes.io/name: {{ include "eric-enm-permissions-mgr.name" . }}-stateful
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ include "eric-enm-permissions-mgr.version" . }}
helm.sh/chart: {{ include "eric-enm-permissions-mgr.chart" . }}
chart: {{ include "eric-enm-permissions-mgr.chart" . }}
{{- end -}}

{{/*
Create a user defined label (DR-D1121-068, DR-D1121-060)
*/}}
{{ define "eric-enm-permissions-mgr.config-labels" }}
  {{- $global := (.Values.global).labels -}}
  {{- $service := .Values.labels -}}
  {{- include "eric-enm-permissions-mgr.mergeLabels" (dict "location" .Template.Name "sources" (list $global $service)) }}
{{- end }}

{{/*
Merged labels for Default, which includes Standard and Config
*/}}
{{- define "eric-enm-permissions-mgr.labels" -}}
  {{- $standard := include "eric-enm-permissions-mgr.standard-labels" . | fromYaml -}}
  {{- $config := include "eric-enm-permissions-mgr.config-labels" . | fromYaml -}}
  {{- include "eric-enm-permissions-mgr.mergeLabels" (dict "location" .Template.Name "sources" (list $standard $config)) | trim }}
{{- end -}}

{{/*
Merged labels for Standalone, which includes Standard and Config
*/}}
{{- define "eric-enm-permissions-mgr.labels-singleton" -}}
  {{- $standard := include "eric-enm-permissions-mgr.standard-labels-singleton" . | fromYaml -}}
  {{- $config := include "eric-enm-permissions-mgr.config-labels" . | fromYaml -}}
  {{- include "eric-enm-permissions-mgr.mergeLabels" (dict "location" .Template.Name "sources" (list $standard $config)) | trim }}
{{- end -}}

{{/*
Merged labels for Stateful, which includes Standard and Config
*/}}
{{- define "eric-enm-permissions-mgr.labels-stateful" -}}
  {{- $standard := include "eric-enm-permissions-mgr.standard-labels-stateful" . | fromYaml -}}
  {{- $config := include "eric-enm-permissions-mgr.config-labels" . | fromYaml -}}
  {{- include "eric-enm-permissions-mgr.mergeLabels" (dict "location" .Template.Name "sources" (list $standard $config)) | trim }}
{{- end -}}

{{/*
Generate chart secret name
*/}}
{{- define "eric-enm-permissions-mgr.secretName" -}}
{{ default (include "eric-enm-permissions-mgr.fullname" .) .Values.existingSecret }}
{{- end -}}


{{/*
Create annotations for roleBinding.
*/}}
{{- define "eric-enm-permissions-mgr.securityPolicy.annotations" }}
ericsson.com/security-policy.type: "restricted/default"
ericsson.com/security-policy.privileged: "false"
ericsson.com/security-policy.capabilities: "N/A"
{{- end -}}
{{/*
Create roleBinding reference.
*/}}
{{- define "eric-enm-permissions-mgr.securityPolicy.reference" -}}
    {{- if .Values.global -}}
        {{- if .Values.global.security -}}
            {{- if .Values.global.security.policyReferenceMap -}}
              {{ $mapped := index .Values "global" "security" "policyReferenceMap" "default-restricted-security-policy" }}
              {{- if $mapped -}}
                {{ $mapped }}
              {{- else -}}
                {{ $mapped }}
              {{- end -}}
            {{- else -}}
              default-restricted-security-policy
            {{- end -}}
        {{- else -}}
          default-restricted-security-policy
        {{- end -}}
    {{- else -}}
      default-restricted-security-policy
    {{- end -}}
{{- end -}}

{{- define "eric-enm-permissions-mgr.allowPrivilegeEscalation" -}}
    {{- if .Values.permissionMgrConfigs.root_squash  -}}
        false
    {{- else -}}
        {{- .Values.securityContext.allowPrivilegeEscalation -}}
    {{- end -}}
{{- end -}}

