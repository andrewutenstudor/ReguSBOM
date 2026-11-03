{{/*
Expand the name of the chart.
*/}}
{{- define "sbom-validator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sbom-validator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sbom-validator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Backend full name
*/}}
{{- define "sbom-validator.backend.fullname" -}}
{{- printf "%s-backend" (include "sbom-validator.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Frontend full name
*/}}
{{- define "sbom-validator.frontend.fullname" -}}
{{- printf "%s-frontend" (include "sbom-validator.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
PVC Name
*/}}
{{- define "sbom-validator.pvcName" -}}
{{- if .Values.persistence.claimName }}
{{- .Values.persistence.claimName }}
{{- else }}
{{- printf "%s-data" (include "sbom-validator.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sbom-validator.labels" -}}
helm.sh/chart: {{ include "sbom-validator.chart" . }}
{{ include "sbom-validator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sbom-validator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-validator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend labels
*/}}
{{- define "sbom-validator.backend.labels" -}}
{{ include "sbom-validator.labels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Backend selector labels
*/}}
{{- define "sbom-validator.backend.selectorLabels" -}}
{{ include "sbom-validator.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "sbom-validator.frontend.labels" -}}
{{ include "sbom-validator.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "sbom-validator.frontend.selectorLabels" -}}
{{ include "sbom-validator.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}
