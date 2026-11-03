{{/*
Expand the name of the chart.
*/}}
{{- define "regubom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "regubom.fullname" -}}
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
{{- define "regubom.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "regubom.labels" -}}
helm.sh/chart: {{ include "regubom.chart" . }}
{{ include "regubom.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: regubom
{{- end }}

{{/*
Selector labels
*/}}
{{- define "regubom.selectorLabels" -}}
app.kubernetes.io/name: {{ include "regubom.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend specific names and labels
*/}}
{{- define "regubom.backend.fullname" -}}
{{- printf "%s-backend" (include "regubom.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "regubom.backend.labels" -}}
{{ include "regubom.labels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{- define "regubom.backend.selectorLabels" -}}
{{ include "regubom.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Frontend specific names and labels
*/}}
{{- define "regubom.frontend.fullname" -}}
{{- printf "%s-frontend" (include "regubom.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "regubom.frontend.labels" -}}
{{ include "regubom.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{- define "regubom.frontend.selectorLabels" -}}
{{ include "regubom.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
PostgreSQL specific names and labels
*/}}
{{- define "regubom.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "regubom.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "regubom.postgresql.labels" -}}
{{ include "regubom.labels" . }}
app.kubernetes.io/component: database
{{- end }}

{{- define "regubom.postgresql.selectorLabels" -}}
{{ include "regubom.selectorLabels" . }}
app.kubernetes.io/component: database
{{- end }}

{{/*
ServiceAccount names
*/}}
{{- define "regubom.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "regubom.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Render Image Reference with ImageRegistry Override
Usage: {{ include "regubom.image" (dict "image" .Values.backend.image "root" .) }}
*/}}
{{- define "regubom.image" -}}
{{- $registry := .image.registry | default .root.Values.imageRegistry | default .root.Values.global.imageRegistry -}}
{{- $tag := .image.tag | default .root.Chart.AppVersion -}}
{{- if $registry -}}
  {{- printf "%s/%s:%s" (trimSuffix "/" $registry) .image.repository $tag -}}
{{- else -}}
  {{- printf "%s:%s" .image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Render Image Pull Policy respecting air-gapped mode
*/}}
{{- define "regubom.pullPolicy" -}}
{{- if and .root.Values.global.airgapped (not .image.pullPolicy) -}}
IfNotPresent
{{- else -}}
{{- .image.pullPolicy | default "IfNotPresent" -}}
{{- end -}}
{{- end }}

{{/*
Backend PVC Name
*/}}
{{- define "regubom.backend.pvcName" -}}
{{- if .Values.persistence.claimName -}}
{{- .Values.persistence.claimName -}}
{{- else -}}
{{- printf "%s-backend-data" (include "regubom.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
App Secrets Name
*/}}
{{- define "regubom.secretName" -}}
{{- if .Values.backend.secrets.existingSecret -}}
{{- .Values.backend.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "regubom.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Database Secret Name
*/}}
{{- define "regubom.dbSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgresql-secret" (include "regubom.fullname" .) -}}
{{- end -}}
{{- end }}
