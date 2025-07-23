{{/*
Expand the name of the chart.
*/}}
{{- define "go-auth-system.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "go-auth-system.fullname" -}}
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
{{- define "go-auth-system.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "go-auth-system.labels" -}}
helm.sh/chart: {{ include "go-auth-system.chart" . }}
{{ include "go-auth-system.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "go-auth-system.selectorLabels" -}}
app.kubernetes.io/name: {{ include "go-auth-system.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "go-auth-system.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "go-auth-system.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "go-auth-system.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- $repository := .Values.image.repository -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- else }}
{{- printf "%s:%s" $repository $tag }}
{{- end }}
{{- end }}

{{/*
Create database connection string
*/}}
{{- define "go-auth-system.databaseHost" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- .Values.externalDatabase.host }}
{{- end }}
{{- end }}

{{/*
Create Redis connection string
*/}}
{{- define "go-auth-system.redisHost" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" .Release.Name }}
{{- else }}
{{- .Values.externalRedis.host }}
{{- end }}
{{- end }}

{{/*
Create secret name
*/}}
{{- define "go-auth-system.secretName" -}}
{{- printf "%s-secrets" (include "go-auth-system.fullname" .) }}
{{- end }}

{{/*
Create config map name
*/}}
{{- define "go-auth-system.configMapName" -}}
{{- printf "%s-config" (include "go-auth-system.fullname" .) }}
{{- end }}

{{/*
Validate required values
*/}}
{{- define "go-auth-system.validateValues" -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.externalDatabase.host) }}
{{- fail "Either postgresql.enabled must be true or externalDatabase.host must be set" }}
{{- end }}
{{- if and (not .Values.redis.enabled) (not .Values.externalRedis.host) }}
{{- fail "Either redis.enabled must be true or externalRedis.host must be set" }}
{{- end }}
{{- end }}