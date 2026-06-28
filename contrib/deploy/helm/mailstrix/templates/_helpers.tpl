{{/*
Expand the name of the chart.
*/}}
{{- define "mailstrix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "mailstrix.fullname" -}}
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
{{- define "mailstrix.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mailstrix.labels" -}}
helm.sh/chart: {{ include "mailstrix.chart" . }}
{{ include "mailstrix.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mailstrix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mailstrix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Container image (repository:tag) — tag falls back to Chart.appVersion.
*/}}
{{- define "mailstrix.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Name of the service account to use.
*/}}
{{- define "mailstrix.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mailstrix.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the auth token (existing or chart-created).
*/}}
{{- define "mailstrix.tokenSecretName" -}}
{{- if .Values.token.existingSecret -}}
{{- .Values.token.existingSecret -}}
{{- else -}}
{{- printf "%s-token" (include "mailstrix.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding the abuse.ch key (existing or chart-created).
*/}}
{{- define "mailstrix.abuseChSecretName" -}}
{{- if .Values.abuseChKey.existingSecret -}}
{{- .Values.abuseChKey.existingSecret -}}
{{- else -}}
{{- printf "%s-abusech" (include "mailstrix.fullname" .) -}}
{{- end -}}
{{- end }}
