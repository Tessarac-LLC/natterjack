{{/* Chart label value. */}}
{{- define "natterjack.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels every object carries. */}}
{{- define "natterjack.labels" -}}
helm.sh/chart: {{ include "natterjack.chart" . }}
app.kubernetes.io/part-of: natterjack
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/* Selector labels of a component; call with (dict "root" $ "component" "agent"). */}}
{{- define "natterjack.selectorLabels" -}}
app.kubernetes.io/name: natterjack-{{ .component }}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{/* All labels of a component's objects. */}}
{{- define "natterjack.componentLabels" -}}
{{ include "natterjack.labels" .root }}
{{ include "natterjack.selectorLabels" . }}
{{- end -}}

{{/* The selector both binaries use to find agent pods. */}}
{{- define "natterjack.agentSelector" -}}
app.kubernetes.io/name=natterjack-agent,app.kubernetes.io/component=agent,app.kubernetes.io/instance={{ .Release.Name }}
{{- end -}}

{{/* Object name prefix, unique per release. */}}
{{- define "natterjack.fullname" -}}
{{- if contains "natterjack" .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "natterjack-%s" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "natterjack.controller.serviceAccount" -}}
{{- default (printf "%s-controller" (include "natterjack.fullname" .)) .Values.controller.serviceAccount.name -}}
{{- end -}}

{{- define "natterjack.agent.serviceAccount" -}}
{{- default (printf "%s-agent" (include "natterjack.fullname" .)) .Values.agent.serviceAccount.name -}}
{{- end -}}

{{/* Image reference; call with (dict "root" $ "image" .Values.agent.image). */}}
{{- define "natterjack.image" -}}
{{- if .image.digest -}}
{{ .image.repository }}@{{ .image.digest }}
{{- else -}}
{{ .image.repository }}:{{ default .root.Chart.AppVersion .image.tag }}
{{- end -}}
{{- end -}}

{{- define "natterjack.pullSecrets" -}}
{{- with .Values.images.pullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end -}}
