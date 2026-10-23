{{- /*
THIRD_PARTY_LICENSES of the release archives and packages: make generate
runs go-licenses report with this template (ADR 0012). Each module with
its version, license and the text of its license file. Never .LicenseURL:
go-licenses looks it up online and writes "Unknown" when that fails.
go-licenses lists libcap/psx twice, as GPL-2.0 and as BSD-3-Clause, the
two licenses its license file offers; gosftpd uses it under BSD-3-Clause
(docs/DEPENDENCIES.md), so only that entry is printed.
*/ -}}
gosftpd is licensed under the Apache License 2.0 (see LICENSE). Its binary
includes the following Go modules, each under the license named with it.
{{ range . }}{{ if or (ne .Name "kernel.org/pub/linux/libs/security/libcap/psx") (eq .LicenseName "BSD-3-Clause") }}
================================================================================
{{ .Name }} {{ .Version }}
License: {{ .LicenseName }}

{{ .LicenseText }}{{ end }}{{ end -}}
