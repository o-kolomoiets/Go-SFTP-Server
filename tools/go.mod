// Developer tools, kept in a separate module so they never enter the
// dependency graph of gosftpd. Run them with: go tool -modfile=tools/go.mod <name>
module github.com/o-kolomoiets/go-sftp-server/tools

go 1.26.5

tool (
	github.com/rhysd/actionlint/cmd/actionlint
	golang.org/x/vuln/cmd/govulncheck
	gotest.tools/gotestsum
	honnef.co/go/tools/cmd/staticcheck
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/bitfield/gotestdox v0.2.3 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.4 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dnephin/pflag v1.0.7 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.31 // indirect
	github.com/mattn/go-shellwords v1.0.16 // indirect
	github.com/rhysd/actionlint v1.7.12 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.3 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
	gotest.tools/gotestsum v1.13.0 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)
