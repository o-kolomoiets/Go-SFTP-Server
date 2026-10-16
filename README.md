<h1 align="center">gosftpd</h1>

<p align="center">
  <strong>Turn a folder into an SFTP drop-box.</strong><br>
  A single Go binary for taking files from partners, devices and backup jobs.<br>
  No root, no system accounts, no database. Clients can't leave the folder,
  uploads don't overwrite by default, and every login, transfer and change lands
  in a JSON audit log.
</p>

<p align="center">
  <a href="https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/o-kolomoiets/go-sftp-server/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/o-kolomoiets/go-sftp-server"></a>
  <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/o-kolomoiets/go-sftp-server"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <!-- Add once the first weekly Scorecard run has published a score:
  <a href="https://scorecard.dev/viewer/?uri=github.com/o-kolomoiets/Go-SFTP-Server"><img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/o-kolomoiets/Go-SFTP-Server/badge"></a>
  -->
</p>

<p align="center">
  <a href="#try-it-in-one-minute">Quick start</a> ·
  <a href="#a-partner-inbox-in-nine-lines">Partner inbox in 9 lines</a> ·
  <a href="https://github.com/o-kolomoiets/go-sftp-server/releases">Releases</a> ·
  <a href="#files-from-strangers-safely">Security</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

## Try it in one minute

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest   # v0.3.0, needs Go 1.26.5+
mkdir -p inbox && gosftpd serve --dir ./inbox                          # as yourself, not root
sftp -P 2022 "$USER@localhost"                                         # in a second terminal
```

No config file: every key in your `~/.ssh/authorized_keys` gets full access
to `./inbox`, under any user name, on port 2022 of every interface (add
`--listen 127.0.0.1:2022` to keep it on this machine). On first start
gosftpd creates an ed25519 host key and prints its fingerprint and a
`known_hosts` line, so you can check what your client is told. No Go
toolchain? Take a [release archive](#install): one binary of about 7 MB for
Linux or macOS.

<p align="center">
  <img src="docs/assets/demo.gif" width="760" alt="Terminal recording in two panes. Server pane: gosftpd serve --dir ./inbox --audit-output audit.jsonl prints its version, a newly generated ed25519 host key saved with mode 0600, its SHA256 fingerprint, a known_hosts line, the mount / -> /home/alex/inbox with on_conflict=rename, listen 0.0.0.0:2022 and a connect hint. Client pane: sftp uploads report.pdf twice; ls -l lists report (1).pdf next to report.pdf, both owned by alex; cd .. and pwd still show /; ls /etc says not found. Finally jq prints the audit event from audit.jsonl: fs.upload by alex, path /report.pdf, final_path /report (1).pdf, conflict renamed, 48000 bytes.">
</p>
<p align="center"><sub>
  A real session with the v0.3.0 release binary, typed by <a href="docs/assets/record-demo.py">a script</a> you can run to record it again.
  The second upload becomes <code>report (1).pdf</code>, <code>cd ..</code> goes nowhere, and the audit log says exactly what happened.
</sub></p>

With one command on the server, you got:

- **A host key you can verify.** The fingerprint is printed, so the first
  "yes" to your client is not a blind one.
- **A client that stays in the folder.** `/` is `./inbox`: `..` stops
  there, `/etc` means `./inbox/etc`, and symlinks that lead outside are
  refused.
- **No silent overwrites.** A second `report.pdf` arrives as
  `report (1).pdf`. Want something else? `--on-conflict reject`, `overwrite`
  or `version`.
- **A paper trail.** Each login, transfer and change is one JSON
  line on stdout, or in a file with `--audit-output audit.jsonl`, as in the
  recording.
- **SFTP and nothing more.** No shell, no exec, no port forwarding, even for
  keys that could log in to your real sshd.

Serve several folders with `--dir docs=/srv/docs --dir inbox=/srv/inbox`,
make them `--read-only`, or accept only one login name with `--user NAME`.
For anything narrower, such as a partner who may only upload, write a
[config file](#a-partner-inbox-in-nine-lines).

<details>
<summary>What the server prints, and what to do if it stops right away</summary>

The real output of the first start, from the session in the GIF, on a host
named `vm`:

```text
gosftpd v0.3.0 (commit 2bd0b1fb2102, 2026-10-09T21:19:06Z, go1.27.2 linux/amd64)
host key: /home/alex/.config/gosftpd/ssh_host_ed25519_key (generated, 0600)
  ED25519 SHA256:abbhjU4ZiDmJE0dNQVwJ4LuCj4L36ufuu5MarxbQs6s
  known_hosts: [vm]:2022 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPCKbAEGDs8uNKcEO8EAZCUkEJMOP8XHoDCccnDQCGG
auth:    publickey, 1 keys from /home/alex/.ssh/authorized_keys
mounts:  / -> /home/alex/inbox (rw, on_conflict=rename)
listen:  0.0.0.0:2022
connect: sftp -P 2022 <user>@vm
```

Compare the fingerprint with the one `sftp` shows on first connect. The
audit log follows on stdout; the banner and other messages go to stderr.

If you have no `~/.ssh/authorized_keys`, gosftpd says so and exits:

```text
Error: no --authorized-keys given and /home/alex/.ssh/authorized_keys does not exist; add your public key there or pass --authorized-keys FILE
```

`cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`
fixes that (create a key with `ssh-keygen -t ed25519` first if you have
none). Like sshd, gosftpd refuses an `authorized_keys` that group or others
can write. `go install` puts the binary in `$(go env GOPATH)/bin`, which
must be in your `PATH`.

</details>

> [!NOTE]
> **Alpha.** Every change is fuzzed and run in CI against OpenSSH `sftp` and
> `scp`, paramiko, rclone and lftp ([the evidence](#proof-not-promises)), but
> configuration and behavior may still change until the v1.0 compatibility
> freeze. Read the [hardening guide](https://github.com/o-kolomoiets/go-sftp-server/blob/v0.3.0/docs/security/hardening.md)
> before you expose v0.3.0 to the internet.

## Why gosftpd

Sooner or later someone needs to send you files over SFTP: an accounting firm
with payroll sheets, a bank with statements, a device on the office network,
a nightly backup. Receiving them should not mean picking one of these:

- **OpenSSH `internal-sftp` with `ChrootDirectory`:** root, a system account
  per partner, root-owned chroot directories, `Match` blocks in
  `sshd_config`, and a second `report.pdf` that quietly replaces the first.
- **SFTPGo:** a capable platform (web admin, database, FTP, WebDAV, cloud
  backends) when all you wanted was one folder.
- **A managed endpoint** such as AWS Transfer Family: billed for every hour it
  is switched on, whether anyone uploads or not.

gosftpd does one job: **a folder that other people can put files into,
safely.** One binary that you run as an ordinary user, one TOML file, one JSON
log. Your accountant doesn't need a Unix account on your server.

What it is for:

- **Partner inbox.** Payroll sheets, statements, invoices, EDI files. The
  `upload` preset lets a partner list, upload and create folders, but not
  read, delete or overwrite anything, and `allow_from` and `expires` tie
  them to a network and an end date. If someone sends `payroll-october.xlsx`
  twice, the second one lands as `payroll-october (1).xlsx`.
- **Devices and scripts that push files.** Give each one a folder of its own
  with a `{user}` home. Password login (argon2id) is there, off by default,
  for senders that can't use keys. With `atomic_uploads = true` a file takes
  its name only when the client closes it; until then it is a hidden
  `.gosftpd-*.part` file in the same folder, so have the watching job skip
  dot-files.
- **Backup targets.** Use `on_conflict = "version"`: rclone and friends keep
  their file names, and the old content moves to a hidden `.versions/`
  folder that clients can read but not change. With the default `rename`,
  every sync run would add a copy.
- **CI artifacts.** A deploy key, `scp` or `sftp -b`, and
  `on_conflict = "reject"`, so an upload never replaces a published file.
- **Your own machines.** `gosftpd serve --dir ./share` moves files between
  your laptop and a VM in one command. It gives every key full access, so
  keep partners in a config file.

## Files from strangers, safely

A drop-box takes files from clients you don't control. Everything in gosftpd
starts from what such a client must **not** be able to do. All of this is in
the v0.3.0 release. A client can't:

- **Leave the folder.** Each mount is opened as a Go
  [`os.Root`](https://pkg.go.dev/os#Root). `..` stops at the folder's `/`,
  absolute paths start there, and symlinks that lead outside are refused.
  Clients can't create symlinks or hard links, FIFOs and devices are hidden,
  no host path appears in any reply, and listings show the user's own name
  as owner instead of your uids.
- **Overwrite what is already there.** A second `report.pdf` arrives as
  `report (1).pdf` (and `a.tar.gz` as `a (1).tar.gz`). For a minute
  afterwards, a stat of the name the client asked for answers for its copy,
  so paramiko `put(confirm=True)` and rclone's size checks still pass. Per
  folder you can choose `reject`, `overwrite` (needs that permission) or
  `version`, which moves the old file into a hidden `.versions` folder that
  clients can read but not change. Each new version of a file removes that
  file's versions older than 30 days and, if the uploader may delete or
  overwrite, all but the newest 10.
- **Rewrite bytes that already arrived.** Resuming works (OpenSSH `reput`,
  paramiko append mode), but only by appending: existing data is immutable.
- **Read or delete the inbox,** if you give it the `upload` preset: list,
  write and mkdir, nothing else. Uploaders may still rename and set times on
  files they created in the last hour, so tools that upload under a temporary
  name, such as rclone, keep working.
- **Get a shell.** Only the `sftp` subsystem is served. Shell, exec, pty,
  env, agent and port forwarding are refused, even for keys that could log in
  to your real sshd.
- **Start uploads on a nearly full disk.** Opening a file for writing is
  refused when less than 1 GiB is free (configurable; not on Windows). Set
  `max_file_size` (off by default) to cap each file: it is checked against
  the end of every write, so sparse writes can't slip past it. There are no
  per-user quotas.
- **Leave half a file behind.** With `atomic_uploads = true`, uploads go to
  a hidden temp file and take their name only when the client closes it. A
  killed client or a dropped connection leaves nothing. Off by default,
  since resume is not possible in this mode.
- **Transfer or change anything unrecorded.** One JSON line per login,
  transfer and change, with a versioned schema. If the log can't be written (disk full, closed
  pipe), gosftpd refuses new connections and every change until it can:
  **fail-closed** by default.
- **Probe for users or hammer the door.** An unknown user, a wrong key or
  password, a disabled or expired account and a disallowed address all fail
  the same way, and each failed login is in your audit log. Connections are
  counted before the SSH handshake (256 in total, 16 per IP or IPv6 /64, 64
  not yet logged in), and 10 failures in 10 minutes earn a 30-minute ban.
  With password login on, response times hide which users exist only while
  all password hashes share one kind and cost (`config validate` warns
  otherwise).

And for you, the person running it:

- **No root, no accounts, no database.** `gosftpd serve` refuses to run as root
  unless you pass `--allow-root`. Users and permissions live in one TOML file.
- **Permissions per folder, per user.** Presets `read`, `upload`, `readwrite`
  and `full`, or any of 9 flags. A mount path ending in `{user}` gives each
  user a home directory of their own.
- **Typos are errors.** Unknown keys fail, and `gosftpd config validate` lists
  every problem at once with its key path.
- **No loose key files.** Like sshd's `StrictModes`, gosftpd won't start if
  its config, host keys or `authorized_keys` files are writable by group or
  others, or owned by anyone but root or the user it runs as.
- **Modern crypto by default.** Post-quantum hybrid `mlkem768x25519-sha256`
  (used automatically by OpenSSH 9.9+) and `curve25519-sha256`;
  ChaCha20-Poly1305, AES-GCM and AES-CTR. Never SHA-1, CBC or DSA; strict KEX
  against Terrapin. A `compat` policy exists for old clients.
- **The keys you already have.** ed25519, ECDSA, RSA of 2048 bits or more, and
  FIDO security keys (`sk-ssh-ed25519@openssh.com`); `from=` and
  `expiry-time=` options; per-user `allow_from` and `expires`. Passwords only
  if you turn them on, hashed with argon2id (19 MiB, t=2, p=1); passwords
  over 1024 bytes are refused before hashing.

Know the limits, too. `os.Root` keeps clients in the folder, but it does not
cover bind mounts inside a served folder, hard links made on the host, or
races with symlinks that local users create.
[Here is exactly what is and isn't covered.](https://github.com/o-kolomoiets/go-sftp-server/blob/v0.3.0/docs/security.md#limits-of-the-protection)
Bans are kept in memory and reset on restart, and the limits count
connections, not their rate: rate-limit new connections in your firewall.

## A partner inbox in nine lines

Save this as `gosftpd.toml` in the directory you start gosftpd from;
`gosftpd serve` finds it on its own.

```toml
config_version = 1
[server]
host_keys = ["/var/lib/gosftpd/ssh_host_ed25519_key"]
host_key_auto_generate = true      # create the key on first start
[mounts.inbox]
path = "/srv/sftp/inbox"
[users.partner]
authorized_keys = ["ssh-ed25519 AAAA... partner@laptop"]
access = { inbox = "upload" }      # list and upload; no reading, deleting or overwriting
```

```console
$ chmod 600 gosftpd.toml     # gosftpd refuses a config that group or others can write
$ gosftpd config validate --check-fs
/home/alex/gosftpd.toml: OK (1 mounts, 1 users)
$ gosftpd serve
```

Run it as a dedicated user that owns `/srv/sftp/inbox` and `/var/lib/gosftpd`
(or add `create = true` to the mount to have the folder created). If you
already have a host key, drop `host_key_auto_generate` and it's eight lines.

Your partner sees one folder as `/`. Their client says both uploads went to
`/report.pdf`, yet nothing was replaced, and reading and deleting are refused:

```console
sftp> put report.pdf
Uploading report.pdf to /report.pdf
report.pdf                                    100%   47KB  42.0MB/s   00:00
sftp> put report.pdf
Uploading report.pdf to /report.pdf
report.pdf                                    100%   47KB  48.8MB/s   00:00
sftp> ls -l
-rw-r-----    1 partner  partner     48000 Oct 11 19:03 report (1).pdf
-rw-r-----    1 partner  partner     48000 Oct 11 19:03 report.pdf
sftp> get report.pdf
Fetching /report.pdf to report.pdf
remote open "/report.pdf": Permission denied
sftp> rm report.pdf
Removing /report.pdf
remote delete /report.pdf: Permission denied
```

And you see what they did. This is the second upload, as gosftpd v0.3.0 wrote
it to the audit log (pretty-printed here):

```json
{
  "time": "2026-10-11T19:03:51.877756975Z",
  "level": "INFO",
  "msg": "audit",
  "conn_id": "7bc79af4f34b75f4",
  "remote_addr": "127.0.0.1:38934",
  "local_addr": "127.0.0.1:2022",
  "user": "partner",
  "session_id": "83aa8a68188c1ebe",
  "schema": 1,
  "event": "fs.upload",
  "path": "/report.pdf",
  "final_path": "/report (1).pdf",
  "conflict": "renamed",
  "open_flags": "WRITE+CREAT+TRUNC",
  "bytes": 48000,
  "duration_ms": 1,
  "result": "ok"
}
```

The refused download and delete are there too, as `fs.denied` events, and the
`auth.success` event for the same `conn_id` names the key that logged in
(`key_fp`). Every key is in the
[configuration reference](https://github.com/o-kolomoiets/go-sftp-server/blob/v0.3.0/docs/configuration.md).

Several partners on one shared upload folder can see each other's file
names. When that matters, as with payroll, give each partner a folder of
their own:

<details>
<summary>A bigger example: a folder per partner, a shared read-only folder, a network and an end date</summary>

```toml
config_version = 1

[server]
host_keys = ["/var/lib/gosftpd/ssh_host_ed25519_key"]
host_key_auto_generate = true

[mounts.inbox]
path = "/srv/sftp/inbox/{user}"    # a folder of their own for every user
create = true
on_conflict = "version"            # a new upload replaces, the old copy goes to .versions/

[mounts.docs]
path = "/srv/sftp/docs"            # one folder that everyone may read

[users.partner]
authorized_keys = ["ssh-ed25519 AAAA... partner@laptop"]
allow_from = ["203.0.113.0/24"]    # only from their network
expires = 2026-12-31T23:59:59Z     # and only until the end of the year
access = { inbox = "upload", docs = "read" }

[users.scanner]
authorized_keys_file = "/etc/gosftpd/keys/scanner.pub"
access = { inbox = "upload" }
```

You collect the files on the server, in `/srv/sftp/inbox/partner/` and
`/srv/sftp/inbox/scanner/`. `gosftpd config example --full` prints every key
with its default, and `gosftpd user add` prints a ready `[users.NAME]` block
for a new partner.

</details>

## Proof, not promises

A security tool should show its work. This is what runs in CI today:

- **Fuzzed on every change.** 6 fuzz targets in v0.3.0 (9 on `main`): path
  resolution, confinement on a tree full of symlinks, conflict names, the
  config parser, `authorized_keys`, and arbitrary SFTP packets against the
  real handlers; `main` adds certificates, PROXY protocol headers and host
  key proofs. Each runs 60 s with `-race` on every pull request and 10
  minutes every night. Fuzzing has already found real bugs, among them a
  data race in pkg/sftp v1.13 that could crash a server (gosftpd works around
  it), a config parser panic and an off-by-one in the path length limit.
- **Tested against real clients.** Every change runs OpenSSH `sftp` and `scp`
  (9.6p1 and 10.6p1), paramiko 5.0.0, rclone v1.75.0 and lftp 4.9.2 against a
  fresh build: escapes, overwrites, resume, permissions, `kill -9` in the
  middle of an upload. The latest run on `main` passed more than 170 checks.
  [Details per client.](docs/interop.md)
- **Crypto checked by ssh-audit.** ssh-audit 3.9.0 reports 0 failures on the
  default policy. Its 2 warnings are for the classic curve25519 key exchange
  (no post-quantum protection), which stays on for clients without ML-KEM.
- **Coverage with floors.** 90.9% of the code on `main` is covered (unit and
  interop tests merged). CI fails if the auth, config, hooks, sandbox, sftpd
  or vfs packages drop below their floors; auth is at 97.5%.
- **All the usual gates.** Unit tests with `-race -shuffle=on` on Linux
  (amd64 and arm64) and macOS, plus Windows (without `-race`), each on two Go
  versions; goroutine leak checks, govulncheck, golangci-lint, CodeQL,
  Dependabot, and every GitHub Action pinned by commit SHA.
- **Few dependencies.** 11 third-party Go modules in the Linux binary
  (x/crypto, pkg/sftp, BurntSushi/toml, cobra, go-proxyproto, go-landlock
  and their helpers; 9 on macOS), no cgo, no database.
  CI fails any release binary over 12 MiB.
- **More tests than code.** Over 27k lines of tests for about 22k lines of
  Go on `main`. Tests also fail if a config key, an audit event or a metric
  is missing from the docs.
- **Decisions written down.** A [threat model](docs/security/threat-model.md),
  a [hardening guide](docs/security/hardening.md) and 11
  [design records](docs/adr/).

Found a vulnerability? Please report it privately, as described in
[SECURITY.md](SECURITY.md).

## How it compares

|  | Runs as | Users live in | Same file uploaded twice | Audit trail | Choose it when |
|---|---|---|---|---|---|
| **gosftpd** | an ordinary user (refuses root) | one TOML file | **kept**: the second one is `report (1).pdf`; or reject, version, overwrite | a JSON line per login, transfer and change; fail-closed | you want a safe drop folder with a paper trail |
| OpenSSH `internal-sftp` + `ChrootDirectory` | root (sshd, root-owned chroot) | system accounts | replaced | syslog (`internal-sftp -l`) | you already run sshd and manage a few system accounts |
| SFTPGo | an ordinary user | its database, via web UI or REST API | replaced, if the user has the `overwrite` permission | JSON logs, event actions | you need a web UI, FTP/WebDAV/HTTP or S3/GCS/Azure storage |
| AWS Transfer Family | managed by AWS | service-managed users or your identity provider | replaced (S3 versioning optional) | CloudWatch | you want AWS to run it; billed per endpoint-hour plus per GB |
| `rclone serve sftp` | an ordinary user | one login, or an `--auth-proxy` program | replaced | rclone's log | you want to expose an rclone remote quickly |
| `atmoz/sftp` | root inside a container | container arguments or `users.conf` | replaced | sshd's log | you want the OpenSSH approach in Docker |

This compares defaults and design as of October 2026, not speed: none of
these, gosftpd included, has been benchmarked here. If you need a web UI,
other protocols or cloud storage, SFTPGo is the better tool. If a cell is
wrong, [open an issue](https://github.com/o-kolomoiets/go-sftp-server/issues).

## Client compatibility

CI tests every change with OpenSSH `sftp` and `scp`, paramiko, rclone and
lftp, directly and through HAProxy and nginx. Things to know:

- `scp` works over the SFTP protocol, the default since OpenSSH 9.0; legacy
  `scp -O` does not.
- rclone needs `shell_type = none` (or `--sftp-shell-type none`).
- **Not tested yet:** WinSCP, FileZilla, Cyberduck, PuTTY and device
  firmware. If you try gosftpd with one of them, please
  [open an issue](https://github.com/o-kolomoiets/go-sftp-server/issues) with
  the result. Right now that is one of the most useful contributions there is.

Quirks and settings per client are in [docs/interop.md](docs/interop.md).

## Install

**Release archive.** Linux and macOS, amd64 and arm64; one binary of about
7 MB, nothing else to install (static on Linux).

```sh
curl -fsSLO https://github.com/o-kolomoiets/go-sftp-server/releases/download/v0.3.0/gosftpd_0.3.0_linux_amd64.tar.gz
curl -fsSLO https://github.com/o-kolomoiets/go-sftp-server/releases/download/v0.3.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar xzf gosftpd_0.3.0_linux_amd64.tar.gz gosftpd
sudo install gosftpd /usr/local/bin/ && gosftpd version
```

Replace `linux_amd64` with `linux_arm64`, `darwin_amd64` or `darwin_arm64` as
needed. On macOS, check with `grep darwin_arm64 checksums.txt | shasum -a 256 -c -`.

**With Go 1.26.5 or newer:**

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest
```

Not there yet: Windows and FreeBSD binaries, a Docker image, deb/rpm
packages, and signed releases (the checksums are SHA-256 and unsigned).
From v0.4 the Linux archives carry a systemd unit with its user and
directories; [docs/install.md](docs/install.md) installs it, with the
binary in `/usr/bin`. With v0.3.0 any process supervisor works: on SIGTERM
gosftpd gives running transfers 30 seconds to finish, a second signal stops
it at once, and v0.3.0 ignores SIGHUP, so restart it to apply a changed
configuration. To run v0.3.0 as a service under its own user, see its
[quickstart](https://github.com/o-kolomoiets/go-sftp-server/blob/v0.3.0/docs/quickstart.md#running-it-as-a-service) and
[hardening guide](https://github.com/o-kolomoiets/go-sftp-server/blob/v0.3.0/docs/security/hardening.md).

## Released and on its way

`go install …@latest` and the release archives give you **v0.3.0** (released
2026-10-09). The `main` branch already has most of **v0.4**:

| | v0.3.0 (latest release) | `main` (v0.4, unreleased) |
|---|:---:|:---:|
| `serve --dir` with no config file, generated host key | ✓ | ✓ |
| Users, mounts, `{user}` home folders, 4 presets and 9 permission flags in one TOML file | ✓ | ✓ |
| Conflict policies `rename`, `reject`, `overwrite`, `version`; append-only resume; atomic uploads; size and free-space limits | ✓ | ✓ |
| JSON audit log with a versioned schema, fail-closed | ✓ | ✓ |
| Connection limits, bans, timeouts; opt-in argon2id passwords | ✓ | ✓ |
| `init`, `config validate / show / example`, `user add` (prints a block to paste), `user list` | ✓ | ✓ |
| `user add --write`, `user disable / enable / remove` (files in `users.d/`, comments kept) | | ✓ |
| Reload on `SIGHUP` without dropping connections, `sd_notify` for systemd | | ✓ |
| OpenSSH user certificates (trusted CAs, `cert-authority`), revoked keys | | ✓ |
| Host key rotation without the `REMOTE HOST IDENTIFICATION HAS CHANGED` warning (OpenSSH 8.5+ clients), host certificates | | ✓ |
| Prometheus `/metrics` (22 `gosftpd_*` metrics, no user, path or address in any label), `/healthz`, `/readyz`, `gosftpd healthcheck` | | ✓ |
| Hooks: a signed webhook or a program when a file arrives, also for WinSCP and rclone temp-file uploads | | ✓ |
| PROXY protocol behind HAProxy, nginx or a cloud load balancer: bans, limits and the audit log see the client, not the load balancer | | ✓ |
| A sandboxed systemd unit (`systemd-analyze security` 1.2) with sysusers and tmpfiles files, [install guide](docs/install.md) | | ✓ |
| Landlock on Linux, on by default without exec hooks: once started, gosftpd can open only its mounts, configuration, keys and audit log ([security model](docs/security.md#landlock)) | | ✓ |

To try `main` today: `init` sets you up, and `user add --write` adds a
partner and prints the host, port, host key fingerprint and `sftp` command to
send them.

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@main
gosftpd init --user alice     # ./gosftpd.toml and a host key, serving ./share
gosftpd user add partner --key partner.pub --access share=upload --write
gosftpd serve                 # later, kill -HUP applies user changes
```

The metrics listener has no authentication, so keep it on loopback. `main`
has a few breaking changes since v0.3.0; for example, `serve --dir ~` is now
refused because it would serve your own `authorized_keys`. See the
[changelog](CHANGELOG.md#unreleased).

## What gosftpd is not

SFTP only, [by design](docs/adr/0002-non-goals.md): no shell, exec, port
forwarding, legacy `scp -O`, rsync or git; no FTP/FTPS, WebDAV or HTTP; no
web UI, share links or REST admin API; no S3, GCS or Azure backends; no LDAP,
OIDC or MFA; no encryption at rest; no database, HA or clustering. Not there
yet either: per-user quotas and bandwidth limits (post-1.0 backlog). It runs
next to OpenSSH (on port 2022 by default), not instead of it.

## Documentation

These pages describe `main`. For the v0.3.0 release, read them
[at the v0.3.0 tag](https://github.com/o-kolomoiets/go-sftp-server/tree/v0.3.0/docs):
v0.3.0 has no `user add --write` and ignores `SIGHUP`.

- [Quickstart](docs/quickstart.md): from nothing to a first upload, and running it as a service
- [Install as a Linux service](docs/install.md): the systemd unit, its user and directories (on `main`)
- [Configuration](docs/configuration.md): every key, with its default
- [Security model](docs/security.md), [threat model](docs/security/threat-model.md) and [hardening guide](docs/security/hardening.md)
- [Audit log](docs/audit-log.md): events, fields and the schema promise
- [Client compatibility](docs/interop.md): what is tested, per client, and known quirks
- [Metrics and health checks](docs/metrics.md) and [hooks](docs/hooks.md) (on `main`)
- [Operations](docs/operations.md): reload, stop, log rotation, backups, upgrades, remounted disks (on `main`)
- [Recipes](docs/recipes/): [retention](docs/recipes/retention.md) and [volume encryption](docs/recipes/volume-encryption.md) (on `main`)
- [Design decisions](docs/adr/), the [changelog](CHANGELOG.md) and the [release checklist](docs/release-checklist.md)

## Roadmap

| Version | Status | What's in it |
|---|---|---|
| v0.3.0 | **released** 2026-10-09 | Connection limits and bans, password login, versions, atomic uploads, size limits, fuzzing, ssh-audit in CI |
| v0.4 | **in progress** on `main` | Done: reload, user commands, certificates, host key rotation, metrics, hooks (exec, signed webhooks), PROXY protocol, a systemd unit, Landlock |
| v0.5 | planned | Docker image, deb/rpm/apk packages, signed releases with SBOM, man pages, FreeBSD binaries |
| v1.0 | planned | Compatibility freeze, benchmarks against OpenSSH, OpenSSF Best Practices badge |

The full plan is in [ROADMAP.md](ROADMAP.md), and progress in [TASKS.md](TASKS.md).

## Contributing

Bug reports, client test results and focused pull requests are all welcome.
Start with [CONTRIBUTING.md](CONTRIBUTING.md): `make test` and `make lint`
run the core checks locally, and every bug fix comes with a regression test.
Please read the [non-goals](docs/adr/0002-non-goals.md) before proposing a
big feature, and report security issues privately ([SECURITY.md](SECURITY.md)).

## Help gosftpd find its people

gosftpd is young and has no marketing, only this page. If it saved you an
afternoon with `sshd_config`, or one more system account:

- ⭐ **Star the repo.** It is how other admins find it.
- 🧪 **Try your client.** WinSCP, FileZilla, Cyberduck and PuTTY are not
  tested yet; [tell us](https://github.com/o-kolomoiets/go-sftp-server/issues)
  what happened.
- 💬 **Share your use case.** Partner inbox, device uploads, backup target:
  it shapes the roadmap.

To hear when v0.4 ships, use **Watch → Custom → Releases** at the top of this
page.

## License

[Apache License 2.0](LICENSE). Versions of this repository before the 2026
restart were published under GPL-3.0.
