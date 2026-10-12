# Hardening

How to run gosftpd on a server that is reachable from the internet. Why each
step matters is in the [threat model](threat-model.md); the keys are
described in [configuration.md](../configuration.md).

## Checklist

- [ ] A dedicated system user owns the served directories and runs gosftpd;
      never root (`serve` refuses without `--allow-root`).
- [ ] On Linux with systemd: the shipped unit, installed as
      [install.md](../install.md) describes, and no older unit in
      `/etc/systemd/system`.
- [ ] Served directories are written only by gosftpd: no other local users,
      no bind mounts or hard links inside them.
- [ ] `config validate --check-fs` passes, without warnings you have not
      understood.
- [ ] Public-key login only, or passwords with argon2id hashes of one cost.
- [ ] `crypto_policy = "modern"` unless a client needs `compat`.
- [ ] The firewall rate-limits new connections to the SFTP port.
- [ ] Inbox mounts set `max_file_size`; `min_free_space` is not 0.
- [ ] Mounts that other programs read use `atomic_uploads = true`.
- [ ] The audit log goes to a file or journald that you keep and watch.
- [ ] The admin listener, if on, is on loopback or a private network, and
      `pprof` is off.
- [ ] Hooks, if any: webhooks use `https` and receivers verify signatures;
      exec hook scripts quote every name ([hooks.md](../hooks.md)).
- [ ] You follow releases and security advisories of the repository.

## Run as a dedicated user

On Linux with systemd, install gosftpd as [install.md](../install.md)
describes: the shipped unit runs it as the system user `gosftpd`, which
`systemd-sysusers` creates, with the home `/`. Elsewhere, create such a
user and its directories yourself:

```sh
sudo useradd --system --home-dir / --no-create-home --shell /usr/sbin/nologin gosftpd
sudo install -d -o gosftpd -g gosftpd -m 0750 /srv/sftp /var/log/gosftpd
sudo install -d -o gosftpd -g gosftpd -m 0700 /var/lib/gosftpd
sudo install -d -o root -g gosftpd -m 0750 /etc/gosftpd
```

The configuration, host keys (and their next and previous keys and
certificates), `authorized_keys` files, the trusted CA keys
and the revocation list must not be writable by group or others (gosftpd refuses them, like sshd's
`StrictModes`).

## The systemd unit

The unit in the release archives,
[packaging/systemd/gosftpd.service](../../packaging/systemd/gosftpd.service),
adds sandboxing on top of `os.Root`; CI starts it under systemd 255 and
fails when `systemd-analyze security` scores it above 1.2. It replaces the
interim unit that this guide showed for v0.3: [install.md](../install.md#upgrade-from-the-quickstart-or-the-interim-unit)
tells how to remove that one, which would override the shipped unit. What
its settings do, and what they cost:

| Settings | What they do | What they cost |
|---|---|---|
| `User=gosftpd`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=` | No root, no capabilities, no setuid programs. | Port 22 needs a drop-in ([install.md](../install.md#port-22)); exec hooks cannot use `sudo`. |
| `ProtectSystem=strict`, `ReadWritePaths=-/srv/sftp`, `StateDirectory=`, `LogsDirectory=` | The file system is read-only except the data, `/var/lib/gosftpd` (0700) and `/var/log/gosftpd` (0750). | Another data path needs a drop-in; a writable mount outside gets the warning "PATH is on a read-only file system". |
| `ProtectHome=yes` | `/home`, `/root` and `/run/user` are hidden. | Mounts or key files under `/home` need `ProtectHome=read-only` or `tmpfs` ([install.md](../install.md#mounts-or-key-files-under-home)). |
| `PrivateTmp=yes`, `PrivateDevices=yes` | A private `/tmp`; no device nodes but `/dev/null` and the like. | Exec hooks see the private `/tmp`. |
| `SystemCallFilter=@system-service`, the three `landlock_*` calls, `~@privileged @resources`, `SystemCallErrorNumber=EPERM` | Only the system calls a service needs, and Landlock's; the others fail with `EPERM`. | Exec hooks cannot use `nice`, `ionice`, `taskset`, `chown` or `chgrp` ([hooks.md](../hooks.md#sandboxes-and-containers)). |
| `MemoryDenyWriteExecute=yes`, `LockPersonality=yes` | No memory that is both writable and executable. | Exec hooks cannot run JIT runtimes such as node or java. |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | Only Unix (`sd_notify`, journald) and Internet sockets. | None for gosftpd. |
| `ProtectProc=invisible`, `ProcSubset=pid` | Other processes and most of `/proc` are hidden. | None for gosftpd (the process metrics read `/proc/self`). |
| `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectClock=`, `ProtectHostname=`, `RestrictNamespaces=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `RemoveIPC=`, `SystemCallArchitectures=native` | The kernel, clock, host name, namespaces and the other ABIs are off limits. | None for gosftpd. |
| `UMask=0027` | Uploads are not readable by other users. | Members of the group `gosftpd` can read them. |
| `KillMode=mixed`, `TimeoutStopSec=45` | Only gosftpd gets SIGTERM: running exec hooks finish during the drain, and what they leave is killed once gosftpd exits. | A stop takes up to `shutdown_timeout` + 10 s; gosftpd asks for more when a reload raised `shutdown_timeout`. |
| `Restart=on-failure`, `RestartSec=2s`, `StartLimitBurst=5` in `StartLimitIntervalSec=60`, `RestartPreventExitStatus=2` | Restarts after a crash, but not after a configuration or file system error (exit status 2), and at most 5 times a minute. | A data disk that is mounted late is not retried ([install.md](../install.md#a-data-disk-mounted-later)). |
| `RequiresMountsFor=/srv/sftp` | Starts after the data file system, and `systemctl stop` of it stops gosftpd first. | A manual `umount` does not stop gosftpd. |
| `LimitNOFILE=131072` | Room for the default limits: 256 connections with 4 sessions and 64 handles each. | None. |

`systemd-analyze security gosftpd.service` scores the unit 1.2 on systemd
255; other versions weigh some items differently. What remains is host
networking (`PrivateNetwork=`,
`RestrictAddressFamilies=`), which a server needs, the root directory, the
clock device of `ProtectClock=`, `UMask=` and two settings that are left
to you because they break common setups: `PrivateUsers=yes` (1.1) breaks
port 22, and `IPAddressDeny=` breaks webhooks unless their receivers are
allowed ([install.md](../install.md#more-hardening)).

**Your own system call filter.** If you write your own
`SystemCallFilter=`, allow `landlock_create_ruleset`, `landlock_add_rule`
and `landlock_restrict_self`: `@system-service` holds none of them, and
the group `@sandbox` exists only from systemd 254 (252 warns that it does
not know it). Without them, gosftpd runs without Landlock and logs
"landlock: not available: blocked by a seccomp filter". It tests the calls
in a child process first, so a filter that kills a process for them, as
one without `SystemCallErrorNumber=` does, does not stop gosftpd.

## Filesystem

- Put served data on its own filesystem, and set `require_mountpoint = true`
  so that gosftpd does not start on the root disk when it is not mounted.
- Keep `min_free_space` (1 GiB by default); with the audit log on the same
  filesystem it also keeps room for the log.
- Set `max_file_size` on mounts that accept uploads from partners.
- Use `on_conflict = "rename"` (the default) or `"reject"` for drop-boxes,
  `"version"` for folders that are synced, and `"overwrite"` only for users
  you trust with existing data.
- Use `atomic_uploads = true` where another program picks up new files, so
  it never sees a partial one.
- Use `symlinks = "deny"` if local users can create links in served
  directories.

## Network

- Listen only where clients are: `listen = ["203.0.113.10:2022"]` rather
  than every address.
- gosftpd bounds concurrent connections before the handshake (`[limits]`),
  not their rate. Rate-limit new connections in the firewall, which also
  bounds the CPU spent on key exchanges (CVE-2002-20001, "DHEat"). With
  nftables, for example:

  ```sh
  nft add rule inet filter input tcp dport 2022 ct state new \
      meter sftp4 '{ ip saddr limit rate over 20/minute burst 20 packets }' drop
  nft add rule inet filter input tcp dport 2022 ct state new \
      meter sftp6 '{ ip6 saddr limit rate over 20/minute burst 20 packets }' drop
  ```

- Behind NAT, many legitimate clients share one address: raise
  `max_connections_per_ip`, and list monitoring hosts in `auth.ban.exempt`
  rather than turning bans off.
- Bans live in memory; for longer bans, feed `auth.ban` audit events to
  fail2ban or the firewall.

## Admin listener

`[metrics] listen` serves `/metrics`, `/healthz` and `/readyz` over plain
HTTP without authentication ([metrics.md](../metrics.md)).

- Keep it on `127.0.0.1` and scrape from the host, or on a private network
  that only Prometheus reaches; in Docker publish it as
  `-p 127.0.0.1:9090:9090`. Never expose it to the internet.
- On loopback, gosftpd answers 421 to a foreign `Host` header (DNS
  rebinding). In Docker it binds `0.0.0.0` inside the container, so that
  check is off: a browser on the Docker host is not protected.
- Behind a reverse proxy with authentication, keep gosftpd on loopback, and
  make the proxy send a loopback `Host` (see
  [metrics.md](../metrics.md#security)).
- Whoever reaches the listener can hold its 64 connections: use `gosftpd
  healthcheck` (SSH) for liveness, not `/healthz`.
- Release binaries do not contain pprof. A binary built with `-tags pprof`
  should run with `pprof = false` and turn it on only while profiling.
- For a container health check, `gosftpd healthcheck` needs no admin
  listener.

## Authentication

- Prefer keys. Restrict them with `from="203.0.113.0/24"` and
  `expiry-time="20271231"` in `authorized_keys`; ed25519 or ECDSA keys, RSA
  at least 2048 bits.
- If you enable passwords (`auth.methods`), create hashes with
  `gosftpd user hash-password` and keep all of them of one kind and cost:
  with mixed ones, response times can reveal which users exist.
- Restrict users to known networks with `allow_from`, and expire or disable
  accounts you no longer need (`expires`, `disabled`).

## Cryptography

`crypto_policy = "modern"` (default) passes ssh-audit without failures; CI
checks it with ssh-audit 3.9.0 and an ed25519 host key (`test/ssh-audit.sh`).
The remaining warnings concern the classic X25519 key exchange, which
clients older than OpenSSH 9.9 need:

| Policy | ssh-audit findings |
|---|---|
| `modern` | warn: `curve25519-sha256`, `curve25519-sha256@libssh.org` (no post-quantum protection) |
| `compat` | the `modern` warnings; fail: `ecdh-sha2-nistp256`, `-nistp384`, `-nistp521` (NIST curves); warn: `diffie-hellman-group14-sha256` (112-bit strength), `diffie-hellman-group16-sha512`, `hmac-sha2-256`, `hmac-sha2-512` (encrypt-and-MAC) |

Use `compat` only for clients that cannot do better, and prefer a separate
instance for them. SHA-1, CBC and DSA are never offered. Strict key
exchange (`kex-strict-s-v00@openssh.com`) protects against Terrapin
(CVE-2023-48795) with clients that support it.

## Audit log

- Keep `audit.on_error = "fail-closed"` (the default): gosftpd refuses
  changes rather than work unaudited.
- Write the log to journald (`output = "stdout"`) or to a file on a
  filesystem with room, rotated by logrotate with a reload in `postrotate`
  (see [audit-log.md](../audit-log.md#rotation)).
- Ship it to a log store the gosftpd user cannot change, and alert on
  `auth.ban`, `fs.denied` and `conn.reject` bursts.

## Updates

- Watch the repository's releases and security advisories, and update when
  a release fixes a vulnerability that is reachable in your setup.
- CI runs `govulncheck` on every change; run it against your binary too
  (`govulncheck -mode=binary "$(command -v gosftpd)"`).
