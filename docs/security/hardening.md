# Hardening

How to run gosftpd on a server that is reachable from the internet. Why each
step matters is in the [threat model](threat-model.md); the keys are
described in [configuration.md](../configuration.md).

## Checklist

- [ ] A dedicated system user owns the served directories and runs gosftpd;
      never root (`serve` refuses without `--allow-root`).
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
- [ ] You follow releases and security advisories of the repository.

## Run as a dedicated user

```sh
sudo useradd --system --home-dir /var/lib/gosftpd --create-home --shell /usr/sbin/nologin gosftpd
sudo install -d -o gosftpd -g gosftpd -m 0750 /srv/sftp /var/log/gosftpd
sudo install -d -o root -g gosftpd -m 0750 /etc/gosftpd
```

The configuration, host keys, `authorized_keys` files, the trusted CA keys
and the revocation list must not be writable by group or others (gosftpd refuses them, like sshd's
`StrictModes`). A systemd unit ships with v0.4; until then, this one adds
sandboxing on top of `os.Root`:

```ini
[Unit]
Description=gosftpd SFTP server
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/srv/sftp

[Service]
User=gosftpd
Group=gosftpd
ExecStart=/usr/local/bin/gosftpd serve --config /etc/gosftpd/config.toml
Restart=on-failure
TimeoutStopSec=45s
LimitNOFILE=65536

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths=/srv/sftp /var/lib/gosftpd /var/log/gosftpd
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

The unit is not tested in CI yet; check it on your system before you rely
on it. Keep `TimeoutStopSec` above `server.shutdown_timeout` (30 s by
default). To
listen on port 22 without root, add `AmbientCapabilities=CAP_NET_BIND_SERVICE`
and set `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, or keep port 2022 and
forward 22 in the firewall.

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
  (`govulncheck -mode=binary /usr/local/bin/gosftpd`).
