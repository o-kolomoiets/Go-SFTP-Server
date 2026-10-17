# Install as a Linux service

This guide installs gosftpd from a release archive as a systemd service, in
the layout that the deb and rpm packages will use from v0.5: those packages
then take the files over. The Linux archives carry the unit and the other
files since v0.4. For a first look, the [Quickstart](quickstart.md) is
enough; it puts the binary in `/usr/local/bin`.

The unit needs systemd 253 or later, or EL9's 252-21 and later; for older
systemd see [systemd before 253](#systemd-before-253). It sandboxes gosftpd
(`systemd-analyze security` scores it 1.2 on systemd 255); what each setting
costs is in the [hardening guide](security/hardening.md#the-systemd-unit).

## What goes where

| From the archive | Installed as |
|---|---|
| `gosftpd` | `/usr/bin/gosftpd` |
| `packaging/systemd/gosftpd.service` | `/usr/lib/systemd/system/gosftpd.service` |
| `packaging/gosftpd.sysusers` | `/usr/lib/sysusers.d/gosftpd.conf`: the user `gosftpd`, with the home `/` |
| `packaging/gosftpd.tmpfiles` | `/usr/lib/tmpfiles.d/gosftpd.conf`: `/srv/sftp` and `/var/log/gosftpd` |
| `packaging/config.toml` | `/etc/gosftpd/config.toml` (root:gosftpd, 0640) |
| `packaging/systemd/legacy-notify.conf` | only for systemd before 253 |

The service keeps its data in `/srv/sftp` (the mount `inbox` is
`/srv/sftp/inbox`), its host keys in `/var/lib/gosftpd` (mode 0700) and the
audit log in `/var/log/gosftpd` (mode 0750). systemd creates the state
directory at start; tmpfiles creates the other two. The rest of the file
system is read-only for gosftpd.

The `d /srv/sftp` line of the tmpfiles file gives an existing `/srv/sftp` to
the user gosftpd. If an OpenSSH chroot lives there (it must belong to
root), choose [another data path](#another-data-path) before you install.

## Install

Download the archive and `checksums.txt` from the
[releases](https://github.com/o-kolomoiets/go-sftp-server/releases), then:

```sh
sha256sum --check --ignore-missing checksums.txt
tar xzf gosftpd_*_linux_amd64.tar.gz
sudo install -m 0755 gosftpd /usr/bin/gosftpd
sudo install -m 0644 packaging/systemd/gosftpd.service /usr/lib/systemd/system/gosftpd.service
sudo install -m 0644 packaging/gosftpd.sysusers /usr/lib/sysusers.d/gosftpd.conf
sudo install -m 0644 packaging/gosftpd.tmpfiles /usr/lib/tmpfiles.d/gosftpd.conf
sudo systemd-sysusers gosftpd.conf
sudo systemd-tmpfiles --create gosftpd.conf
sudo install -d -m 0755 /etc/gosftpd
sudo install -m 0640 -g gosftpd packaging/config.toml /etc/gosftpd/config.toml
```

On an upgrade, skip the last line: it would replace your configuration.
`systemd-sysusers` keeps a user `gosftpd` that exists already.

Then decide whether this systemd needs the drop-in for systemd before 253.
This probe asks systemd whether it knows `Type=notify-reload`; it works
without a running systemd, so also in an image build or a chroot:

```sh
d=$(mktemp -d)
printf '[Unit]\nDefaultDependencies=no\n[Service]\nType=notify-reload\nExecStart=/bin/true\n' >"$d/gosftpd-probe.service"
if systemd-analyze verify --man=no "$d/gosftpd-probe.service" 2>&1 | grep -q 'Failed to parse service type'; then
	sudo install -D -m 0644 packaging/systemd/legacy-notify.conf /etc/systemd/system/gosftpd.service.d/legacy-notify.conf
else
	sudo rm -f /etc/systemd/system/gosftpd.service.d/legacy-notify.conf
fi
rm -r "$d"
sudo systemctl daemon-reload
```

Check the configuration as the service user, then start the service:

```sh
sudo runuser -u gosftpd -- gosftpd config validate --check-fs --config /etc/gosftpd/config.toml
sudo systemctl enable --now gosftpd
systemctl status gosftpd
```

The check warns "no users configured" until you add one. It must run as
gosftpd: run as root, it refuses the host key, which belongs to gosftpd
after the first start ("it must belong to root or to the user running
gosftpd"). It also runs outside the unit's sandbox, so it cannot see what
the unit hides (`/home`) or makes read-only (everything outside
`ReadWritePaths=`). The service itself warns at start, in the journal,
about a writable mount on a read-only file system: "mounts.NAME.path: PATH
is on a read-only file system; uploads will fail".

## Add users

`user add --write` writes `/etc/gosftpd/users.d/NAME.toml`. Run it as root
(it writes to `/etc/gosftpd`), then reload:

```sh
sudo gosftpd user add partner --key partner.pub --access inbox=upload --write --config /etc/gosftpd/config.toml
sudo systemctl reload gosftpd
systemctl status gosftpd
```

It prints the host, port, host key fingerprint and `sftp` command to send
to the partner. `user disable`, `enable` and `remove` work the same way.

## The result of a reload

`systemctl reload gosftpd` returns 0 even when the reload failed: systemd
cannot be told that a reload failed. The running configuration then stays.
The result is in three places:

- the `Status:` line of `systemctl status gosftpd`:
  - `configuration reloaded`;
  - `configuration reloaded; restart needed for: KEYS`: the reload worked,
    but the settings named (at most five, then "and N more; see the log")
    did not take effect. Until `systemctl restart gosftpd` some keep
    their running value, and under Landlock others are left out, so that
    a mount can be unavailable or users cannot log in
    ([operations.md](operations.md#reload) says which, and when to
    restart);
  - `configuration reload failed, see the log`;
- the journal (`journalctl -u gosftpd`), with the reason;
- the metric `gosftpd_config_reloads_total{result="error"}` with the admin
  listener ([metrics.md](metrics.md)), and the audit event `server.reload`.

Check the file first with `config validate` (as above): a reload that
fails changes nothing, but you only see it in these places.

## Stop and restart

`systemctl stop` gives running transfers `server.shutdown_timeout` (30 s)
to finish; hooks get a little more after that. The unit's
`TimeoutStopSec=45` covers the default. When a reload raised
`shutdown_timeout`, gosftpd asks systemd for that time plus 10 s at stop
(`EXTEND_TIMEOUT_USEC`), so the unit needs no change.

After a failure, systemd restarts gosftpd after 2 s, at most 5 times a
minute. Exit status 2 is a configuration or file system error, such as a
data directory that cannot be opened: a restart does not fix it, so systemd
does not retry. Fix the cause and run `sudo systemctl start gosftpd`.

## Upgrade from the Quickstart or the interim unit

The Quickstart and v0.3's hardening guide put the binary in
`/usr/local/bin`, and the hardening guide had an interim unit and created
the user by hand. Take these steps before you install; the configuration,
the host keys and the data stay where they are.

- **A unit in `/etc/systemd/system`.** It overrides the one in
  `/usr/lib/systemd/system`, and the service would keep running the old
  unit. The first line of `systemctl cat gosftpd` names the file systemd
  uses. Stop the service and remove the old unit:

  ```sh
  systemctl cat gosftpd | head -n 1   # "# /etc/systemd/system/gosftpd.service": the old unit
  sudo systemctl disable --now gosftpd
  sudo rm /etc/systemd/system/gosftpd.service
  sudo systemctl daemon-reload
  ```

  After the install, the first line names
  `/usr/lib/systemd/system/gosftpd.service`.
- **The user from `useradd --home-dir /var/lib/gosftpd --create-home`.** Its
  home is the state directory, and `useradd` copied the files of
  `/etc/skel` there. With the service stopped (`usermod` refuses a user
  that runs processes), give it the home `/` and remove those files:

  ```sh
  sudo usermod --home / gosftpd
  (cd /etc/skel && for f in .[!.]* *; do [ -e "$f" ] && sudo rm -rf "/var/lib/gosftpd/$f"; done)
  ```

  The sandbox lets a reload read new files in the state directory, such as
  the next host key of a rotation, only while that directory holds nothing
  but gosftpd's own files and is not a home directory. Otherwise each step
  of a host key rotation needs a restart.
- **A binary in `/usr/local/bin`.** `PATH` finds it before `/usr/bin`, so
  `gosftpd user add` would run the old version. Remove it:
  `sudo rm /usr/local/bin/gosftpd`.

## systemd before 253

`Type=notify-reload` came with systemd 253 and EL9's 252-21. Older systemd
(Debian 12, Ubuntu 22.04, older EL9) ignores it with a warning and starts
gosftpd as a simple service, which cannot be reloaded. The drop-in
`legacy-notify.conf` sets `Type=notify` and reloads with
`kill -HUP`; the probe in [Install](#install) installs it where it is
needed and removes it where it is not. It decides by testing the feature,
not by the version number (EL9 has it in 252), and is not fooled by the
drop-in itself.

Run the probe again after upgrading the operating system. With the
drop-in, `systemctl reload` can in rare cases return before the reload has
finished, and every `systemctl daemon-reload` logs "Failed to parse
service type, ignoring" for the unit.

## Another data path

The unit may write only to `/srv/sftp`, the state and the log directory.
For data in `/data/sftp`, add it with a drop-in (`sudo systemctl edit
gosftpd` creates `/etc/systemd/system/gosftpd.service.d/override.conf`):

```ini
[Unit]
RequiresMountsFor=/data/sftp

[Service]
ReadWritePaths=-/data/sftp
```

Create the directory with an override of the tmpfiles file, which replaces
the shipped one:

```sh
sudo tee /etc/tmpfiles.d/gosftpd.conf <<'EOF'
d /data/sftp 0750 gosftpd gosftpd -
d /var/log/gosftpd 0750 gosftpd gosftpd -
EOF
sudo systemd-tmpfiles --create gosftpd.conf
```

Then change `path` in `/etc/gosftpd/config.toml` and restart. Without the
drop-in, the directory is read-only for gosftpd: it warns at start, and
every upload fails (or the start fails, when gosftpd has to create the
directory).

## Mounts or key files under /home

`ProtectHome=yes` hides `/home`, `/root` and `/run/user` from gosftpd, and
`ReadWritePaths=` cannot open a path under them. Use one of these drop-ins:

```ini
[Service]
# gosftpd may read all of /home and write /home/sftp.
ProtectHome=read-only
ReadWritePaths=/home/sftp
```

```ini
[Service]
# gosftpd sees only /home/sftp; the other homes stay hidden.
ProtectHome=tmpfs
BindPaths=/home/sftp
```

For `authorized_keys` files under `/home`, use `ProtectHome=read-only`, or
`ProtectHome=tmpfs` with `BindReadOnlyPaths=` naming each key directory.

## Port 22

The unit has no capabilities. To listen on port 22 (with OpenSSH moved to
another port), set `listen = [":22"]` in the configuration and add this
drop-in, then restart:

```ini
# /etc/systemd/system/gosftpd.service.d/port22.conf
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

gosftpd keeps the capability, but clears the ambient set once its
listeners are bound and before any exec hook can run, so hooks do not get
it. Alternatively keep port 2022 and redirect 22 to it in the firewall.
`PrivateUsers=yes` (below) and port 22 do not go together.

## A data disk mounted later

`RequiresMountsFor=/srv/sftp` starts gosftpd after the file system mounted
there, when it is in `/etc/fstab` or has a mount unit. A disk mounted on
`/srv/sftp` after the install has a root directory that belongs to root:
gosftpd then exits at start with "permission denied" for the mount's
directory. Give it to gosftpd by running tmpfiles again, then start the
service (exit status 2 is not retried):

```sh
sudo systemd-tmpfiles --create gosftpd.conf
sudo systemctl start gosftpd
```

At boot, systemd runs tmpfiles after the local file systems are mounted,
so a disk in `/etc/fstab` gets the owner on its own. `config validate
--check-fs` does not catch this case when the new root directory is
readable (mode 0755): only creating the mount's directory fails.

A disk mounted while gosftpd runs, on `/srv/sftp` or on a mount's own
directory, is served only after a reload, or under Landlock a restart; see
[operations.md](operations.md#a-disk-mounted-on-a-mount-directory). For an
encrypted disk, see [recipes/volume-encryption.md](recipes/volume-encryption.md).

A manual `umount /srv/sftp` does not stop gosftpd: it keeps the old view of
the file system in its own mount namespace. Only `systemctl stop
srv-sftp.mount` stops gosftpd first. To stop gosftpd whenever the file
system goes away, add a drop-in (only when `/srv/sftp` is a mount point,
or the service cannot start):

```ini
[Unit]
BindsTo=srv-sftp.mount
After=srv-sftp.mount
```

## More hardening

Two settings are not in the unit, because they break common setups:

- `PrivateUsers=yes` (score 1.1) runs gosftpd in a user namespace. Port 22
  then fails to bind, even with the capability.
- `IPAddressDeny=any` with `IPAddressAllow=` limits the addresses gosftpd
  may talk to. List the client networks and, for webhooks, the receivers
  and the DNS server, or webhooks fail:

  ```ini
  [Service]
  IPAddressDeny=any
  IPAddressAllow=localhost 192.0.2.0/24
  ```

Exec hooks run inside the unit's sandbox; what they cannot do there is in
[hooks.md](hooks.md#sandboxes-and-containers).
