# Operations

Everyday tasks for a gosftpd service: reload, stop and restart, rotate the
logs, back up and restore, upgrade, and deal with a disk mounted on a mount
directory. The commands assume the packaged layout of
[install.md](install.md): the unit `gosftpd.service`, the configuration in
`/etc/gosftpd`, the host keys in `/var/lib/gosftpd`, the audit log in
`/var/log/gosftpd` and the data in `/srv/sftp`. Under another supervisor,
`kill -HUP` and `kill -TERM` to the gosftpd process do what `systemctl
reload` and `systemctl stop` do.

## Reload

Check the file as the service user, reload, and read the result:

```sh
sudo runuser -u gosftpd -- gosftpd config validate --check-fs --config /etc/gosftpd/config.toml
sudo systemctl reload gosftpd
systemctl status gosftpd
```

`systemctl reload` sends SIGHUP and, with the shipped unit
(`Type=notify-reload`), waits until gosftpd has finished; with the drop-in
for [systemd before 253](install.md#systemd-before-253) it can return
earlier. gosftpd reopens the audit log first, then reads and checks the
same configuration file again, and switches only if it is valid. New logins
get the new configuration; open connections keep the one they logged in
under. What a reload changes, and what it does not, is in
[configuration.md](configuration.md#reload). A reload never runs a new
binary: that takes a restart ([Upgrades](#upgrades)).

Check first: a reload that fails changes nothing, and says so only in the
places below. `config validate --check-fs` is stricter about mounts than a
reload: a mount that fails its checks (a missing directory, a disk that is
not mounted under `require_mountpoint`) is an error there, while a reload
serves without that mount until a later reload finds it usable.

`systemctl reload` succeeds even when the reload failed
([install.md](install.md#the-result-of-a-reload)). The `Status:` line of
`systemctl status gosftpd` says what happened:

| Status | What to do |
|---|---|
| `configuration reloaded` | Nothing. |
| `configuration reloaded; restart needed for: KEYS` | The reload worked, but the settings named did not take effect. A restart-only setting keeps its running value: restart when it suits you ([Stop and restart](#stop-restart-and-interrupted-uploads)). Under Landlock a mount, a hook, the audit log, or the keys or CAs of a file named there can instead be left out until the restart, so that a mount is unavailable or users cannot log in (the list below): then restart soon. |
| `configuration reload failed, see the log` | Nothing changed. `journalctl -u gosftpd -n 20` has the reason in the line "configuration reload failed; the running configuration stays". Fix the file, check it and reload again. |

The status line names at most five settings, then "and N more; see the
log". The journal has a warning for each one, and the audit event
`server.reload` lists them all in `restart_required`:

```sh
sudo grep '"event":"server.reload"' /var/log/gosftpd/audit.jsonl | tail -n 1
```

**No metric says that a restart is needed.**
`gosftpd_config_last_reload_successful` is 1 after such a reload. Watch the
status line, the journal or `restart_required` in the audit log. Under
Landlock two cases also show in the metrics: a mount left out
(`gosftpd_mounts_unavailable`) and an exec hook left out
(`gosftpd_hooks_not_updated`); see [metrics.md](metrics.md#queries-and-alerts).

These keys can appear in `restart_required`:

- the restart-only settings: `server.listen`,
  `server.host_key_auto_generate`, `server.crypto_policy`,
  `server.landlock`, `metrics.listen`, `log.format`, `audit.events` and
  `audit.on_error`;
- under Landlock (the default on Linux), what the ruleset applied at start
  does not cover ([configuration.md](configuration.md#landlock)):
  - `mounts.NAME.path`: a new or moved mount, or a mount directory that was
    recreated or had a disk mounted on it since the start. The mount is
    unavailable until the restart
    ([A disk mounted on a mount directory](#a-disk-mounted-on-a-mount-directory));
  - `mounts.NAME.read_only` and `mounts.NAME.create`: the mount keeps its
    running value;
  - `audit.output`: a new audit output is not used and the running one
    stays; or the audit log was rotated by rename next to other files
    ([Log rotation](#log-rotation)), and writing it fails until the
    restart;
  - `hooks`: an exec hook that the reload added is left out;
  - `server.host_keys`, `users.NAME.authorized_keys_file`,
    `auth.trusted_user_ca_keys_file`, `hooks[N].webhook.secret_file` or
    `--authorized-keys`: a file in a shared directory was replaced by
    rename, and the reload treats it as an unreadable file. The running
    host keys stay. The keys of an authorized_keys file are not used: its
    users cannot log in with them, and with `--authorized-keys` nobody
    can. The CAs of `auth.trusted_user_ca_keys_file` are not trusted, so
    the certificates they signed are refused. A webhook keeps its running
    secret, and one that the reload added is left out.

## Stop, restart and interrupted uploads

```sh
sudo systemctl stop gosftpd      # or: sudo systemctl restart gosftpd
```

On SIGTERM gosftpd:

1. closes its listeners: new connections are refused, in a restart until
   the new process listens. `/readyz` answers `stopping`;
2. stops reloading: a SIGHUP from now on does nothing;
3. lets open connections finish for up to `server.shutdown_timeout` (30 s).
   They stay open, also idle ones, and may start new transfers. When the
   time is up it closes the rest, and the journal says "closed connections
   that did not finish in time";
4. gives hooks what is left of that time, at least 5 s
   ([hooks.md](hooks.md#shutdown)), and writes `server.stop`.

So a stop with clients connected takes the whole `shutdown_timeout`. The
unit allows 45 s (`TimeoutStopSec=`); gosftpd asks systemd for
`shutdown_timeout` + 10 s when it stops (`EXTEND_TIMEOUT_USEC`), so a larger
`shutdown_timeout` needs no change to the unit. `KillMode=mixed` sends
SIGTERM to gosftpd only; running exec hooks are killed once it has exited.

A second SIGTERM during the drain ends gosftpd at once, and so does
systemd's SIGKILL when the stop takes too long. Then there is no
`server.stop` event, and no `fs.upload` event for the transfers that were
running.

What an interrupted upload leaves:

| Upload | Closed at the end of the drain | Ended by a second SIGTERM or a SIGKILL |
|---|---|---|
| Written in place (the default) | The data received so far, under the name the upload got; `fs.upload` with `result` `aborted` and `bytes`. | The same data, without an `fs.upload` event. |
| Through a temporary file (`atomic_uploads`, a conflict under `on_conflict = "version"`) | Nothing: the temporary file is removed, and the name keeps what it had. | A hidden `.gosftpd-*.part` file. gosftpd removes it once it is 24 hours old; it looks at start and every 6 hours. |

The audit log records a connection closed at the end of the drain as
`conn.close` with `result` `ok`. The aborted uploads, with the file each
one wrote (`final_path`), are:

```sh
sudo grep '"event":"fs.upload"' /var/log/gosftpd/audit.jsonl | grep '"result":"aborted"'
```

**Resuming.** A client continues an upload with OpenSSH `reput` or
paramiko's append mode. With `resume = "append-only"` (the default) the
bytes the file has cannot change, so a resume only adds the rest. A resume
continues the file that has the requested name now. If the interrupted
upload wrote another file, the name still holds the old content, and the
resume appends the rest of the new file to it:

- under `on_conflict = "rename"` the upload went to a copy such as
  `report (1).pdf`. For 60 seconds after it ended, a resume by the same
  user goes to the copy (the stat redirect,
  [configuration.md](configuration.md#upload-conflicts)). The redirect
  lives in memory: after 60 seconds, or after a restart, `reput
  report.pdf` appends to the original `report.pdf`;
- under `on_conflict = "version"` the upload was written to a temporary
  file, which is gone; `reput` appends to the file that was there before.

In both cases the original keeps its bytes, but grows by the end of the
other file. After a restart or a longer break, tell such users to delete
their partial copy and upload again (`put`, not `reput`). Where a partial
file must never appear under a name, set `atomic_uploads = true`: an
interrupted upload leaves nothing, and a resume is refused ("resume is
disabled"), so the client uploads the whole file again.

After a crash or a failure, systemd restarts gosftpd, but not after exit
status 2, a configuration or file system error
([install.md](install.md#stop-and-restart)).

## Log rotation

**The operational log** goes to stderr, under systemd to the journal:
`journalctl -u gosftpd`. journald rotates it by its own limits
(`SystemMaxUse=`, `MaxRetentionSec=` in `journald.conf`). `log.level`
changes with a reload; `log.format` needs a restart.

**The audit log** with `audit.output = "stdout"` goes to the journal as
well, one JSON line per event:

```sh
journalctl -u gosftpd -o cat | grep '"msg":"audit"'
```

In a file, as in the packaged layout, rotate it with logrotate and reload
gosftpd in `postrotate`; the configuration is in
[audit-log.md](audit-log.md#rotation). Three details matter:

- `create 0600 gosftpd gosftpd`: gosftpd must be able to open the new
  file. With another owner every write fails until the file is fixed, and
  with `on_error = "fail-closed"` gosftpd refuses new connections and
  changes meanwhile.
- `delaycompress`: the newest rotated file is compressed only at the next
  rotation. Keep it with the drop-in for systemd before 253, where
  `systemctl reload` can return before gosftpd has reopened the file: lines
  written in between go to `audit.jsonl.1`.
- Under Landlock, rotation by rename needs a directory that holds nothing
  but the audit log and its rotated copies, as `/var/log/gosftpd` does.
  Elsewhere use `copytruncate`, or every rotation needs a restart.

## Backups and restore

Back up, with owners and modes:

| Path | What it holds |
|---|---|
| `/etc/gosftpd` | `config.toml` (root:gosftpd, 0640) and `users.d/`, and the CA file, revocation list and webhook secret files if you keep them there. |
| `/var/lib/gosftpd` | The host keys (0600, owned by gosftpd) with their `.pub`, `.next`, `.old` and `-cert.pub` files. Without them gosftpd generates a new key at start (`host_key_auto_generate`), and every client warns "REMOTE HOST IDENTIFICATION HAS CHANGED". |
| `/var/log/gosftpd` | The audit log and its rotated copies. |
| `/srv/sftp` | The data, with each mount's `.versions` directory. Leave out `.gosftpd-*.part` files: they are uploads in progress. |
| `/etc/systemd/system/gosftpd.service.d/`, `/etc/tmpfiles.d/gosftpd*.conf`, `/etc/logrotate.d/` | Your drop-ins, tmpfiles overrides and logrotate file. |
| Exec hook programs | The scripts your `[[hooks]]` run, such as `/usr/local/bin/archive-upload`. |

Bans and the stat redirects of `on_conflict = "rename"` live in memory; a
restart clears them, and no backup holds them.

To restore, stop gosftpd, restore the files, then check them as the
service user before you start it:

```sh
sudo systemctl stop gosftpd
# restore the paths above, as root, with owners and modes
sudo runuser -u gosftpd -- gosftpd config validate --check-fs --config /etc/gosftpd/config.toml
sudo runuser -u gosftpd -- gosftpd hostkey show --config /etc/gosftpd/config.toml
sudo systemctl start gosftpd
```

Compare the fingerprints that `hostkey show` prints with those your
clients know. gosftpd refuses files that are unsafe, as sshd's
`StrictModes` does ([configuration.md](configuration.md#file-permissions)),
with errors such as:

- `writable by group or others (mode 0664); fix with: chmod go-w PATH`;
- `owned by uid 998; it must belong to root or to the user running gosftpd
  (uid 997)`;
- for a host key, `permissions 0640 are too open; fix with: chmod 600 PATH`.

On a new host, `systemd-sysusers` may give the user gosftpd another uid.
tar and rsync, run as root, restore owners by name unless told to keep the
numbers (`--numeric-owner`, `--numeric-ids`). When the numbers were kept,
give the files back to gosftpd:

```sh
sudo chown -R gosftpd:gosftpd /var/lib/gosftpd /var/log/gosftpd /srv/sftp
sudo chgrp -R gosftpd /etc/gosftpd/config.toml /etc/gosftpd/users.d
```

Under Landlock, leave nothing else in `/etc/gosftpd` and `/var/lib/gosftpd`,
such as an archive or a copy of the old configuration under another name:
a file the configuration does not name makes the directory shared, and a
reload then cannot read files that were replaced by rename, such as a
`users.d` file that `user add --write` wrote
([configuration.md](configuration.md#landlock)). The start warns about it.

A restore sets the change time (ctime) of every file to the time of the
restore. Retention by ctime ([recipes/retention.md](recipes/retention.md))
then counts restored files as new.

## Upgrades

Read the [CHANGELOG](../CHANGELOG.md) of every version since yours first:
the entries marked **BREAKING:** and the upgrade notes. Coming from the
Quickstart or the interim unit of v0.3, take the steps in
[install.md](install.md#upgrade-from-the-quickstart-or-the-interim-unit)
too.

Download and check the archive as for an [install](install.md#install).
Then put the new binary next to the old one, check the configuration with
it, and replace the old one:

```sh
sudo install -m 0755 gosftpd /usr/bin/gosftpd.new
sudo runuser -u gosftpd -- /usr/bin/gosftpd.new config validate --check-fs --config /etc/gosftpd/config.toml
sudo mv /usr/bin/gosftpd.new /usr/bin/gosftpd
```

Use `install` or `mv`, not `cp`: `cp` onto the binary of the running
process fails with "Text file busy". The running process keeps the old
binary until it is restarted; a reload does not change it.

Install the unit, sysusers and tmpfiles files from the archive again, as
in [Install](install.md#install), but not `config.toml`. Then restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart gosftpd
```

Your drop-ins in `/etc/systemd/system/gosftpd.service.d/` stay; after an
upgrade of the operating system, run the probe for
[systemd before 253](install.md#systemd-before-253) again. The restart waits
for open connections as a [stop](#stop-restart-and-interrupted-uploads)
does. Then check the version that runs: `gosftpd_build_info{version}` with
the admin listener, or the `version` of the newest `server.start` event:

```sh
sudo grep '"event":"server.start"' /var/log/gosftpd/audit.jsonl | tail -n 1
```

**Downgrades** are not tested. An older version refuses settings it does
not know ("unknown key"), with exit status 2, so keep a copy of the
configuration it accepts. v0.3 does not notify systemd and ignores SIGHUP:
the packaged unit (`Type=notify-reload`) waits for its start until the
start times out.

## A disk mounted on a mount directory

gosftpd opens each mount's directory once, at start, and keeps it open. If
a disk (or NFS) is mounted on that directory later, gosftpd still serves
the directory below the mount point: uploads land there, hidden on the
host behind the new disk. The same holds for a disk mounted above it, on
`/srv/sftp`: the mount's path then names a directory on the new disk. Mount
data disks before gosftpd starts (see Prevention below). When it has
happened:

- **Without Landlock** (`server.landlock = "off"`, exec hooks configured,
  or a kernel without it), a reload opens the new directory for new
  logins: `sudo systemctl reload gosftpd`. Connections that logged in
  before the reload keep the old directory until they end. The reload
  reports `configuration reloaded`, and the log has `mount reopened` with
  the mount's name.
- **Under Landlock**, the kernel ties the mount's rule to the directory
  opened at start, and the new disk is outside it. A reload leaves the
  mount out instead: the status line has `restart needed for:
  mounts.NAME.path`, the journal warns "mounts.NAME.path: PATH: outside the
  Landlock ruleset applied at start; restart gosftpd; the mount is
  unavailable until then", `gosftpd_mounts_unavailable` is 1, and clients
  get errors for that mount. Restart gosftpd: `sudo systemctl restart
  gosftpd`.

A disk mounted on a directory *inside* a mount (`/srv/sftp/inbox/archive`)
is served at once, also under Landlock, without a reload.

Under the packaged unit gosftpd runs in a mount namespace of its own. A
disk mounted on the host while gosftpd runs reaches it (the systemd CI job
checks this on Ubuntu 24.04 with systemd 255), and after a restart gosftpd
always sees it.

**Files written below the mount point** stay on the old file system. A
bind mount of that file system shows them; here it is the root file
system:

```sh
sudo mkdir -p /mnt/rootfs
sudo mount --bind / /mnt/rootfs
sudo ls -lA /mnt/rootfs/srv/sftp/inbox
```

Copy what you need to the new disk with its owner (`sudo cp -a`), remove
it below the mount point, then `sudo umount /mnt/rootfs`.

**Unmounting.** While gosftpd runs, `umount` of a disk it serves fails with
"target is busy", also after a reload: gosftpd holds the directory open.
Stop gosftpd first. Under the packaged unit a manual `umount`
behaves differently; see
[install.md](install.md#a-data-disk-mounted-later).

**Prevention:**

- Order gosftpd after the disk: the unit has `RequiresMountsFor=/srv/sftp`.
  A disk mounted on a mount's own directory, such as `/srv/sftp/inbox`,
  needs a drop-in with `RequiresMountsFor=/srv/sftp/inbox`
  ([recipes/volume-encryption.md](recipes/volume-encryption.md)).
- Set `require_mountpoint = true` on such a mount. Without the disk,
  gosftpd then exits at start with status 2 and "mounts.NAME.require_mountpoint:
  PATH is not a mount point (it is on the same filesystem as its parent);
  is the disk mounted?", and systemd does not restart it
  (`RestartPreventExitStatus=2`). Mount the disk, then `sudo systemctl
  start gosftpd`. The mount's path itself must be the mount point: a disk
  on `/srv/sftp` does not count for `/srv/sftp/inbox`.
- A new disk's root directory belongs to root: give it to gosftpd before
  the start ([install.md](install.md#a-data-disk-mounted-later)).
- On a small disk, mind `min_free_space` (1 GiB by default): with less
  free space, every upload is refused.
