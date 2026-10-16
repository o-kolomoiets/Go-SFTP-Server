# Retention

gosftpd never deletes old files on its own: retention is the job of a
scheduler ([ADR 0002](../adr/0002-non-goals.md)). This page deletes files
in `/srv/sftp/inbox` 30 days after they arrived, in three ways:
systemd-tmpfiles, a systemd timer that runs `find`, and a hook that moves
each file to an archive that expires.

Whatever deletes the files, it is not gosftpd, so the deletions are not in
the audit log. And clients that synchronize a folder (`rclone copy` or
`sync`, WinSCP Synchronize, `lftp mirror -R`) upload a deleted file again
on their next run while they still have it.

## systemd-tmpfiles

One line in a file of its own:

```
# /etc/tmpfiles.d/gosftpd-retention.conf
e /srv/sftp/inbox - - - c:30d
```

- `e` cleans the contents of an existing directory; `c:30d` deletes a file
  when its change time (ctime) is more than 30 days old. For a file at
  rest that is when it arrived: the end of its upload, or its rename into
  place.
- Old versions of `on_conflict = "version"` expire the same way. The move
  into the versions directory sets a version's change time, so tmpfiles
  deletes it 30 days after it was saved, the default `versions.max_age`.
  Do not exclude the versions directory: gosftpd prunes the versions of a
  file only when it saves the next one, so the versions of a file that
  tmpfiles deleted would stay forever.
- Empty directories go too. A lowercase letter such as `c` ages files
  only; directories are aged by their access, birth and modification
  times, and tmpfiles removes an empty one once all three are more than
  30 days old. That includes a folder a partner created and the versions
  directory; gosftpd creates the versions directory again when it saves
  the next version.
- Do not call the file `gosftpd.conf`: a file of that name in
  `/etc/tmpfiles.d` replaces the packaged
  `/usr/lib/tmpfiles.d/gosftpd.conf` ([install.md](../install.md#another-data-path)).

For a home mount (`path = "/srv/sftp/home/{user}"`):

```
# /etc/tmpfiles.d/gosftpd-retention-home.conf
e /srv/sftp/home - - - ~c:30d
```

The `~` keeps what is directly in `/srv/sftp/home`, the users'
directories, and ages everything inside them as above, versions
included. Without it, tmpfiles removes the directory of a user whose
files have all expired, and with `create = false` (the default) that
user's home mount is then unavailable (`fs.denied` with
`reason = "home_missing"`).

`systemd-tmpfiles-clean.timer` applies the lines 15 minutes after boot and
then once a day. To apply them now:

```sh
sudo systemd-tmpfiles --clean /etc/tmpfiles.d/gosftpd-retention.conf
```

**Why `c:`.** tmpfiles can age a file by its access, birth, change or
modification time. Tested with systemd 255 on ext4:

- `c:30d` deleted the files that arrived more than 30 days ago, also one
  that had been read since, and kept a new upload whose client had set an
  old modification time.
- `30d`, without a letter, deletes a file only when all its times are
  older. It kept the old file that had been read: every download, or a
  backup that reads the files, renews the access time and postpones the
  deletion.
- `m:30d` deleted the new upload with the old modification time at the
  first run. Clients that keep the times of the files they upload (`sftp
  put -p`, rclone, WinSCP) set it. Do not use `m:`.

The change time is also set by a client's rename or SETSTAT, and by a
restore from a backup: restored files count as new.

## A timer with find

A oneshot service that runs `find` as the user gosftpd, and a timer that
starts it every day. Each deleted file is in the journal.

```ini
# /etc/systemd/system/gosftpd-retention.service
[Unit]
Description=Delete files older than 30 days from the gosftpd inbox
RequiresMountsFor=/srv/sftp

[Service]
Type=oneshot
User=gosftpd
Group=gosftpd
ExecStart=/usr/bin/find /srv/sftp/inbox -xdev -type f -cmin +43200 -not -name '.gosftpd-*' -print -delete
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/srv/sftp/inbox
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
```

```ini
# /etc/systemd/system/gosftpd-retention.timer
[Unit]
Description=Delete old files from the gosftpd inbox every day

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now gosftpd-retention.timer
sudo systemctl start gosftpd-retention.service   # once now
journalctl -u gosftpd-retention.service          # what it deleted
```

`-cmin +43200` is 30 days in minutes, by change time as above, also for
old versions. `-xdev` stays on the inbox's file system, `-type f` leaves
every directory, and `-not` skips the temporary files of uploads in
progress (gosftpd removes those left over itself). With
`Persistent=true`, a run missed while the machine was off starts at the
next boot.

## Hooks

An exec hook can move each file to an archive when it arrives, which
empties the inbox at once; tmpfiles then deletes the archive by age. The
hook and the script are in [hooks.md](../hooks.md): the `archive` hook at
the top, and the script under [exec](../hooks.md#exec), which moves files
to `/srv/archive/USER/`. The unit needs the drop-in that lets gosftpd write
there ([Sandboxes and containers](../hooks.md#sandboxes-and-containers)),
and tmpfiles creates the archive and expires it:

```
# /etc/tmpfiles.d/gosftpd-archive.conf
d /srv/archive 0750 gosftpd gosftpd c:30d
```

```sh
sudo systemd-tmpfiles --create /etc/tmpfiles.d/gosftpd-archive.conf
```

The move sets the file's change time, so the 30 days count from the
archiving. Before you choose hooks:

- A hook waits at most an hour (`delay`): it cannot delete a file after
  30 days, only move it.
- Hook events wait in memory. At a stop, hooks get a few seconds for the
  events still waiting and drop the rest
  ([hooks.md](../hooks.md#shutdown)); a crash loses them all. Their files
  stay in the inbox: add the tmpfiles lines of the first section as a
  sweep for them.
- An exec hook turns Landlock off for the whole process
  ([hooks.md](../hooks.md#sandboxes-and-containers)).
- A partner whose client synchronizes a folder uploads every moved file
  again ([hooks.md](../hooks.md#recipes)).

## What is tested

CI checks the units and tmpfiles files on this page offline
(`systemd-analyze verify` and `systemd-tmpfiles` in
[test/systemd/lint.sh](../../test/systemd/lint.sh)); it runs neither the
timer nor the cleanup. The ages above, the directories and `~` were tested
by hand, with systemd 255 on ext4.
