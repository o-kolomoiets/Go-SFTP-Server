# Volume encryption

gosftpd does not encrypt files: encryption at rest is the job of the disk
or the file system, which keeps the keys out of the server process
([ADR 0002](../adr/0002-non-goals.md)). To gosftpd an encrypted disk is a
data disk like any other. What matters is the order: the disk must be
unlocked and mounted before gosftpd starts, or gosftpd serves the empty
directory below the mount point. This page shows that order for LUKS2,
fscrypt, ZFS and cloud disks, in the packaged layout of
[install.md](../install.md).

## Where to mount the disk

- **On `/srv/sftp`**, the directory that holds the mounts. The packaged
  unit already starts gosftpd only after the file system mounted there
  (`RequiresMountsFor=/srv/sftp`), and the disk's `lost+found` stays out
  of the users' sight.
- **On a mount's own directory**, such as `/srv/sftp/inbox`, when a mount
  has a disk of its own, or when you unlock the disk by hand. Then add a
  drop-in and `require_mountpoint = true` (below). The users of that mount
  see the disk's `lost+found` directory, which they cannot open.

Keep key files off the data disk, and out of `/etc/gosftpd`: under
Landlock a file there that the configuration does not name makes the
directory shared ([configuration.md](../configuration.md#landlock)).

## LUKS2

Format the disk (this erases it), open it and create a file system:

```sh
sudo cryptsetup luksFormat --type luks2 /dev/disk/by-id/DISK
sudo cryptsetup open /dev/disk/by-id/DISK sftp-data
sudo mkfs.ext4 /dev/mapper/sftp-data
sudo cryptsetup luksUUID /dev/disk/by-id/DISK      # for /etc/crypttab
```

### Unlocked at boot, on /srv/sftp

```
# /etc/crypttab
sftp-data  UUID=LUKS-UUID  none  luks
```

```
# /etc/fstab
/dev/mapper/sftp-data  /srv/sftp  ext4  defaults,nofail  0  2
```

With `none`, systemd reads the key from `/etc/cryptsetup-keys.d/sftp-data.key`
if that file exists, and asks for the passphrase at boot otherwise;
`systemd-cryptenroll --tpm2-device=auto` and the option `tpm2-device=auto`
unlock the disk with the TPM instead. `nofail` lets the boot go on without
the disk, so that you can still log in; gosftpd does not start without it.

The first time, stop gosftpd, copy what `/srv/sftp` holds now onto the disk
(it would be hidden below the mount point), mount it, give its root
directory to gosftpd and start:

```sh
sudo systemctl stop gosftpd
sudo mount /dev/mapper/sftp-data /mnt
sudo cp -a /srv/sftp/. /mnt/
sudo umount /mnt
sudo systemctl daemon-reload
sudo mount /srv/sftp
sudo systemd-tmpfiles --create gosftpd.conf
sudo runuser -u gosftpd -- gosftpd config validate --check-fs --config /etc/gosftpd/config.toml
sudo systemctl start gosftpd
```

`systemd-tmpfiles --create` gives `/srv/sftp` to gosftpd, as for any disk
mounted there later ([install.md](../install.md#a-data-disk-mounted-later));
the owner is kept on the disk.

### On a mount's directory

For a disk on `/srv/sftp/inbox`, order gosftpd after it with a drop-in,
then run `sudo systemctl daemon-reload`:

```ini
# /etc/systemd/system/gosftpd.service.d/inbox-disk.conf
[Unit]
RequiresMountsFor=/srv/sftp/inbox
```

and set `require_mountpoint` on the mount in `/etc/gosftpd/config.toml`:

```toml
[mounts.inbox]
path = "/srv/sftp/inbox"
create = true
require_mountpoint = true
```

The fstab line names `/srv/sftp/inbox` instead of `/srv/sftp`. After the
first mount, give the disk's root directory to gosftpd; the owner is kept
on the disk:

```sh
sudo mount /srv/sftp/inbox
sudo chown gosftpd:gosftpd /srv/sftp/inbox
sudo chmod 0750 /srv/sftp/inbox
```

### Unlocked by hand

When nobody may unlock the disk but a person, keep it out of the boot:
`noauto` in `/etc/fstab`, no crypttab line, and no `RequiresMountsFor=`
drop-in for it (systemd would then try to mount and unlock the disk before
it starts gosftpd). Mount it on the mount's directory with
`require_mountpoint = true`:

```
# /etc/fstab
/dev/mapper/sftp-data  /srv/sftp/inbox  ext4  noauto  0  2
```

At boot gosftpd then exits with status 2 and "mounts.inbox.require_mountpoint:
/srv/sftp/inbox is not a mount point (it is on the same filesystem as its
parent); is the disk mounted?". The unit's `RestartPreventExitStatus=2`
keeps systemd from restarting it, and `systemctl status gosftpd` shows the
failure until you start it. To unlock, mount and start:

```sh
sudo cryptsetup open /dev/disk/by-uuid/LUKS-UUID sftp-data
sudo mount /srv/sftp/inbox
sudo systemctl start gosftpd
```

## fscrypt

fscrypt encrypts a directory on ext4, f2fs and a few other file systems,
not a whole disk, and only an empty one. After a reboot the directory is
locked until its key is given: file names are scrambled and new files
cannot be created. gosftpd cannot tell (`require_mountpoint` sees the same
file system), so it must not start before the directory is unlocked.
fscrypt unlocks a directory for all users, gosftpd included.

```sh
sudo fscrypt setup     # and fscrypt setup MOUNTPOINT for a file system other than /
sudo install -d -m 0750 -o gosftpd -g gosftpd /srv/sftp/inbox   # new and empty
sudo fscrypt encrypt /srv/sftp/inbox
```

`fscrypt encrypt` asks for a protector: a passphrase, or a raw key file
(`--source=raw_key --key=FILE`, 32 bytes). With a passphrase, unlock by
hand: keep gosftpd from starting at boot (`sudo systemctl disable
gosftpd`), and after each boot run `sudo fscrypt unlock /srv/sftp/inbox`,
then `sudo systemctl start gosftpd`. With a key file, a oneshot unit
unlocks the directory at boot, and a drop-in makes gosftpd depend on it:

```ini
# /etc/systemd/system/gosftpd-unlock.service
[Unit]
Description=Unlock the encrypted gosftpd inbox
RequiresMountsFor=/srv/sftp
Before=gosftpd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/fscrypt unlock /srv/sftp/inbox --key=/etc/gosftpd-keys/inbox.key
```

```ini
# /etc/systemd/system/gosftpd.service.d/unlock.conf
[Unit]
Requires=gosftpd-unlock.service
After=gosftpd-unlock.service
```

## ZFS

Create the dataset with encryption on, mounted on the mount's directory:

```sh
sudo zfs create -o encryption=on -o keyformat=passphrase -o mountpoint=/srv/sftp/inbox tank/sftp-inbox
sudo chown gosftpd:gosftpd /srv/sftp/inbox
sudo chmod 0750 /srv/sftp/inbox
```

A dataset is a file system of its own, so `require_mountpoint = true` on
the mount works as for a LUKS disk: without the dataset mounted, gosftpd
does not start. After a reboot, load the key, mount and start:

```sh
sudo zfs load-key tank/sftp-inbox
sudo zfs mount tank/sftp-inbox
sudo systemctl start gosftpd
```

With a key file (`keyformat=raw`, `keylocation=file:///...`), the ZFS units
of your distribution can load the key and mount the dataset at boot; a
drop-in with `After=zfs-mount.service` then orders gosftpd after them.

## Cloud disks

Disks that the cloud provider encrypts (encrypted EBS volumes, Persistent
Disk, Azure managed disks) need nothing in gosftpd. Mount one like any
data disk, as in [LUKS2](#luks2) without the `cryptsetup` steps and the
crypttab line: on `/srv/sftp` with `nofail`, or on a mount's directory
with the drop-in and `require_mountpoint`.

## A disk mounted after gosftpd started

gosftpd keeps the directory it opened at start. Without Landlock a reload
makes new logins use the disk; under Landlock, the default on Linux, the
mount is unavailable until a restart. Both are in
[operations.md](../operations.md#a-disk-mounted-on-a-mount-directory). So
unlock and mount first, then start gosftpd, as above.

## What is tested

CI checks the systemd units and drop-ins on this page offline
(`systemd-analyze verify` in
[test/systemd/lint.sh](../../test/systemd/lint.sh)). It does not test the
`cryptsetup`, crypttab, fstab, fscrypt or ZFS steps, nor whether a disk
mounted on the host while gosftpd runs reaches the unit's mount namespace.
The exit status 2 of `require_mountpoint` without the disk was tested by
hand.
