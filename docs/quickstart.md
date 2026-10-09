# Quickstart

From nothing to a first upload in a few minutes. You need an SSH key pair
(`ssh-keygen -t ed25519` if you have none) and an SFTP client; OpenSSH `sftp`
is used below.

## Install

Download the archive for your system from the
[releases](https://github.com/o-kolomoiets/go-sftp-server/releases), check it
against `checksums.txt` and put `gosftpd` in your `PATH`:

```sh
sha256sum --check --ignore-missing checksums.txt
tar xzf gosftpd_*_linux_amd64.tar.gz gosftpd
sudo install gosftpd /usr/local/bin/
gosftpd version
```

Or build it with Go 1.26.5 or newer:

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest
```

## One directory, no configuration

```sh
mkdir share
gosftpd serve --dir ./share
```

Every SSH user name is accepted with the keys from `~/.ssh/authorized_keys`
(or `--authorized-keys FILE`, `--user NAME` to accept one name only). On first
start gosftpd creates a host key and prints its fingerprint and a
`known_hosts` line:

```text
host key: /home/me/.config/gosftpd/ssh_host_ed25519_key (generated, 0600)
  ED25519 SHA256:...
  known_hosts: [myhost]:2022 ssh-ed25519 AAAA...
connect: sftp -P 2022 <user>@myhost
```

Compare the fingerprint with what your client shows on first connection, or add
the `known_hosts` line to `~/.ssh/known_hosts`. Then:

```sh
sftp -P 2022 "$USER@localhost"
sftp> put notes.txt
sftp> ls -l
```

Uploading over an existing file does not replace it: the upload goes to
`notes (1).txt`. Use `--on-conflict overwrite`, `reject` or `version` (keeps
the old file in `.versions`) to change that.

## Several users with a configuration file

```sh
gosftpd init --user alice --authorized-keys ~/.ssh/id_ed25519.pub
```

This writes `./gosftpd.toml` (mode 0600), which `gosftpd serve` finds on its
own, and the host key. It serves `./share` with full access for `alice`. Add
a partner who may only drop files into it:

```sh
gosftpd user add partner --key partner.pub --access share=upload --expires 720h >> gosftpd.toml
gosftpd config validate --check-fs
gosftpd serve
```

`partner` can list and upload, but not download, delete or overwrite; an
upload over an existing name becomes a copy. See
[configuration.md](configuration.md) for mounts, per-user home directories,
permissions and every other key, and [audit-log.md](audit-log.md) for the
JSON audit log on stdout.

## Running it as a service

Run gosftpd as an unprivileged user that owns the served directories, never as
root. A systemd unit, packages and a Docker image are planned for v0.4–v0.5;
until then any supervisor works: gosftpd stops cleanly on SIGTERM (running
transfers get `shutdown_timeout`, 30 s by default) and ignores SIGHUP.
