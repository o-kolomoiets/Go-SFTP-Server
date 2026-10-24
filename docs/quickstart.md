# Quickstart

From nothing to a first upload in a few minutes. You need an SSH key pair
(`ssh-keygen -t ed25519` if you have none) and an SFTP client; OpenSSH `sftp`
is used below. With Docker, skip to [With Docker](#with-docker); coming
from atmoz/sftp, see [Migrate from atmoz/sftp](migrate-from-atmoz.md).

## Install

Download the archive for your system (Linux, macOS or FreeBSD, amd64 or
arm64) from the
[releases](https://github.com/o-kolomoiets/go-sftp-server/releases), check it
against `checksums.txt` ([verify](install.md#verify-a-release) that file's
signature first) and put `gosftpd` in your `PATH`:

```sh
sha256sum --check --ignore-missing checksums.txt
tar xzf gosftpd_*_linux_amd64.tar.gz gosftpd
sudo install gosftpd /usr/local/bin/
gosftpd version
```

On macOS, check the archive with
`grep 'darwin_arm64\.tar\.gz$' checksums.txt | shasum -a 256 -c -`
(`darwin_amd64` on an Intel Mac). Or build it with Go 1.26.5 or newer:

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
gosftpd user add partner --key partner.pub --access share=upload --expires 720h --write
gosftpd serve
```

`user add --write` checks the configuration with the new user, writes
`users.d/partner.toml` (`gosftpd init` includes that directory) and prints the
connection details to send to the partner: host, port, host key fingerprint
and the `sftp` command. On a running server, `kill -HUP` (or `systemctl reload
gosftpd`) applies it without a restart; `gosftpd user disable partner`,
`enable` and `remove` change the file the same way.

On Linux `serve` confines itself with Landlock
([security.md](security.md#landlock)), and in `init`'s layout `share` lies
next to `gosftpd.toml`: an edit that replaces `gosftpd.toml` by rename
(`sed -i`, most editors) then needs a restart, and every reload fails until
one. To reload such edits too, keep `gosftpd.toml` in a directory that
holds only gosftpd's files (`gosftpd.toml` and `users.d`, not your home
directory), for example with `init --out DIR/gosftpd.toml --dir
NAME=PATH`.

`partner` can list and upload, but not download, delete or overwrite; an
upload over an existing name becomes a copy. See
[configuration.md](configuration.md) for mounts, per-user home directories,
permissions and every other key, and [audit-log.md](audit-log.md) for the
JSON audit log on stdout.

## With Docker

The image `ghcr.io/o-kolomoiets/gosftpd` needs no Go and no archive. In an
empty directory, with your public key in `~/.ssh/id_ed25519.pub`:

```sh
V=0.5.0
mkdir -p gosftpd data state
docker run --rm "ghcr.io/o-kolomoiets/gosftpd:v$V" config example > gosftpd/config.toml
sed -i "s|<paste your public key[^>]*>|$(cat ~/.ssh/id_ed25519.pub)|" gosftpd/config.toml
sudo chown root:65532 gosftpd/config.toml && sudo chmod 0640 gosftpd/config.toml
sudo chown 65532:65532 data state
docker run -d --name gosftpd --stop-timeout 40 -p 2022:2022 \
  -v ./gosftpd:/etc/gosftpd:ro -v ./data:/srv/sftp -v ./state:/var/lib/gosftpd \
  "ghcr.io/o-kolomoiets/gosftpd:v$V"
```

Then `sftp -P 2022 alice@localhost`; `docker logs gosftpd` shows the host
key's fingerprint and the audit log. The configuration lives in
`gosftpd/`, a mounted directory: edit it and `docker kill -s HUP gosftpd`
applies it. The uploads land in `data/` and the host key in `state/`, so
a new container keeps both. [install.md](install.md#docker) explains each
line, the variants without `sudo`, Compose, reloads and upgrades.

## Running it as a service

Run gosftpd as an unprivileged user that owns the served directories, never as
root. On Linux with systemd, the deb, rpm and Arch packages install it as a
service with its user and directories ([install.md](install.md#packages)),
and so does the release archive by hand: the binary then goes to `/usr/bin`
instead, and a copy left in `/usr/local/bin` should be removed. Any other
supervisor works too: gosftpd stops cleanly on SIGTERM (running transfers
get `shutdown_timeout`, 30 s by default) and applies its configuration
again on SIGHUP without dropping connections (see
[Reload](configuration.md#reload)).
