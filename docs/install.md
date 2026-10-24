# Installation

gosftpd comes in three forms, each for amd64 and arm64:

- [Packages](#packages) for Debian and Ubuntu (deb), EL9 (rpm) and Arch
  Linux install it as a systemd service, with its user, its directories,
  the man pages and the shell completions.
- [Release archives](#install-from-the-archive) for Linux, macOS and
  FreeBSD hold the binary. The Linux archives also carry the unit and the
  other files of the packages, to install the same service by hand.
- [The container image](#docker) `ghcr.io/o-kolomoiets/gosftpd` runs it
  with Docker or Compose.

Every release is signed: [verify it](#verify-a-release) before you
install it. For a first look, the [Quickstart](quickstart.md) is enough;
it puts the binary in `/usr/local/bin`. Coming from atmoz/sftp, see
[Migrate from atmoz/sftp](migrate-from-atmoz.md).

The unit needs systemd 253 or later, or EL9's 252-21 and later; for older
systemd see [systemd before 253](#systemd-before-253). It sandboxes gosftpd
(`systemd-analyze security` scores it 1.2 on systemd 255); what each setting
costs is in the [hardening guide](security/hardening.md#the-systemd-unit).

## Packages

The releases have deb, rpm and Arch packages for amd64 and arm64 (from
v0.5.0). They install the files of [What goes where](#what-goes-where), the
man pages (`man gosftpd`), the bash, zsh and fish completions, the
reference configuration (`/usr/share/doc/gosftpd/config.example.toml`) and
an empty `/etc/gosftpd/users.d`. Their scripts create the user and the
directories, give `config.toml` and `users.d` to the group gosftpd, and
install the drop-in for [systemd before 253](#systemd-before-253) where it
is needed. They never enable, start or restart the service, also not on an
upgrade.

There is no package repository: download the package for your architecture
and the release's `checksums.txt` from the
[releases](https://github.com/o-kolomoiets/Go-SFTP-Server/releases), and
[verify](#verify-a-release) them. CI installs, reloads, upgrades and
removes the packages under systemd on Ubuntu 24.04 (amd64 and arm64),
Debian 12 and 13, EL9 and Arch.

### Debian and Ubuntu

In the directory with the package for your architecture and the release's
`checksums.txt`:

<!-- ci:deb -->
```sh
V=0.5.0
sha256sum --check --ignore-missing checksums.txt
sudo apt install -y "./gosftpd_${V}_linux_$(dpkg --print-architecture).deb"
sudo systemctl enable --now gosftpd
systemctl is-active gosftpd
sudo -u gosftpd gosftpd config validate --check-fs
```
<!-- /ci -->

`apt` also installs procps, whose `kill` the drop-in for systemd before 253
reloads with. The packaged configuration has the mount `inbox`
(`/srv/sftp/inbox`) and no users: the check warns "no users configured"
until you [add one](#add-users). `sudo -u gosftpd` works from any
directory, `/root` included: the search for the configuration skips
`./gosftpd.toml` in a working directory that gosftpd cannot search. On
Ubuntu the package also keeps needrestart from restarting gosftpd after an
apt run ([operations.md](operations.md#needrestart-on-ubuntu)).

### RHEL, Rocky Linux and AlmaLinux 9

In the directory with the package and `checksums.txt` (`linux_arm64` on
ARM):

```sh
V=0.5.0
sha256sum --check --ignore-missing checksums.txt
sudo dnf install -y "./gosftpd_${V}_linux_amd64.rpm"
sudo systemctl enable --now gosftpd
systemctl is-active gosftpd
sudo -u gosftpd gosftpd config validate --check-fs
```

### Arch Linux

```sh
V=0.5.0
sha256sum --check --ignore-missing checksums.txt
sudo pacman -U "./gosftpd_${V}_linux_amd64.pkg.tar.zst"
sudo systemctl enable --now gosftpd
systemctl is-active gosftpd
sudo -u gosftpd gosftpd config validate --check-fs
```

The Arch package's version carries the epoch 0, which pacman assumes when
there is none: `pacman -Q gosftpd` prints `gosftpd 0:0.5.0-1`. A
pre-release sorts below its final in every format: `0.5.0~rc.1` in deb and
rpm, `0:0.5.0rc.1-1` in Arch.

### Upgrades and removal

To upgrade, install the new package as above; an upgrade keeps your
configuration, `users.d`, your drop-ins, the host keys, the data and the
audit log. The running server keeps the old binary until you restart it:
check the configuration with the new one, then `sudo systemctl restart
gosftpd` ([operations.md](operations.md#with-a-package)).

An upgrade keeps an edited `config.toml`. When the package's own changed
too, it leaves that next to yours, as `config.toml.dpkg-dist` (dpkg asks
first), `.rpmnew` or `.pacnew`
([merge it](operations.md#leftover-configuration-files)). It does not keep
every owner and mode:

- deb keeps an owner, group or mode you gave `config.toml` or `users.d`;
- rpm puts root:gosftpd 0750 back on `users.d` at every upgrade and
  reinstall; pacman keeps it, with a warning ("directory permissions
  differ");
- rpm and pacman put root:gosftpd 0640 back on a `config.toml` you have
  not edited; an edited one keeps its owner and mode.

So leave these files to the group gosftpd. To run gosftpd as another
account, add that account to the group instead (`sudo usermod -aG gosftpd
ACCOUNT`) and name it in a drop-in, with the data directories given to it
by a tmpfiles override (see [Another data path](#another-data-path)):

```ini
# /etc/systemd/system/gosftpd.service.d/account.conf
[Service]
User=sftp
Group=sftp
```

A removal (`sudo apt remove gosftpd`, `sudo dnf remove gosftpd`, `sudo
pacman -R gosftpd`) stops and disables the service on a running system and
deletes the unit, the binary, the drop-in for systemd before 253,
`/usr/share/gosftpd` and `/usr/share/doc/gosftpd`. What it keeps:

| | deb | rpm | Arch |
|---|---|---|---|
| `config.toml` | kept until `apt purge`, as is `/etc/needrestart/conf.d/gosftpd.conf` | an edited one is renamed to `config.toml.rpmsave`, an unedited one deleted | an edited one is renamed to `config.toml.pacsave`, an unedited one deleted |
| `users.d` | kept while it holds files, also after `apt purge` (with a warning); deleted when empty | kept while it holds files; deleted when empty | kept while it holds files; deleted when empty |
| the user gosftpd, your drop-ins, `/var/lib/gosftpd` (the host keys), `/var/log/gosftpd` (the audit log), `/srv/sftp` (the data) | kept | kept | kept |

rpm and pacman print a warning for the renamed file. After a removal and a
new install the packaged `config.toml` is back: move the saved one over it
before you start the service (`sudo mv /etc/gosftpd/config.toml.rpmsave
/etc/gosftpd/config.toml`). For a complete removal, delete what the table
keeps yourself: `/etc/gosftpd` with `users.d`, which holds password hashes
and keys, and any saved `config.toml`; `/var/lib/gosftpd` and
`/var/log/gosftpd`; the data in `/srv/sftp` once you no longer need it;
your drop-ins in `/etc/systemd/system/gosftpd.service.d`; and the user and
the group gosftpd (`userdel`, `groupdel`).

### From the archive install to a package

The packages take over the layout of an
[archive install](#install-from-the-archive); the configuration, the host
keys and the data stay. The files that no package owned need one step per
format:

- **deb:** `sudo apt-get -o Dpkg::Options::=--force-confold install
  ./gosftpd_*.deb`, or answer `N` at the prompt. An edited `config.toml`
  makes dpkg ask whether to keep it ("File on system created by you or by a
  script"), and without a terminal, as in a script, the install then fails
  with the package unpacked and not configured; `DEBIAN_FRONTEND` does not
  change that. `--force-confold` keeps your file and leaves the package's
  as `config.toml.dpkg-dist`; after a failed run, `sudo dpkg
  --force-confold --configure -a` finishes it. Ansible's apt module passes
  `--force-confold` by default.
- **rpm:** no flag: `sudo dnf install` replaces the files in `/usr`,
  keeps an edited `config.toml` and writes the package's as
  `config.toml.rpmnew`.
- **Arch:** `pacman -U` refuses the files ("conflicting files"). Name them,
  or delete them first:

  ```sh
  sudo pacman -U --overwrite /usr/bin/gosftpd --overwrite /usr/lib/systemd/system/gosftpd.service \
    --overwrite /usr/lib/sysusers.d/gosftpd.conf --overwrite /usr/lib/tmpfiles.d/gosftpd.conf \
    ./gosftpd_*.pkg.tar.zst
  ```

  It keeps an edited `config.toml` and writes the package's as
  `config.toml.pacnew`.

Then, in every format: `sudo rm /usr/local/bin/gosftpd` if it exists (it
comes first in `PATH`), delete the package's copy of `config.toml` if it
left one, once you have compared it with yours (it is the archive's
`packaging/config.toml`, unchanged since v0.4.0), and restart the service,
which still runs the archive's binary: `sudo systemctl restart gosftpd`.
The drop-in for systemd before 253 stays where the probe put it; the
package manages it from now on.

## What goes where

| From the archive | Installed as |
|---|---|
| `gosftpd` | `/usr/bin/gosftpd` |
| `packaging/systemd/gosftpd.service` | `/usr/lib/systemd/system/gosftpd.service` |
| `packaging/gosftpd.sysusers` | `/usr/lib/sysusers.d/gosftpd.conf`: the user `gosftpd`, with the home `/` |
| `packaging/gosftpd.tmpfiles` | `/usr/lib/tmpfiles.d/gosftpd.conf`: `/srv/sftp` and `/var/log/gosftpd` |
| `packaging/config.toml` | `/etc/gosftpd/config.toml` (root:gosftpd, 0640) |
| `packaging/systemd/legacy-notify.conf` | only for systemd before 253 |

The packages install the same files in the same places. The archive also
holds the man pages (`man/`, read one with `man ./man/gosftpd.1.gz`) and
the completions (`completions/`); the packages install those too.

The service keeps its data in `/srv/sftp` (the mount `inbox` is
`/srv/sftp/inbox`), its host keys in `/var/lib/gosftpd` (mode 0700) and the
audit log in `/var/log/gosftpd` (mode 0750). systemd creates the state
directory at start; tmpfiles creates the other two. The rest of the file
system is read-only for gosftpd.

The `d /srv/sftp` line of the tmpfiles file gives an existing `/srv/sftp` to
the user gosftpd. If an OpenSSH chroot lives there (it must belong to
root), choose [another data path](#another-data-path) before you install.

## Install from the archive

Download the archive and `checksums.txt` from the
[releases](https://github.com/o-kolomoiets/go-sftp-server/releases)
([verify](#verify-a-release) them), then:

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

The archive install has no `/etc/gosftpd/users.d`: `user add --write`
creates it, with the group of `config.toml`. Under Landlock a reload reads
it then, as long as `/etc/gosftpd` holds only files that the configuration
names. Once it holds another one, such as a note or a copy under another
name, create `users.d` before the start (`sudo install -d -m 0750 -g
gosftpd /etc/gosftpd/users.d`), or the first user added needs a restart;
the start warns "include: /etc/gosftpd/users.d does not exist: the first
file added there needs a restart"
([configuration.md](configuration.md#landlock)).

macOS and FreeBSD (Tier 2: cross-built, not tested) have no service files:
run the binary from the archive as in the [Quickstart](quickstart.md).
On macOS, check the archive with
`grep 'darwin_arm64\.tar\.gz$' checksums.txt | shasum -a 256 -c -`
(`darwin_amd64` on an Intel Mac).

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
`kill -HUP`; the probe in [Install from the archive](#install-from-the-archive)
installs it where it is needed and removes it where it is not, and the
packages run the same probe at every install and upgrade. It decides by
testing the feature, not by the version number (EL9 has it in 252), and is
not fooled by the drop-in itself.

After upgrading the operating system, run the probe again, or reinstall the
package. With the drop-in, `systemctl reload` can in rare cases return
before the reload has finished, and every `systemctl daemon-reload` logs
"Failed to parse service type, ignoring" for the unit.

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

## Docker

The image `ghcr.io/o-kolomoiets/gosftpd` (linux/amd64 and linux/arm64,
Docker 25 or later) runs gosftpd as uid 65532 and finds its configuration
in `/etc/gosftpd/config.toml`. Mount the directory that holds the file, not
the file itself: a reload (`docker kill -s HUP gosftpd`) then reads a file
that an editor or `sed -i` replaced.

Each release has the tag `vX.Y.Z`; `latest` names the newest stable
release. The image is distroless: it holds `/usr/bin/gosftpd`, its
entrypoint, and no shell, so `docker run IMAGE ARGS` runs `gosftpd ARGS`,
and `gosftpd serve` when there are none. Without a configuration file
`serve` exits 2 with a hint that gives the commands below, unless
atmoz/sftp users are given
([Migrate from atmoz/sftp](migrate-from-atmoz.md)). The health check is
`gosftpd healthcheck`, which turns the container `healthy` within seconds.

### Quickstart

With your public key in `~/.ssh/id_ed25519.pub`:

<!-- ci:quickstart -->
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
<!-- /ci -->

Then `sftp -P 2022 alice@localhost`. `config example` writes a
configuration with one user, `alice`, who has full access to `/srv/sftp`,
the `data` directory, with your key in place of the placeholder; the audit
log goes to stdout. gosftpd refuses a configuration that belongs to
someone other than root or the user it runs as, or that others can write:
hence the `chown root:65532` and the mode 0640. Bind mounts keep the owner
of the host directory, so `data` and `state` must belong to 65532.
`--stop-timeout 40` lets `docker stop` wait for the 30 s that running
transfers get (`server.shutdown_timeout`), not the default 10 s.

The host key is generated in `./state` at the first start, so a new
container keeps it. `docker logs gosftpd` shows its fingerprint (and the
audit log): compare it with what `sftp` shows on the first connection. The
`known_hosts` line printed there names the container's host name: put
`[localhost]:2022` in its place before you add it to `~/.ssh/known_hosts`.

Two variants:

- **Named volumes** need no `chown` of `data` and `state`: a new named
  volume starts with the owner and mode of the image's directory, which
  belongs to 65532. Leave out `sudo chown 65532:65532 data state` and mount
  `-v gosftpd-data:/srv/sftp -v gosftpd-state:/var/lib/gosftpd` instead.
- **Your own uid**, with `--user "$(id -u):$(id -g)"` added to `docker
  run -d`, needs no `sudo`: leave out both `chown` lines and run `chmod
  0600 gosftpd/config.toml` instead. The directories and the uploads then
  belong to you.

To change the configuration, edit `gosftpd/config.toml`, check it as the
server will read it, and reload:

```sh
docker exec gosftpd gosftpd config validate --check-fs
docker kill -s HUP gosftpd
docker logs --tail 5 gosftpd 2>&1 | grep 'configuration reload'
```

The log says `configuration reloaded`, or `configuration reload failed;
the running configuration stays` with the reason. A reload never
changes the image. To upgrade, read the [CHANGELOG](../CHANGELOG.md), then
replace the container with one of the new version and the same volumes:
`docker stop gosftpd && docker rm gosftpd`, and the `docker run` above with
the new tag. For tests, `serve --ephemeral` also runs in the container
([configuration.md](configuration.md#in-a-container)).

### Compose

Compose takes over from the Quickstart, in its directory, with the
release's `digests.txt`, which names the image's digest. The first command
removes the Quickstart's container, which holds port 2022; the service
mounts the same `./gosftpd`, `./data` and `./state`, so the configuration,
the uploads and the host key stay. The file is also in
[examples/compose.yaml](examples/compose.yaml), with `<digest>` in place
of the digest.

<!-- ci:compose -->
```sh
V=0.5.0
docker rm -f gosftpd
DIGEST=$(awk -v t="ghcr.io/o-kolomoiets/gosftpd:v$V" '$2 == t { print $1 }' digests.txt)
cat > compose.yaml <<EOF
# In the directory of the Quickstart (docs/install.md): ./gosftpd holds
# config.toml; ./data and ./state, owned by 65532, keep the uploads and
# the host key.
services:
  gosftpd:
    image: ghcr.io/o-kolomoiets/gosftpd:v$V@sha256:$DIGEST
    ports: ["2022:2022"]
    volumes:
      - ./gosftpd:/etc/gosftpd:ro
      - ./data:/srv/sftp
      - ./state:/var/lib/gosftpd
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    stop_grace_period: 40s
    # init: true   # with exec hooks (docs/hooks.md)
EOF
docker compose up -d --wait
```
<!-- /ci -->

## Verify a release

The release workflow signs `checksums.txt`, which lists every archive,
package and SBOM, and the image with cosign, keyless, and attests their
build provenance. These commands check a release before you install it:
the signature of `checksums.txt`, the archive against it, the archive's
provenance, and the image by the digest that `digests.txt` names. They
need cosign v3.0 or later (v2.6 only with `--new-bundle-format`; older
releases find no signature) and gh 2.68.0 or later, the first whose
`attestation verify` has `--source-ref`. gh must be logged in (`gh auth
login`, or a token in `GH_TOKEN`): `gh release download` and the
attestations API need a token, of any account. Set `V` to the version to
check; the release workflow runs the same commands before a release is
published, and again once it is.

<!-- ci:verify -->
```sh
V=0.5.0
ID="https://github.com/o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/v$V"
gh release download "v$V" -R o-kolomoiets/Go-SFTP-Server -p checksums.txt \
  -p checksums.txt.sigstore.json -p digests.txt -p "gosftpd_${V}_linux_amd64.tar.gz"
cosign verify-blob --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "gosftpd_${V}_linux_amd64.tar.gz" --repo o-kolomoiets/Go-SFTP-Server \
  --signer-workflow o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml --source-ref "refs/tags/v$V"
IMAGE="ghcr.io/o-kolomoiets/gosftpd@sha256:$(awk -v t="ghcr.io/o-kolomoiets/gosftpd:v$V" '$2 == t { print $1 }' digests.txt)"
cosign verify --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE"
gh attestation verify "oci://$IMAGE" --repo o-kolomoiets/Go-SFTP-Server \
  --signer-workflow o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml --source-ref "refs/tags/v$V"
# then run "$IMAGE", the reference just verified, not the tag
```
<!-- /ci -->

Type the identity exactly as here: cosign compares it with the
certificate's, capitals included. The identity names the release workflow
and the tag, so a signature made by any other workflow or for another
version fails; `--signer-workflow` and `--source-ref` do the same for the
attestations, which `--repo` alone would accept from any workflow of the
repository.

- **Other files.** `checksums.txt` covers every archive, package and SBOM:
  download the file you install next to it (another `-p` to `gh release
  download`), run `sha256sum` again, and the first `gh attestation verify`
  with its name.
- **The image by digest.** A tag can move; the digest cannot. Run the
  reference you verified, `"$IMAGE"`, and give Compose the tag with the
  digest (`image: ghcr.io/o-kolomoiets/gosftpd:vX.Y.Z@sha256:...`, as in
  [Compose](#compose)). `docker buildx imagetools inspect
  ghcr.io/o-kolomoiets/gosftpd:vX.Y.Z` shows the digest a tag names now.
  Admission controllers need Sigstore bundle and OCI 1.1 referrer support
  to find the image's signature.
- **Without the attestations API**, or without a GitHub login, the release
  carries the provenance of its files as `gosftpd_X.Y.Z.intoto.jsonl`,
  which `curl` or a browser downloads like the other assets: `gh
  attestation verify FILE --bundle "gosftpd_${V}.intoto.jsonl"` with the
  same `--repo`, `--signer-workflow` and `--source-ref` needs no login. gh still
  fetches Sigstore's trust root; on a host without internet access, write
  it beforehand on another one with `gh attestation trusted-root >
  trusted_root.jsonl` and add `--custom-trusted-root trusted_root.jsonl`.
  The image's provenance is only in the attestations API.

Releases before v0.5.0 are not signed: they have only an unsigned
`checksums.txt`. Tags are not signed either; the signatures and
attestations name the tag.

## Rebuild a release

Two builds of the same tag with the same Go and GoReleaser versions give
the same archives and packages, so you can rebuild a release and compare
it with its `checksums.txt`, once that is verified as above. You need the
Go version that built the release, which `gosftpd version` prints (or
`go version -m gosftpd`), and the GoReleaser version that
`.github/workflows/release.yml` names at the tag (the `version:` of the
GoReleaser step). `GOTOOLCHAIN=goX.Y.Z` in the environment makes the go
command fetch and use that Go release. In the directory with the verified
`checksums.txt`:

```sh
V=0.5.0
git clone --branch "v$V" https://github.com/o-kolomoiets/Go-SFTP-Server.git "gosftpd-$V"
cd "gosftpd-$V"
GORELEASER_CURRENT_TAG="v$V" goreleaser release --clean --skip=publish,sign,sbom,docker
cd dist && sha256sum --check --ignore-missing ../../checksums.txt
```

Each of the 12 archives and packages must print `OK`. `--skip=publish`
needs no token. Not `--snapshot`: it names every file
`X.Y.Z-SNAPSHOT-COMMIT`, so nothing would match. Signatures, SBOMs and the
image are not reproducible and are left out. `GORELEASER_CURRENT_TAG`
makes GoReleaser build that tag and no other on the same commit, such as
the final of an rc you rebuild.
