# Migrate from atmoz/sftp

The gosftpd image runs the users of [atmoz/sftp](https://github.com/atmoz/sftp)
as that image does: user specs as arguments, in `SFTP_USERS` or in
`/etc/sftp/users.conf`, directories under `/home/<user>`, keys in
`/home/<user>/.ssh/keys/` and host keys in `/etc/ssh`. This is atmoz mode
([ADR 0012](adr/0012-distribution.md#atmoz-compatibility)). Most atmoz
commands keep working after five changes:

| atmoz/sftp | gosftpd |
|---|---|
| `atmoz/sftp` | `ghcr.io/o-kolomoiets/gosftpd:v0.5.0` |
| `-p 22:22`, `-p 2222:22` | `-p 22:2022`, `-p 2222:2022`: the container listens on 2022 |
| `:e` with an MD5-crypt or SHA-crypt hash | `:e` with a bcrypt (cost 10 to 14) or argon2id hash ([Passwords](#passwords)) |
| a mounted `users.conf` of any owner | owned by root, readable by the image's group 65532 and not by others, as it holds passwords: `sudo chown root:65532 users.conf && sudo chmod 0640 users.conf` |
| a mounted key file of any owner | owned by root and not writable by group or others: `sudo chown root:root FILE && sudo chmod 0644 FILE` |

Files that clients upload belong to the user the image runs as, 65532, not
to the uid of the spec ([Ownership](#ownership)). An upload to an existing
name overwrites it, as in atmoz. The server is not OpenSSH: there is no
shell and no `/etc/sftp.d` scripts.

## The README's examples

Each example of the atmoz README, as it runs with gosftpd.

**Simplest `docker run`:** user foo with password pass uploads to `/upload`.

```sh
docker run -p 22:2022 -d ghcr.io/o-kolomoiets/gosftpd:v0.5.0 foo:pass:::upload
```

The image's `/home` belongs to 65532, so gosftpd creates
`/home/foo/upload` without a volume. gosftpd warns that the password is
visible to anyone who can run `docker inspect`; see [Passwords](#passwords).

**Sharing a directory from your computer:**

```sh
sudo chown 65532:65532 <host-dir>/upload
docker run \
    -v <host-dir>/upload:/home/foo/upload \
    -p 2222:2022 -d ghcr.io/o-kolomoiets/gosftpd:v0.5.0 \
    foo:pass:1001
```

The spec names no directory: in the image every directory that exists
directly under `/home/foo` at start becomes one of foo's, here `upload`.
The uid 1001 is ignored.

**Using Docker Compose:** the atmoz README's file puts the service at the
top level, which current Compose refuses ("additional properties 'sftp'
not allowed"); it goes under `services:`. With `<host-dir>/upload` owned
by 65532, as in the example before:

```yaml
services:
  sftp:
    image: ghcr.io/o-kolomoiets/gosftpd:v0.5.0
    volumes:
      - <host-dir>/upload:/home/foo/upload
    ports:
      - "2222:2022"
    command: foo:pass:1001
```

**Logging in:** `sftp -P 2222 foo@<host-ip>`, as before.

**Store users in config:**

```sh
sudo chown root:65532 <host-dir>/users.conf && sudo chmod 0640 <host-dir>/users.conf
docker run \
    -v <host-dir>/users.conf:/etc/sftp/users.conf:ro \
    -v mySftpVolume:/home \
    -p 2222:2022 -d ghcr.io/o-kolomoiets/gosftpd:v0.5.0
```

The file holds passwords: the image's group 65532 and mode 0640 let
gosftpd read it, and not the other users of the host.

`users.conf` holds one spec per line; blank lines and lines starting with
`#` are skipped. Its users `foo:123:1001:100` and so on name no directory:
on a fresh volume they log in to an empty, read-only root, as in atmoz,
and gosftpd warns about each. Give them a directory in the spec
(`foo:123:1001:100:upload`) or create one in the volume.

**Encrypted password:** the README's `$1$` hash is MD5-crypt, which
gosftpd refuses (exit 2, "create a hash with 'gosftpd user
hash-password'"). Make a bcrypt or argon2id hash and keep the `:e`:

```sh
docker run \
    -v <host-dir>/share:/home/foo/share \
    -p 2222:2022 -d ghcr.io/o-kolomoiets/gosftpd:v0.5.0 \
    'foo:$2y$10$...:e:1001'
```

**Logging in with SSH keys:**

```sh
sudo chown root:root <host-dir>/id_rsa.pub <host-dir>/id_other.pub
sudo chmod 0644 <host-dir>/id_rsa.pub <host-dir>/id_other.pub
sudo chown 65532:65532 <host-dir>/share
docker run \
    -v <host-dir>/id_rsa.pub:/home/foo/.ssh/keys/id_rsa.pub:ro \
    -v <host-dir>/id_other.pub:/home/foo/.ssh/keys/id_other.pub:ro \
    -v <host-dir>/share:/home/foo/share \
    -p 2222:2022 -d ghcr.io/o-kolomoiets/gosftpd:v0.5.0 \
    foo::1001
```

Every file in `/home/<user>/.ssh/keys/` is read as an `authorized_keys`
file; a name that starts with `.` is skipped. Like every file gosftpd
trusts, it must belong to root or to the user gosftpd runs as and must not
be writable by group or others: a key bind-mounted from a home directory
on the host belongs to that user, hence the `chown root`. A line that
cannot be used (a DSA key, an unknown option) is skipped with a warning.

**Providing your own SSH host key:** clients keep their `known_hosts`
entry when the old keys are mounted where atmoz kept them. Like every
host key, they must belong to the user gosftpd runs as, with mode 0600:

```sh
sudo chown 65532:65532 <host-dir>/ssh_host_ed25519_key <host-dir>/ssh_host_rsa_key
sudo chmod 0600 <host-dir>/ssh_host_ed25519_key <host-dir>/ssh_host_rsa_key
docker run \
    -v <host-dir>/ssh_host_ed25519_key:/etc/ssh/ssh_host_ed25519_key:ro \
    -v <host-dir>/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key:ro \
    -v <host-dir>/share:/home/foo/share \
    -p 2222:2022 -d ghcr.io/o-kolomoiets/gosftpd:v0.5.0 \
    foo::1001
```

Without them gosftpd generates `/var/lib/gosftpd/ssh_host_ed25519_key` on
the first start; mount a volume on `/var/lib/gosftpd` to keep it, as in the
[Quickstart](quickstart.md).

**Execute custom scripts, bindmount dirs:** the image has no shell and runs
nothing from `/etc/sftp.d`. Mount each directory where the user should see
it instead, which needs no `CAP_SYS_ADMIN`: `-v /data/common:/home/dave/common`.
With `:ro` the directory is read-only for everyone; gosftpd warns at start
that uploads to it fail.

## User specs

`user:pass[:e][:uid[:gid[:dir1[,dir2]...]]]`, split as atmoz splits it.

- **user** must be a gosftpd user name: lowercase letters, digits, `.`,
  `_` and `-`, at most 32, starting with a letter or a digit. atmoz also
  takes upper case and a leading `.` or `_`; rename such users.
- **pass** is the password, at most 255 characters; empty means keys only.
  With `:e` it is a hash ([Passwords](#passwords)).
- **uid** and **gid** must be numbers and are ignored, with one line in the
  log: the users are virtual, and files belong to the user gosftpd runs as.
- **dirs** are directories directly under `/home/<user>`, separated by `,`.
  Each must be a mount name (letters, digits, `.`, `_`, `-` and spaces, not
  starting with `.`, not a device name such as `NUL`), not `.ssh`, and not
  nested (`a/b`); two whose names differ only in case are an error. A
  spec with more fields than the syntax has is an error too.

User `foo` with directory `upload` sees `/upload`, stored in
`/home/foo/upload`; the top level `/` is read-only, as atmoz's root-owned
home is, and `/home/foo/.ssh` is never reachable. Each directory is a mount
of its own: two users' `upload` share nothing.

The sources are read in atmoz's order: the users file, the arguments, then
`SFTP_USERS` (separated by white space). A user given again is skipped with
a warning: the first definition wins. A spec that cannot be used stops the
start with exit 2; the message names the source and position (`argument
2`, `SFTP_USERS entry 3`, `/etc/sftp/users.conf line 4`), the user once
its name is valid, and the field, never the password or the spec.

In the image, a directory that exists under `/home/<user>` at start is one
of the user's, whether the spec names it or not; a name that is not a
mount name (`lost+found`, `_data`, a dot name) is skipped with a warning,
`.ssh` silently, and so are files and links. gosftpd creates the
directories a spec names; one it cannot create, such as a second
directory without a volume under a `/home/foo` that Docker created for the
first one, owned by root, is unavailable to its user, with a warning; give
it a volume of its own, or `chown 65532` the parent on the host. So is a
directory it cannot open, such as a volume whose host directory belongs
to another user with mode 0700: `chown 65532` that directory.

## Passwords

A plain password in an argument or in `SFTP_USERS` is visible to anyone
who can run `docker inspect` or read the process's command line or
environment; gosftpd warns about each. It hashes it with argon2id at start
and keeps only the hash. Better, give a hash with `:e`:

```sh
docker run --rm -it ghcr.io/o-kolomoiets/gosftpd:v0.5.0 user hash-password   # argon2id, asked twice
htpasswd -nBC 10 "" | tr -d ':\n'                                            # bcrypt, asked twice
```

Both ask for the password, so that it stays out of the shell history and
the process list; do not give it to `htpasswd` with `-b`.

`htpasswd`'s default bcrypt cost, 5, is below gosftpd's minimum of 10:
pass `-C 10` or more (up to 14). MD5-crypt (`$1$`), SHA-crypt (`$5$`,
`$6$`, Python's `crypt` default) and yescrypt (`$y$`) are refused. When
plain and hashed passwords are mixed, or hashes of different costs,
gosftpd warns that the response time can tell which users exist.

In a compose file, write each `$` of a hash as `$$`, in `command:` and in
`environment:`; Compose would expand it otherwise:

```yaml
    command: 'foo:$$2y$$10$$...:e:1001'
    environment:
        SFTP_USERS: 'bar:$$argon2id$$v=19$$m=19456,t=2,p=1$$...:e:::inbox'
```

No message of gosftpd shows a password, a hash or a spec. atmoz logs each
spec ("Parsing user data") to `docker logs`; delete those logs if you kept
them.

## Changes take a restart

gosftpd reads the users file, the keys and the directories once, at start,
before it locks itself down (Landlock). SIGHUP is logged and ignored. After
a change, run `docker restart` (or `docker compose restart`), not `docker
kill -s HUP`. The restart also mounts a single file again: a users file or
key edited on the host with a tool that replaces the file (`sed -i`, most
editors) is otherwise still the old one in the container.

A key file mounted on its own that you remove on the host makes the
restart fail: Docker creates a directory in its place. Remove its `-v` as
well, or mount the whole keys directory, `-v <host-dir>/keys:/home/foo/.ssh/keys:ro`,
and remove the file from it.

## Ownership

Files that clients upload belong to 65532, the image's user, with mode
0640 (directories 0750). On a bind mount, or a volume on a directory that
the image does not have, `chown 65532:65532` the directory first; a new
named volume on `/home` belongs to 65532 already, as the image's `/home`
does. To get
atmoz's ownership back, run the container as that user: `--user 1001:100`
with a volume for the host key that this user can write
(`-v <host-dir>/state:/var/lib/gosftpd`, owned by 1001) and a volume for
each user's directories; then the users file and the keys may also
belong to 1001. The users file then takes that group instead of 65532
(`sudo chown root:100 users.conf && sudo chmod 0640 users.conf`), or
belongs to 1001 with mode 0600.

## When atmoz mode starts

The image's command is `serve`. It looks for a configuration file
(`/etc/gosftpd/config.toml`); only when there is none does it read the
atmoz users. A mounted configuration always wins over `SFTP_USERS` and
`/etc/sftp/users.conf`, which are then ignored with a warning. Specs given
as arguments replace the command and always start atmoz mode; a
configuration file is then ignored, with a warning.

An `/etc/gosftpd` without `config.toml` never starts atmoz mode: the image
has no such directory, so it is a mount whose host path is wrong or did
not exist. gosftpd exits 2 with a hint instead of serving the old users.

The image sets `GOSFTPD_ATMOZ_IMAGE=1`. Only then do the default users
file, the discovery of directories under `/home/<user>` and the host keys
in `/etc/ssh` apply. Outside the image, give the users file with
`--users-conf`, name every directory in the specs (still
`/home/<user>/<dir>`, which gosftpd must be able to create or write), and
the host key is generated in the state directory, as with `--dir`:

```sh
gosftpd serve --users-conf ./users.conf --state-dir ./state
gosftpd 'foo:$2y$10$...:e:::upload' --listen :2222
```

The packaged systemd unit never reaches atmoz mode: it passes `--config`,
and its `ProtectHome=yes` hides `/home`.

Atmoz mode takes these flags: `--users-conf`, `--listen`, `--host-key`,
`--state-dir`, `--read-only`, `--on-conflict` (default `overwrite`),
`--allow-root` and the log and audit flags (`gosftpd --help`). The audit
log goes to stdout, so to `docker logs`. The health check of the image
connects to port 2022 unless `GOSFTPD_LISTEN` says otherwise: to listen on
another port, set `-e GOSFTPD_LISTEN=:2222` rather than `--listen`.

## Beyond atmoz mode

Atmoz mode serves what atmoz served. A configuration file adds per-user
access levels (upload only, read only), shared mounts, `allow_from`,
expiry, certificates, hooks, metrics and reloads without a restart. To
move, write one with `gosftpd config example`, add the users with
`gosftpd user add`, mount it as in the [Quickstart](quickstart.md), and
keep the `/home/<user>/<dir>` paths as mount paths.
