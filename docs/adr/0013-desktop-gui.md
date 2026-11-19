# ADR 0013: Desktop GUI: a Qt front end that supervises gosftpd

- **Status:** accepted, 2026-11-12; revised with M5b-02's CLI additions
  (2026-11-13), where the implementation and its review found the text
  wrong or short. Amends:
  - ROADMAP §1.4 (the GUI paragraph);
  - ROADMAP §5: the M5b rows of the table, and M5b's items,
    Definition of Done, estimate and risks;
  - the post-1.0 backlog;
  - decision D22;
  - the README's v0.6 paragraph.

  When M5b-07 lands, it also amends ROADMAP §9.1 (the `gui/` CI job and
  its Dependabot directory), §9.3 (the GUI jobs of `release.yml`),
  §9.4 (the GUI's packages and macOS app: amd64 only, their build
  images, Qt dependencies and the path of their gosftpd) and §9.5 (the
  GUI files in `checksums.txt`), ADR 0012 (the GUI jobs; the
  Go version the release job sets up), docs/install.md (rebuilding the
  GUI packages), docs/security.md (what rebuilds byte for byte) and the
  release checklist's pin table.
- **Context:** ROADMAP M5b asks for `gosftpd-gui`, a desktop program for
  people who never open a terminal. In it they share a folder, add the
  people who may upload, start and stop sharing, copy the connection
  details and see who uploaded what.
  - It must not be a web UI (§1.4).
  - It must leave the server static, CGO-free and within its size budget
    (D21).
  - It must do nothing the CLI cannot.

  M5b-01 asks to choose the toolkit "after a small prototype of the same
  screen in each candidate". The criteria: native look and
  accessibility, CGO and cross-compilation, binary size, reproducible
  builds, packaging and signing per OS, license and maintenance. It also
  asks to settle the architecture, the two modes (share a folder; manage
  an installed server) and the security model.

  **The prototypes.** One screen, "Share a folder", was written in each of
  Fyne v2.8.2, Gio v0.10.3, Wails v3.1.0 and Qt 6.4.2 through miqt
  v0.15.0. The screen has:
  - a folder and its name, upload or read-only;
  - a person with a password or a public key;
  - Start and Stop;
  - the connection details with Copy buttons;
  - the latest uploads.

  Each prototype is its own module. All four use one shared Go package
  that runs the gosftpd v0.5.0 release binary as a child process.
  - They were built on Ubuntu 24.04 (gcc 13.3, Go 1.26.9). They ran as an
    ordinary user under Xvfb, with Mesa's software renderer, a D-Bus
    session and the AT-SPI accessibility bus.
  - Each was measured: CGO, cold and warm build time, stripped size,
    run-time libraries, and cross-builds for darwin/arm64 and
    windows/amd64. Each was built twice at different paths, the second
    time with a fresh cache and umask 002.
  - Each was run and checked:
    - screenshots, memory, the clipboard;
    - closing and killing the window;
    - an upload of the same file twice with OpenSSH `sftp` and a
      password;
    - the accessibility tree read over AT-SPI;
    - Tab through the controls.

  Nothing ran on macOS or Windows. What this ADR says about them comes
  from the toolkits' sources and documentation; "(read)" marks the
  statements about their behaviour, and
  [Not verified yet](#not-verified-yet) lists what a run must confirm.
  For Qt, whose web site this environment could not reach, it comes from
  what is known of its documentation, not checked against it.

  **The reviews.** Three rounds of review, each finding backed by a
  source, a command or a run of gosftpd v0.5.0:
  - the first (evidence; architecture and security; feasibility)
    confirmed 52 findings;
  - the second (coverage of the first; a fresh read) confirmed 35 more;
  - a final pass (coverage of the second; an implementer's read)
    confirmed 10 more.

  This version takes them in. The owner decided four questions on
  2026-11-12 ([Owner decisions](#owner-decisions)).

## Decision

### Two programs: the GUI supervises gosftpd

`gosftpd-gui` is a separate program. It runs the same `gosftpd` binary
that people use from the command line, with the options added below, as
a child process. It talks to it only through:
- its command line;
- its standard streams;
- signals;
- the audit log.

It never links the server's packages.

Running the server inside the GUI's process was ruled out:

- **Landlock covers the whole process.** On Linux `serve` restricts the
  process it runs in to the files and directories it needs, and a
  ruleset can only be narrowed later (ADR 0011). Inside the GUI it would
  also take away the GUI's own access: its settings, its fonts, the
  folder picker, the next folder the person wants to share. Turning
  Landlock off for GUI users would make the GUI weaker than the CLI.
- **`serve` starts its own binary again** to probe Landlock under a
  seccomp filter (`sandbox.ProbeMain`, ADR 0011). In the GUI's binary
  that would start a second GUI.
- **The chosen toolkit needs CGO** on every target, as Fyne and Gio do on
  Linux and macOS; only Wails' experimental `purego` backend avoids it
  (table below). The server must stay static and CGO-free.
- **Every action of the GUI is then a gosftpd command**, so "every action
  of the GUI has a CLI counterpart" holds by construction, and the logic
  is tested once, by the CLI's tests. What the GUI needs and the CLI
  lacks is added to the CLI first
  ([below](#what-the-gui-needs-from-gosftpd)). This replaces M5b-02's
  "logic it shares with the CLI in `internal/`".

**Where the code lives.**
- The GUI is its own Go module, `gui/` (module path
  `github.com/o-kolomoiets/go-sftp-server/gui`). Its packages are under
  `gui/internal/` (principle 11), and its command is
  `gui/cmd/gosftpd-gui`.
- The server's `go.mod` and `go.sum` never see the toolkit, and
  `go test ./...` at the root does not build it.
- The module does not import the server's `internal/` packages, although
  Go would allow it: the CLI is the interface.
- The GUI's toolkit code is one package. The supervisor and the gosftpd
  calls are toolkit-free.
- The module gets its own CI job, which `ci-ok` requires. The job uses
  the Qt development packages of a pinned image and runs vet,
  golangci-lint, govulncheck and the tests.
- It also gets its own Dependabot directory and `make` targets.
- Its build caches (about 1.1 GB per OS) share the repository's 10 GB
  Actions cache with the server's.

**Which gosftpd.** Release builds use only the gosftpd shipped with the
GUI, never one found in `PATH`:
- in the macOS app, `Contents/MacOS/gosftpd`;
- in the Linux packages, `/usr/libexec/gosftpd-gui/gosftpd`
  (`/usr/lib/gosftpd-gui/gosftpd` on Arch). It is built like the server
  package's `/usr/bin/gosftpd`, byte for byte, but carried by the GUI
  package itself.

So one download installs the GUI, without the server package's system
user, unit and `/etc/gosftpd`. Before each `serve` the GUI runs `gosftpd
version --json` and refuses a version other than its own. The check runs
every time because a package upgrade can replace the file under a
running GUI, and the message names the version it found. A development
build may take `--gosftpd PATH`.

### What the GUI needs from gosftpd

Additions to four commands, CGO-free and without a new dependency. Like
any CLI change, each comes with tests in `internal/cli`. Under D21 the
server grows by a few kilobytes.

- **`serve --print-details`.** One JSON line on stdout with the
  connection details. It is printed where `--ephemeral` prints its line:
  after the sandbox step, when serving starts.
  - Fields shared with `--ephemeral`'s line keep their names: `host`,
    `port`, `host_key_fingerprint`, `known_hosts`, `pid`, `version`. They
    describe the first listener and the first host key, as the banner's
    `connect:` line does.
  - Added fields:
    - `listen`: every address;
    - `host_keys`: an array of `{type, fingerprint}`;
    - `addresses`: the addresses of the interfaces that another machine
      can connect to: neither loopback nor link-local.
  - For an unspecified listen address such as `:2022`, `host` is this
    machine's name, as in the banner. `--ephemeral` says `127.0.0.1`,
    which is no use to a person on another machine. `known_hosts` then
    names the host and every address (`[vm]:2022,[192.0.2.10]:2022
    ssh-ed25519 ...`), so the line works whichever one the person types.
  - A start that fails after the command line is parsed prints one JSON
    line instead, with the exit status it has today: `{"error": TEXT,
    "kind": "listen" | "config" | "sandbox" | "other", "address":
    ADDR}`. The GUI tells a port in use from other failures by `kind`,
    not by wording. An argument gosftpd cannot parse ends it with exit
    status 2 and no line; when stdout ends without a line, the GUI shows
    stderr.
  - With `--print-details` the banner is not printed, so while it serves
    every line on stderr is a JSON log line (with `--log-format json`). A
    start that fails also writes its error as text (`Error: ...`), after
    the JSON line on stdout, which is the one to read.
  - `audit.output = "stdout"`, set or by default, is refused at start and
    fails a reload, as `--audit-output stdout` is with `--ephemeral`; so
    is an audit path that is stdout's file, such as `/dev/stdout`.

  The prototypes parsed the human banner on stderr instead. That works,
  but any rewording of the banner would break the GUI.
- **`serve --stop-on-stdin-eof`.** `serve` stops, as on SIGTERM, when its
  stdin reaches end of file. It refuses to start unless stdin is a pipe
  or a socket, and discards what is written to it. The GUI holds the
  write end. When the GUI exits for any reason, even SIGKILL or a crash,
  the kernel closes it and the server stops.
  - With this flag, as with `--ephemeral`, `serve` catches SIGPIPE and
    never stops catching it. It is caught, not ignored: an ignored
    SIGPIPE would be inherited by the processes gosftpd starts (the
    Landlock probe, exec hooks).
  - Without that, the stop would not happen. When the GUI dies, the
    server's stdout and stderr lose their reader, and its next write to
    stderr kills it. A review reproduced this with v0.5.0: with stderr's
    reader killed, a SIGTERM made gosftpd exit with status 141 four
    milliseconds later, with no drain and no `server.stop`. Caught,
    SIGPIPE turns those writes into EPIPE errors, the stop drains as on
    SIGTERM, and `server.stop` reaches the audit log, which is a file.
  - In the Fyne, Gio and Qt prototypes a GUI killed abruptly (XKillClient,
    or SIGKILL for Qt) left gosftpd running and sharing, unseen. Wails was
    not killed, but it uses the same supervisor.
  - Linux's `Pdeathsig` would cover only Linux, and it fires when the
    thread that started the child exits, not the process. macOS has no
    equivalent. A pipe works on Linux, macOS and later Windows.
- **`init` writes the GUI's configuration.** The GUI owns its
  configuration directory, the state directory. It writes the main file
  only through `gosftpd init --force` and the users only through `gosftpd
  user`; it never writes or parses TOML itself. `init` gains:
  - `--state-dir DIR`, as in `serve`: where the host key is generated.
    Today `init` always uses `<user config dir>/gosftpd`.
  - `--listen` and `--on-conflict`.
  - `--audit-output FILE`. It creates FILE's directory (mode 0700) when
    it is missing, as `init` creates `users.d/`. `serve` and `config
    validate --check-fs` refuse an audit file whose directory does not
    exist.
  - `--read-only FOLDER` (repeatable): the folder FOLDER of a `--dir` is
    read-only. A `:ro` suffix on the path would change the meaning of
    paths that contain `:`, which are valid.
  - `--password-logins`, which writes `auth.methods = ["publickey",
    "password"]`. gosftpd allows only public keys by default, so in every
    prototype the first share with a password failed: `user add --write`
    refused the user because it "could not log in".
  - `--disconnect-removed-users`, which writes
    `reload.disconnect_removed_users = true`. Disabling or removing a
    person then ends their open connections at the reload.
  - `--no-user`, so that `init` adds no user of its own. With it, at
    least one `--dir` is required (without one, `init` would share
    `./share` in the GUI's working directory), and a `--dir` whose part
    before `=` is not a valid folder name is refused.
    Today `init` reads such a value as a path, so `Фото=/x` shares a
    directory named `Фото=/x`.
  - `--no-create`: the folders get `create = false`. A folder the person
    later moves or renames is then an error at the next start ("the
    folder X was moved or deleted"). Today an empty folder would be
    created again at the old path.
  - With `--force`, `init` checks the new file together with its
    includes, as `config validate --check-fs` does, and refuses to write
    an invalid one. It loads or generates the host key, then replaces
    the file through a temporary file and a rename, as `user add --write`
    does; today it truncates the file in place. So exit status 2 always
    leaves the old file as it was. `init --force` keeps `users.d/` and
    the host key.
    - The check does not cover files that do not exist yet: the audit
      log, and Landlock's view of a file it has not seen. In the state
      directory, which the GUI owns, neither can fail.
- **`user`.**
  - `user set PERSON --access FOLDER=PERMISSIONS...` replaces the
    person's whole access in `users.d/PERSON.toml` with the folders
    given; `--no-access` leaves them none, which validation accepts with
    its warning ("the user can log in but sees nothing").
    - It checks the whole configuration with the change, as `user add
      --write` does (without the file checks of `--check-fs`).
    - It writes through a temporary file and a rename, as `disable`
      does, in the included file that defines the person.
    - Without `--force` it refuses a change that leaves the person unable
      to log in when they could before, and a password they cannot use.
      A change of access alone, for a person who could not log in
      before, is written with the warnings.
    - Today no command changes access. Removing a person and adding them
      again would need their password or key.
    - Before the GUI removes a folder, it removes the folder from
      everyone's access with this command. A grant for a missing folder
      makes the configuration invalid.
  - `user add` and `user set` gain `--password-stdin`: the first line of
    stdin, hashed as `hash-password` does. The GUI then passes neither
    the password nor its hash as an argument (see the security model).
  - `user list --json`: the same information as the table, one object
    per person (`name`, `access`, `keys`, `password`, `expires`,
    `status` and the `_off` flags), for the People screen.
- **`config show --json`.** The part of the effective configuration the
  GUI reads, as JSON, with the names of the keys: `file`,
  `server.listen`, `server.host_keys`, `auth.methods`,
  `defaults.on_conflict`, the `mounts` (path, `read_only`, `create`,
  `on_conflict`), `audit.output` and `reload.disconnect_removed_users`.
  No user, hook or secret is in it. The Folders screen reads it, and the
  GUI builds the next `init --force` from it, so `config.toml` stays the
  only record of the GUI's settings.
  - `init` has no per-folder `on_conflict` and only an all-or-nothing
    `--no-create`. A folder whose `on_conflict` or `create` differs from
    the others, by a hand edit, would be reset by the next `init
    --force`; the GUI says so before it rebuilds.

### The state directory

The state directory is `<user config dir>/gosftpd-gui` (on Linux
`~/.config/gosftpd-gui`, on macOS `~/Library/Application
Support/gosftpd-gui`), mode 0700. The GUI creates it before the first
`init`, which does not create the directory of `--out`. It holds only
what gosftpd names:
- `config.toml`;
- `users.d/`;
- the host key and its `.pub`;
- `audit/audit.jsonl`, in a directory of its own.

gosftpd then treats both directories as dedicated and gives no Landlock
warning. A review ran v0.5.0 on two layouts:
- with the audit log next to `config.toml` and a lock file in the
  directory, it gave three warnings on every start;
- with this layout, under umask 002, it gave none.

The GUI keeps its own files elsewhere:
- its preferences in `<user config dir>/gosftpd-gui.conf`, outside the
  state directory;
- its lock file in the per-user runtime directory (`$XDG_RUNTIME_DIR` on
  Linux, the per-user temporary directory on macOS).

gosftpd's permission checks (StrictModes) look at files, not at the
directory, and accept this layout.

### Lifecycle

Every command below runs with `--config STATE/config.toml`; `init` runs
with `--out STATE/config.toml --state-dir STATE`. The GUI removes the
`GOSFTPD_*` variables and `NOTIFY_SOCKET` from the child's environment.
Otherwise the environment could:
- change where the server listens (`GOSFTPD_LISTEN`);
- change what the GUI parses;
- send READY=1 to a systemd unit that started the GUI.

| The person | The GUI runs |
|---|---|
| shares a folder for the first time | `init --force --no-user --no-create --disconnect-removed-users --dir FOLDER=PATH [--read-only FOLDER] --listen :2022 --audit-output STATE/audit/audit.jsonl [--password-logins]` |
| adds a person with a password, or gives a password to a person who has none | if nobody has a password yet, `init --force ... --password-logins` with the current settings; then `user add PERSON --password-stdin --access FOLDER=upload\|read --write`, or `user set PERSON --password-stdin` |
| adds a person with a public key | `user add PERSON --key KEY --access FOLDER=... --write` |
| changes what a person may do | `user set PERSON --access ...`. A person with exactly one folder sees it as `/` (`flatten`, the default), so going to or from one folder changes their paths (`/report.pdf` becomes `/Inbox/report.pdf`); the GUI says so before it applies the change. |
| disables or enables a person | `user disable\|enable PERSON`. Password logins stay on while anyone has a password, enabled or not, so an enabled person can always log in. |
| removes a person | `user remove PERSON`; when nobody with a password is left, `init --force` without `--password-logins` |
| adds or removes a folder, or changes read-only | `user set` for the people who lose the folder, then `init --force` with the new folders. The GUI never removes the last folder: a configuration needs one. |
| presses Start sharing | `serve --print-details --stop-on-stdin-eof --log-format json`, stdin a pipe |
| changes anything while sharing | the commands above, then SIGHUP (ADR 0005) |
| presses Stop, or closes the window | SIGTERM; see below |

- **Reloads.** The GUI sends one SIGHUP at a time and waits for its
  `server.reload` event in the audit log (`result`, `reason`,
  `restart_required`) before sending the next: two quick signals can give
  one reload.
  - A failure's text comes from the next error line of the JSON
    operational log. The audit event carries none, since it never names
    host paths.
  - On a failure gosftpd keeps the running configuration, and the GUI
    says so in plain words.
- **Open connections keep their rights.** A reload does not take a folder
  or a right from a connection that is already open (ADR 0005).
  - Disabling or removing a person ends their connections at the reload,
    through `disconnect_removed_users`.
  - After `user set` narrows someone's access, or a folder is removed,
    the GUI names the people connected and says that they keep the old
    access until they disconnect. It offers the same restart as below.
- **Restarts.** The GUI restarts gosftpd only for the keys a reload lists
  in `restart_required`, or when the person asks.
  - On Linux, under Landlock, a new folder and upload rights on a
    read-only folder are among those keys (ADR 0011). On macOS, and on
    Linux without Landlock, a reload applies them.
  - A restart is a SIGTERM, and a new `serve` once the old gosftpd has
    exited. On SIGTERM gosftpd stops accepting and waits up to
    `shutdown_timeout` (30 s by default) for every connection to end,
    then closes the rest. An upload that takes longer is cut. Until it
    exits, the old process still writes `session.end` and `server.stop`
    to the audit log, whose events carry no pid. A second server on the
    same port and log would mix its events with the new one's; a review
    reproduced this with v0.5.0.
  - So the GUI restarts only when no session is open: a `session.start`
    without its `session.end`. If the person asks to restart at once, the
    GUI names the people connected and says that their transfers may be
    cut.
  - M5b-04's "never by a restart that drops uploads" becomes: never
    without the person's say while someone is connected.
- **Stop and closing the window (Q3).** Closing the window stops
  sharing. If someone is connected, the GUI first asks and names them.
  - Stop sends SIGTERM. The window says "Stopping: waiting up to 30 s for
    partner to disconnect" and offers "Stop now", which sends the second
    SIGTERM that ends gosftpd at once.
  - "Stop now", like any SIGTERM after end of file on stdin, writes
    neither `session.end` nor `server.stop`. So the GUI clears its list
    of connected people when the child exits, and counts only sessions
    after the last `server.start`.
  - The GUI quits when the child has exited.
  - There is no tray icon and no background mode in v0.6.0.
- **Activity.** The GUI follows the audit log (JSON lines):
  - `session.start` and `session.end` give who is connected;
  - the `fs.*` events give the transfers. They are written when a file is
    closed, so the list shows finished transfers, not running ones;
  - `server.start`, `server.stop` and `server.reload` give the state;
  - `server.start`'s `landlock` field gives the sandbox state.

  Known warnings of the operational log, such as a disk almost full, get
  a plain-words text; unknown ones are shown as gosftpd wrote them.
- **Clearing the view.** "Clear activity" hides the entries shown so far.
  The GUI keeps the audit log's size at that moment in its preferences
  and shows only what follows. It never changes the audit log, which is
  the record of who uploaded what (D20).
  - `docs/gui.md` says how to make the log smaller: `copytruncate`, or
    delete it while not sharing.
  - gosftpd opens the log with `O_APPEND`, so `copytruncate` leaves no
    hole. In its own directory, rotation by rename works too
    (docs/audit-log.md).
  - When the file is shorter than the size the GUI kept (truncated,
    deleted or rotated), the GUI shows it from the start.
- **One GUI per user, one server per state directory.** The lock file
  makes a second start bring up a message, not a second server on the
  same state directory and port.
  - The GUI keeps the running gosftpd's pid, from `--print-details`, next
    to its lock file. A GUI started after a killed one finds that pid. If
    that process is still the gosftpd of this state directory, still
    draining, the GUI says that the previous server is stopping and waits
    for it to exit before it serves.
  - A port that another program holds is reported (`kind: "listen"`)
    with the address and a field for another port.
- **`--start-sharing`.** Starting the GUI with `--start-sharing` starts
  sharing at launch, as the button does. `docs/gui.md` documents it, and
  the macOS smoke test uses it.

### Security model

- **No listener of its own.** The GUI opens no network socket and
  registers no URL handler. The only listener is gosftpd's SFTP port.
- **Other programs reach it only through the accessibility tree and the
  clipboard.**
  - The tree is on the session's AT-SPI bus (Linux) or NSAccessibility
    (macOS). Processes of the same user can read and operate it, which
    is what screen readers and the end-to-end test do. That is no new
    boundary: the same user can run gosftpd directly.
  - A generated password is removed from the window when its dialog
    closes.
  - The clipboard holds only what the person copies (see Secrets).
- **Qt.**
  - The GUI links Qt Core, Gui and Widgets. Gui brings Qt DBus on Linux
    for the accessibility bridge.
  - It links no Qt Network, WebEngine or QML.
  - It accepts only the `xcb`, `wayland` and `cocoa` platform plugins and
    ignores other `QT_QPA_PLATFORM` values. Qt's `vnc` plugin, for
    example, opens a network listener.
- **Never root.** The GUI refuses to start as root, as gosftpd does. It
  and the gosftpd it starts run as the desktop user.
- **The server is confined where the system allows it.**
  - On Linux gosftpd applies Landlock where the kernel supports it.
    `auto` serves without Landlock on a kernel without it, and ABI 2
    (Debian 12) does not restrict truncation by path (ADR 0011). The GUI
    shows the state from `server.start`.
  - On macOS gosftpd runs unconfined, as `gosftpd serve` does there. Its
    isolation is `os.Root`, as on every platform.
  - The GUI itself is not sandboxed: it needs the folder picker and the
    person's files.
- **Secrets.**
  - A password never appears in arguments or the environment, and neither
    does its hash. On Linux `/proc/PID/cmdline` is readable by every local
    user, and an argon2id hash invites offline guessing. The GUI passes
    the password to `user add --password-stdin` through a pipe.
  - `--password-stdin` reads one line, so the GUI refuses passwords with
    CR, LF or other control characters.
  - Only the argon2id hash is stored.
  - A generated password is shown once to copy and is not kept: 16
    URL-safe characters from `crypto/rand`, 96 bits. Putting it on the
    clipboard is the person's choice, and the GUI says that other
    programs can read the clipboard.
  - People are added with public keys only, never private keys.
  - gosftpd generates the host key (mode 0600) in the state directory.
- **Defaults no weaker than the CLI's.**
  - The listen address is `:2022`, as with `serve --dir`: all interfaces,
    which receiving from another machine needs.
  - `on_conflict = "rename"`, the default.
  - Password logins only while a person with a password exists, enabled
    or disabled.
  - The same validation and the same error texts as the CLI.
  - The fingerprint and the `known_hosts` line, to send to the person.

### Toolkit: Qt 6 Widgets through miqt (Q1)

The GUI is written with Qt 6 Widgets through miqt
(`github.com/mappu/miqt/qt6`, MIT), the maintained Go binding of Qt 5 and
6. The prototype is 438 lines of Go, and miqt is its only Go dependency.

#### What the prototypes measured

All four were built on Linux amd64 (4 CPUs, 15 GB) with `-trimpath
-ldflags="-s -w"`. Other prototypes were often building at the same
time, so the cold times are ranges, measured at load averages from 0.3
to 10.

| | Fyne v2.8.2 | Gio v0.10.3 | Wails v3.1.0 | Qt 6.4.2 via miqt v0.15.0 |
|---|---|---|---|---|
| Release, cadence | 2026-10-07; a minor every 6–9 months, patches every 1–3 | 2026-09-28; pre-1.0, tags "for reference only", 8-month gaps | 2026-11-01, six days after v3.0.0; weekly minors announced, none since as of 2026-11-12 | miqt 2026-10-09, a minor every 3–5 months, pre-1.0 |
| License | BSD-3 (Apache-2.0 and MIT deps; OFL fonts) | MIT or Unlicense (Apache-2.0 icons) | MIT; GTK and WebKitGTK LGPL (system) | miqt MIT; Qt LGPLv3 |
| CGO | every target | Linux, macOS | Linux, macOS (an experimental `purego` backend avoids it) | every target (C++17) |
| Stripped binary | 24.5 MB | 9.2 MB | 9.7 MB | 30.3 MB (21.0 MB with the size flags below) |
| Also needs | libGL, X11 and Wayland client libraries | EGL, GLES, X11, Wayland and xkbcommon libraries | GTK 4 and WebKitGTK 6.0: 131 libraries, WebKitGTK alone 90 MB | Qt 6 Core, Gui, Widgets, DBus (21 MB) and plugins (1.1 MB): 47 libraries, 65 with the xcb plugin, ICU 74 (36 MB) among them |
| Cold, warm build | 187–204 s, 1.2 s | 20–33 s, 0.8 s | 45–50 s, 1.0 s | 353–466 s (295 s with the size flags), 2.9 s; the compiler peaks at 6.9–7.0 GiB |
| Two builds identical | yes | yes | yes | yes |
| Memory while sharing (Xvfb; Qt without GL, the others on Mesa llvmpipe) | 173 MB | 197 MB | about 620 MB in 3 processes (375 MB with the cairo renderer) | 56 MB |
| Screen readers on Linux (AT-SPI) | the app is absent: 0 nodes | the app is absent: 0 nodes | 79 nodes with roles and names | 70 nodes with roles and names |
| Tab reaches every enabled control | yes (traced idle only) | yes (traced while sharing only) | yes, after a fix in the page's JS | yes, after a fix (table) |
| VoiceOver on macOS (read) | behind a build tag; buttons and labels only | none | WKWebView's web accessibility | Qt's NSAccessibility bridge |
| Look on Linux | Fyne's own theme, its own file dialog | Material Design; the folder picker needs xdg-desktop-portal | a web form; the GTK file chooser | Fusion under Xvfb; Qt's own file dialog |
| macOS build from Linux | no (needs an Apple SDK) | no | only with `purego` | no |
| Lines of Go (and web) for the screen | 490 | 503 | 527 (257 Go, 270 HTML, CSS and JS) | 438 |

In all four:
- both uploads appeared in the list within the 2-second refresh;
- Copy put the exact values on the X11 clipboard. All six buttons were
  checked in Gio and Qt; the sftp command, the fingerprint and the
  `known_hosts` line in Fyne and Wails;
- closing the window stopped gosftpd.

#### Why Qt

- **Accessibility is the deciding criterion.** The GUI exists for people
  who do not use a terminal, and among them are people who use a screen
  reader.
  - On Linux, Fyne and Gio are not in the accessibility tree at all.
  - Fyne 2.8 has an opt-in bridge for macOS and Windows that covers
    buttons and labels, not fields, checkboxes or tables.
  - Gio's semantic tree reaches only Android.
  - Making either accessible would mean writing platform bridges
    ourselves.
- **Qt's tree had every control, with the right states:** disabled,
  read-only, checked, password text hidden. Read-only fields are also
  reported editable, a Qt quirk.
  - Fields in plain form rows took their names from their labels, colon
    included ("User name:").
  - The Folder field (its row holds a layout), the password and key
    fields and the six Copy buttons needed an explicit `accessibleName`.
  - One Qt default had to change: a table's Tab navigation, which kept
    the keyboard inside the table.
  - Wails' tree was as good, through WebKit, but only with hand-written
    HTML semantics and a JavaScript fix for a keyboard trap in WebKitGTK
    6.
- **The smallest running cost.** 56 MB, against about 620 MB for Wails in
  three processes (the GUI, WebKit's web process and its network
  process).
- **No browser engine.** Wails puts an HTML and JavaScript page in front
  of Go methods that configure and start a server.
  - Its v3.0.0 release notes list an advisory (GHSA-2p5f-2gx8-mh8m) as
    only partly fixed.
  - A WebKit sandbox failure aborts the whole GUI. It happened once in
    the prototype, from an `XDG_DATA_DIRS` entry the user could not read,
    leaked from root's environment by the test harness.
  - For a security tool the smaller surface counts.
- **Maturity.** Wails v3 had been generally available for two weeks,
  under an announced weekly minor-release policy and an undefined
  stability promise. Qt is mature, its API is stable within Qt 6, and
  miqt's generated binding follows it one to one.
- **Native enough.**
  - On macOS: the macOS style and native dialogs (read).
  - On KDE: Breeze (not tried).
  - Under Xvfb without a platform theme it used Fusion, which GNOME users
    will likely see: a plain classic desktop look, not Adwaita.

#### Costs, and how they are carried

- **miqt is young:** v0.x, a small team, breaking changes allowed.
  - It is pinned and updated deliberately.
  - Its bindings are generated (MIT, with the generator in the module),
    so the project could regenerate them if miqt stopped.
  - Moving to another binding or toolkit would rewrite the one toolkit
    package, about 450 lines, not the design.
- **Heavy first builds.** A cold build takes 5–8 minutes. Compiling the
  Go side of `miqt/qt6` peaked at 6.9–7.0 GiB of memory:

  | Setting | Peak | Binary |
  |---|---|---|
  | none | 6.9–7.0 GiB | as measured |
  | `GOMAXPROCS=3`, as on GitHub's 3-CPU arm64 runner | 7.0 GiB | the same |
  | `GOGC=50` | 6.2 GiB | the same |
  | `-gcflags=github.com/mappu/miqt/qt6=-c=1` | 5.9 GiB | the flag is recorded in it |
  | both | 5.6 GiB | the flag is recorded in it |

  CI keeps a build cache. The release does not (see
  [Packaging](#packaging-and-signing)).
- **Size.** The binary is 30 MB.
  - Built with `CGO_CFLAGS` and `CGO_CXXFLAGS` set to `-Os
    -ffunction-sections -fdata-sections` and
    `CGO_LDFLAGS=-Wl,--gc-sections`, it is 21 MB. The release uses those
    flags.
  - The macOS app adds an estimated 20 MB of Qt frameworks. That figure
    comes from the Linux sizes, for one architecture; it was not
    measured.
- **Qt versions.**
  - The Linux packages use the distribution's Qt. On Debian 12 that is
    6.4.2, which is out of upstream support; fixes come from the
    distributions.
  - For open-source users an LTS branch gets public patch releases only
    up to x.y.3. So the macOS app follows the current Qt minor, not an
    LTS, and each Qt update may raise the minimum macOS.
  - Qt's security advisories are followed by hand: govulncheck, OSV and
    Dependabot do not see Qt. A Qt fix that matters for the frameworks
    bundled in the app means a patch release, as a Go advisory does
    (principle 8).
- **LGPLv3.** Qt is linked dynamically everywhere, which is miqt's
  default, and the GUI does not modify Qt.
  - **Linux:** the binary contains code from Qt's headers (inline
    functions and templates), so each package installs, in
    `/usr/share/doc/gosftpd-gui/`:
    - a notice that the GUI uses Qt under the LGPLv3;
    - the GPLv3 and LGPLv3 texts;
    - the project's LICENSE;
    - a `THIRD_PARTY_LICENSES` for the gui module (miqt, Go), generated
      by go-licenses as the server's is;
    - gosftpd's own `THIRD_PARTY_LICENSES`, as
      `THIRD_PARTY_LICENSES.gosftpd`, since the package carries gosftpd.
  - **macOS:** the app carries the same files, plus the third-party
    notices of the Qt code it bundles: PCRE2, HarfBuzz, libpng,
    libjpeg-turbo, zlib, double-conversion, md4c and the others in
    qtbase's `qt_attribution.json`.
    - Only qtbase is installed on the build machine, so every bundled
      framework and plugin comes from qtbase.
    - The release attaches qtbase's source archive for the bundled
      version (GPLv3 §6(d), which LGPLv3 builds on).
    - A person may replace the frameworks in the app; on macOS that needs
      an ad-hoc signature afterwards.
  - The project stays Apache-2.0 (D1), which may be combined with LGPLv3
    libraries.

### Look and behaviour

- One window. "Share a folder" is the first-run screen; "People and
  folders" and "Activity" come next (M5b-03 to M5b-05).
- Qt's own layouts and widgets: forms with labels and group boxes, and a
  table for the transfers with Tab navigation turned off inside it.
- Every input control, and every button whose text repeats ("Copy"),
  gets an explicit `accessibleName`: the label's text without its colon,
  or "Copy host", "Copy port" and so on.
- Status and error changes are sent as accessibility events, so that a
  screen reader announces them. Without an event, a changed label is not
  spoken.
- Errors from gosftpd are shown as it wrote them, in the status line and
  in a details pane, never hidden behind a generic message.
- The folder picker is `QFileDialog::getExistingDirectory`: NSOpenPanel on
  macOS (read), Qt's dialog on Linux, or the desktop portal's where one is
  configured.
- Linux sessions: X11 and Wayland through Qt's platform plugins. Only X11
  was tried.

### Packaging and signing

- **One Go for a release.** `generate` gives the Go version it resolved
  (`go env GOVERSION`) as a job output. The GUI jobs and the `release` job
  set up exactly that version (`check-latest: false`), so every gosftpd
  in a release is built with one Go. That holds also when the `release`
  job is re-run alone.
- **The GUI jobs** in `release.yml` follow the rules of `generate`
  (ADR 0012):
  - the release guard runs first;
  - `contents: read`, no `id-token`;
  - setup-go with `cache: false`, and no Actions cache restored. A
    poisoned cache must not be compiled into binaries the release signs,
    so their builds are cold.
- **Each GUI job builds:**
  - the GUI binary;
  - gosftpd, from a clean git checkout of the tag, with
    `.goreleaser.yaml`'s `env` (`CGO_ENABLED=0`), flags and ldflags for
    that target, the `-X` values rendered as GoReleaser renders them.
    The GUI jobs have a C++ compiler, so cgo would otherwise be on. Go
    records `vcs.revision`, `vcs.time` and `vcs.modified` in the binary,
    so the build needs the `.git` directory;
  - the packages or the app (below);
  - an SBOM of each GUI binary with syft (the version `release.yml`
    pins). The SBOM names the Go modules; Qt is named in the notices,
    not in the SBOM.

  It uploads them as an artifact.
- **The `release` job checks the GUI artifacts.**
  - It downloads each one into `$RUNNER_TEMP`, never into the checkout,
    and fails unless it holds only regular files with exactly the
    expected names, as `release-out.sh` does for `generate`'s artifact.
    Code that runs in a GUI job controls that job's upload step, so only
    the `release` job can check it.
  - After GoReleaser it takes gosftpd out of each GUI package and out of
    the app as they are shipped, and compares it with the same target's
    binary in `dist/`, byte for byte. It uses tools of the runner image:
    `dpkg-deb --fsys-tarfile` for the deb, `tar` for the Arch package,
    and `rpm2cpio` or 7-Zip for the rpm and the `.dmg`. A loose copy in
    the artifact would prove nothing about the packaged one, since the
    GUI job writes both.
  - GoReleaser lists the GUI files and their SBOMs with
    `checksum.extra_files` and uploads them with `release.extra_files`.
    A glob that matches nothing passes silently, so a release step fails
    unless `checksums.txt` names every expected GUI file.
  - The existing attestation step covers them through `checksums.txt`.
- **Linux.** deb, rpm and Arch packages `gosftpd-gui`, for amd64 only in
  v0.6.0. arm64 follows when someone asks for it, built on the
  `ubuntu-24.04-arm` runner in the arm64 variants of the same images.
  The server keeps its arm64 packages.
  - Each package has a `.desktop` file, an icon, the notices above and
    gosftpd at the path above.
  - The packages are made with nfpm, pinned, in the GUI jobs; GoReleaser
    makes no GUI package. Its configuration gains only the GUI entries
    of `checksum.extra_files` and `release.extra_files`.
    - Each entry is a wildcard pattern under a directory that only the
      `release` job sets, for example `{{ if isEnvSet "GUI_DIR" }}{{
      .Env.GUI_DIR }}/*{{ end }}`.
    - In GoReleaser v2.19.0 a literal path that does not exist, or `{{
      .Env.X }}` with X unset, fails the run, also with `--snapshot` or
      `--skip=publish`.
    - So a local run and `goreleaser-check` find no GUI files and pass,
      and docs/install.md's "Rebuild a release" still rebuilds and checks
      the server's 12 files. Its `sha256sum --check --ignore-missing`
      skips the GUI's lines.
  - The GUI binary for the deb and Arch packages is compiled in a Debian
    12 container (Qt 6.4.2, glibc 2.36). A binary compiled on Ubuntu
    24.04 needs glibc 2.35 (`hypotf@GLIBC_2.35`, from Qt's headers) and
    would not start on EL 9 (glibc 2.34).
  - The deb depends on `libqt6core6`, `libqt6gui6`, `libqt6widgets6`
    (6.4 or newer) and `qt6-qpa-plugins`. Debian lists the X11 plugin
    package only as a recommendation, so without this dependency the GUI
    would not start.
  - The rpm's GUI binary is compiled in EL 9's container against EL 9's
    own Qt 6; it then also runs on current Fedora. If EL 9's Qt is older
    than miqt needs, it is compiled on Fedora and EL 9 is left out.
    M5b-07 checks this first.
  - The images are pinned by digest, and their Qt packages by version
    from snapshot.debian.org and the EL 9 vault, so a rebuild can fetch
    them. Both are written once, in the script that `make gui-packages`
    runs.
    - That command builds the Linux GUI binaries, gosftpd and the
      packages in those images with `docker run`. The images install git,
      so the build has the `.git` directory.
    - The release's Linux GUI job runs it on the `ubuntu-24.04` runner,
      after the release guard, which needs the runner's `gh`.
    - The `reproducible` job runs it twice, cold, and docs/install.md
      documents it. So the release, the CI check and a person's rebuild
      all run the same command.
  - CI starts each package's GUI under Xvfb in the debian-12, debian-13,
    el9 and arch containers of `test/packages` and checks the
    accessibility tree.
  - Not in v0.6.0:
    - an AppImage, which would bundle Qt (about 22 MB, 58 MB with ICU)
      and its LGPL source duties;
    - a Flatpak, where the folder picker returns document-portal paths
      and gosftpd's Landlock inside bubblewrap is untested.
  - Installing a downloaded package without a terminal (Ubuntu's App
    Center, GNOME Software) is shown in `docs/gui.md`.
- **macOS.** `gosftpd-gui.app` for Apple silicon (arm64), in a `.dmg`,
  built on the `macos-15` runner.
  - Qt comes from the official universal binaries, through aqtinstall
    pinned by version and hash. Qt's framework builds ship no pkg-config
    files (read), so the job writes the `Qt6Core`, `Qt6Gui`, `Qt6Widgets`
    and `Qt6DBus` files that miqt needs, as miqt's own macOS build does.
  - The minimum macOS is the Qt release's (12 for Qt 6.8, 13 for 6.10;
    read), and at least Go's 12.0. `docs/gui.md` states it.
  - The compile runs with `GOGC=50` and `-c=1` for `miqt/qt6` (5.6 GiB on
    Linux). If the 3-CPU, 7 GB runner still does not fit, the job
    cross-compiles for arm64 on the `macos-15-intel` runner (4 CPUs, 14
    GB) with the universal Qt; the smoke test stays on arm64. GitHub's
    larger runners need an organization on a paid plan, so they are no
    option here.
  - Bundling, in this order:
    1. `macdeployqt` copies the frameworks and plugins, without
       `-codesign`;
    2. `lipo` thins them to arm64;
    3. each framework and plugin is ad-hoc signed (`codesign --force -s
       -`), inside out, since the install-name changes and `lipo` break
       their signatures;
    4. gosftpd is copied into `Contents/MacOS`;
    5. the app is signed with `codesign -s -`, without `--deep`, which
       seals gosftpd without re-signing it, so it keeps the signature the
       Go linker gave it and its bytes;
    6. `hdiutil` makes the `.dmg` (`-fs HFS+ -format UDZO`, which can be
       read on Linux). It is not reproducible, and docs/security.md says
       so.
  - It is ad-hoc signed and not notarized: there is no Apple Developer ID
    (Q2). macOS therefore blocks the first start of a downloaded copy.
    The person allows it once in System Settings, Privacy & Security,
    Open Anyway (read). `docs/gui.md` shows the steps with screenshots.
  - Intel Macs are not built for v0.6.0.
- **Windows.** After M3b.
  - The supervisor's process handling (process groups, signals) is
    Unix-only today, and the prototypes did not build for Windows
    because of it.
  - Qt also needs a mingw g++ and a Windows Qt 6, so in practice a
    Windows runner.
  - A Windows code-signing certificate (D22) is decided with Windows.
- **Pins.** These join the release checklist's table of versions
  Dependabot does not update:
  - the macOS Qt version, and aqtinstall's version and hash;
  - the Linux build images and their Qt packages' versions, in the
    script `make gui-packages` runs;
  - nfpm.

  `TestChecklistPins` is extended to read that script too, and to find
  aqtinstall's and Qt's versions, the Qt packages' `=VERSION` and nfpm's
  version. miqt is in `gui/go.mod` and goes through Dependabot.

### Tests

- **The CLI additions:** unit tests in `internal/cli`, like every command.
  One test reproduces a killed GUI with a session open: it closes the
  write end of a `serve --stop-on-stdin-eof`'s stdin and the read ends
  of its stdout and stderr. It checks that gosftpd drains and writes
  `server.stop`.
- **The supervisor**, in `gui/`, against a fake `gosftpd` script:
  - the details line and the error line;
  - the reload results and the restart policy;
  - the stdin pipe, so that a killed GUI leaves no server;
  - no second `serve` while a previous one still runs;
  - the version check;
  - the environment it passes on.
- **End to end on Linux, in CI.** Xvfb, a D-Bus session and the AT-SPI
  bus, as in the prototypes.
  - The test finds the controls by their accessible names ("Folder",
    "User name", "Start sharing"), fills them and presses them.
  - It uploads with OpenSSH `sftp`, waits for the row in "Latest
    uploads" and reads it from the tree.
  - On each screen, idle and while sharing, it also walks the whole
    tree. It fails on any focusable control, button or field whose name
    is empty or ends with a colon.
  - So the test fails when any control loses its name. It replaces
    M5b-08's "the toolkit's test driver".
- **The packages** start under Xvfb in four distribution containers
  (above).
- **macOS, in CI.** The app is built and bundled, and a smoke test:
  - starts it with `--start-sharing` on a state directory prepared with
    gosftpd commands, sharing a folder outside Desktop, Documents and
    Downloads, since a hosted runner cannot answer a privacy prompt;
  - uploads with `sftp` and checks the audit log;
  - checks that the gosftpd inside the mounted `.dmg` has the sha256 of
    the gosftpd the job built.

  It does not drive the UI or look at the activity view. That needs the
  Accessibility permission for the test runner, which a hosted runner
  cannot be expected to grant (not verified).
- **The DoD run by hand** on a clean Linux desktop and a clean Mac covers
  the rest. On the Mac, the shared folder is in Documents.

### Owner decisions

On 2026-11-12 the owner decided:

- **Q1, the toolkit:** Qt 6 through miqt, as recommended. Wails v3 was
  the alternative put to the owner.
- **Q2, an Apple Developer ID:** not now. The macOS app is ad-hoc signed
  and not notarized, with the Open Anyway step above. The question
  returns before v1.0, or earlier if people ask for it. D22 records it.
- **Q3, closing the window:** it stops sharing, after asking if someone
  is connected. A tray icon and a background mode are not in v0.6.0.
- **Q4, managing an installed server** (packages, systemd, Docker): later
  than v0.6.0. It needs elevated rights (polkit, sudo or macOS
  authorization), editing `/etc/gosftpd` and `systemctl reload`: a
  security model of its own, and about twice the work.
  - M5b-06 leaves M5b and becomes row 15 of the post-1.0 backlog, to be
    planned after v0.6.0.
  - If it is planned before 1.0, it leaves that table for a milestone of
    its own.

### Definition of Done (amended)

On a clean Linux desktop and a clean Mac, a person who never used gosftpd
installs the GUI, shares a folder with one user and receives an upload
from OpenSSH `sftp` in under 5 minutes, without a terminal. On macOS this
includes the one-time Open Anyway step.

- Every action of the GUI has a CLI counterpart: it is a CLI command.
- Every control has an accessible name on Linux (the end-to-end test
  walks the whole tree).
- A killed GUI leaves no gosftpd running.
- The server binary stays CGO-free and within D21, changed only by the
  CLI additions above.
- v0.6.0 ships the GUI in `checksums.txt`, signed with cosign and with
  build provenance, as the server is. On macOS it is ad-hoc signed, not
  notarized (Q2).

### Estimate

| Part | pd |
|---|---|
| CLI additions (`serve`, `init`, `user`, `config show`) | 3–4 |
| The supervisor and three screens (share a folder, people and folders, activity) | 6–8 |
| Packaging and release: Linux packages in two images, the macOS app and `.dmg`, the release jobs and checks, notices, pins | 6–9 |
| Tests: the supervisor, the AT-SPI end-to-end test, the package and macOS smoke tests | 3–4 |
| `docs/gui.md` with screenshots, README, quickstart | 1–2 |
| **M5b** | **19–27** (was 15–25); with the 20% reserve 23–32 |

Dropping notarization (Q2) and managing an installed server (Q4)
removed work; the CLI additions, the two Linux build images and the
release checks added more.

### Not verified yet

- **Everything on macOS:**
  - the build, the look, VoiceOver;
  - `macdeployqt` with the official Qt, the bundling order and the
    frameworks' size;
  - the ad-hoc signatures, and whether gosftpd keeps its linker signature
    and its bytes in the app;
  - Gatekeeper's Open Anyway, also on a standard (non-administrator)
    account, and whether Gatekeeper blocks `Contents/MacOS/gosftpd`
    separately when the approved app starts it;
  - the firewall prompt for incoming connections;
  - the privacy prompt for files and folders, when gosftpd, the app's
    child, opens a shared folder in Desktop, Documents, Downloads,
    iCloud Drive or on an external disk: that it names the app, that a
    refusal reaches the GUI as gosftpd's error, and whether an ad-hoc
    signed app, whose identity is its code hash, keeps the permission
    after an update;
  - reading gosftpd out of the `.dmg` and the rpm on the `ubuntu-24.04`
    release runner without installing anything.
- **The build's memory on the `macos-15` arm64 runner** (7 GB), with
  `GOGC=50` and `-c=1`.
- **The Linux packages beyond Ubuntu 24.04:**
  - the Debian 12 build;
  - EL 9's Qt version, and the rpm built there;
  - the GUI on Debian 13, Fedora and Arch;
  - installing a local package without a terminal.
- **The release's size flags.** The `-Os` and `--gc-sections` build was
  built once and started. Its reproducibility, the upload and the
  accessibility tree were checked only on the default build.
- **Desktop sessions:** Wayland, GNOME and KDE (only Xvfb ran), and real
  GPUs (the memory figures are from Xvfb).
- **A screen reader's speech.** Orca was not run, so neither was the
  announcement of status and error changes; only the tree was read.

### Not in this ADR

- Managing an installed server (Q4).
- Windows (M3b).
- Linux arm64 GUI packages, until someone asks.
- A tray icon, start at login, notifications.
- Translations: the GUI is in English first, like the CLI (ADR 0006).

## Consequences

- The server stays a static, CGO-free binary; four commands gain
  options. Everything the GUI does can be done, scripted and tested from
  a terminal.
- The project gains a C++ toolchain, Qt and native runners for the GUI
  alone. The costs:
  - wall time on the free macOS runner, with cold builds in release
    jobs;
  - build caches in CI;
  - Qt advisories, followed by hand.
- A second module (`gui/`) to keep current: miqt, Qt through the
  distributions, and the pinned macOS Qt.
- The macOS app is not notarized until Q2 is revisited, and its first
  start takes an extra step.
- The accessibility tree becomes part of the tests, so a control without
  a name fails CI.

## Alternatives considered

- **The server inside the GUI's process.** Rejected: Landlock would
  confine the GUI too, `serve`'s self-exec probe would start a second
  GUI, and the server would need CGO.
- **The GUI in the server's module.** Rejected: the toolkit and its CGO
  dependencies would enter the server's `go.mod`, and `go build ./...`
  with `CGO_ENABLED=0` would fail.
- **The GUI writes the TOML itself.** Rejected: a second writer of the
  schema, and GUI actions without a CLI counterpart.
- **The GUI's packages made by GoReleaser.** Rejected: GoReleaser would
  need the GUI binaries for every run, also for a local "Rebuild a
  release", which has none.
- **Fyne.** Mature, permissive and easy to write. Rejected for
  accessibility (none on Linux, partial elsewhere) and a look of its own.
- **Gio.** Small binary and fast builds. Rejected for accessibility (none
  on desktops), pre-1.0 tags without support, and the Material look.
- **Wails v3.** Good accessibility and fast builds. Its `purego` build
  gave a 5 MB `.dmg`, made on Linux and never run on a Mac. Not chosen:
  - two weeks old, under a weekly release policy;
  - about 620 MB of memory;
  - a browser engine and a JavaScript bridge in front of the server's
    configuration;
  - GTK 4 with WebKitGTK 6 required on Linux.
- **A web UI.** A non-goal (§1.4).
- **Parsing the banner instead of `--print-details`.** Worked in the
  prototypes, but would tie the GUI to wording meant for people.
- **Linux's `Pdeathsig` instead of the stdin pipe.** Linux-only, and tied
  to the thread that started the child.
