#!/usr/bin/env python3
"""Records docs/assets/gui-demo.gif: gosftpd-gui shares a folder, a partner
uploads to it with OpenSSH sftp in a terminal next to it, the uploads show
in the window's activity, and disabling the partner ends their connection.

Nothing is staged. The window is driven through its accessibility tree
(AT-SPI), as a screen reader drives it: the folder is chosen in the folder
dialog, the fields are filled in and the buttons pressed. The terminal
runs the real sftp, typed key by key. ffmpeg records the X display.

Run it as an ordinary user named alex (gosftpd refuses root), home
/home/alex, on Linux with Landlock, with:
- Xvfb, dbus-launch, at-spi2-core, python3-gi (Atspi 2.0), xterm, ffmpeg,
  OpenSSH sftp and ssh-keygen;
- gosftpd and gosftpd-gui built from this repository in ~/bin (make gui);
- an empty ~/Inbox and a 48 kB ~/report.pdf, no ~/.config/gosftpd-gui;
- the partner's key in ~/partner (ssh-keygen -t ed25519 -N "" -C partner
  -f ~/partner/id_ed25519), and in ~/.ssh/config, for the host name the
  window shows ("vm" here):

      Host vm
        IdentityFile ~/partner/id_ed25519
        IdentitiesOnly yes
        UserKnownHostsFile ~/partner/known_hosts
        StrictHostKeyChecking yes
        LogLevel ERROR

Then, with nothing else on port 2022:

    python3 record-gui-demo.py session        # Xvfb :95, D-Bus, AT-SPI
    . ~/gui-demo.env && /usr/bin/python3 -I record-gui-demo.py record demo.mkv
    ffmpeg -i demo.mkv -vf "fps=8,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" gui-demo.gif

The "record" step needs the system Python, whose gi module has Atspi.
"""
import ctypes
import os
import pty
import random
import select
import signal
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
ENV = os.path.join(HOME, "gui-demo.env")
W, H = 1500, 960
UPLOADED = os.path.join(HOME, "partner", ".uploaded")
KNOWN = os.path.join(HOME, "partner", "known_hosts")


def session():
    """Starts Xvfb :95 with a D-Bus session and the AT-SPI bus."""
    subprocess.Popen(["Xvfb", ":95", "-screen", "0", f"{W}x{H}x24", "-nolisten", "tcp"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    out = subprocess.run(["dbus-launch", "--sh-syntax"], capture_output=True, text=True, check=True).stdout
    with open(ENV, "w") as f:
        f.write(out + "export DISPLAY=:95\n")
    env = dict(os.environ, DISPLAY=":95")
    for line in out.splitlines():
        if line.startswith("DBUS_SESSION_BUS_ADDRESS="):
            env["DBUS_SESSION_BUS_ADDRESS"] = line.split("=", 1)[1].strip("';")
    subprocess.Popen(["/usr/libexec/at-spi-bus-launcher", "--launch-immediately"], env=env,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print("session ready: . " + ENV)


def typist():
    """The partner's terminal: real sftp, typed key by key."""
    random.seed(3)
    prompt = "\x1b[1;32m❯\x1b[0m "

    def out(s):
        sys.stdout.write(s)
        sys.stdout.flush()

    def typed(s, fd=None):
        for ch in s:
            if fd is None:
                out(ch)
            else:
                os.write(fd, ch.encode())
            time.sleep(random.uniform(0.05, 0.12))

    os.chdir(HOME)
    out("\x1b[2m# The partner's computer. They wait for the connection details.\x1b[0m\r\n" + prompt)
    while not os.path.exists(KNOWN):
        time.sleep(0.2)
    time.sleep(1.5)
    typed("sftp -P 2022 partner@vm")
    time.sleep(0.4)
    out("\r\n")
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("sftp", ["sftp", "-P", "2022", "partner@vm"])
    commands = ["put report.pdf", "put report.pdf", "ls -l"]
    buf = b""
    while True:
        r, _, _ = select.select([fd], [], [], 0.1)
        if not r:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out(data.decode(errors="replace"))
        buf = (buf + data)[-200:]
        if buf.rstrip().endswith(b"sftp>"):
            buf = b""
            if commands:
                time.sleep(0.8)
                typed(commands.pop(0), fd)
                time.sleep(0.3)
                os.write(fd, b"\r")
            else:
                open(UPLOADED, "w").close()
    os.waitpid(pid, 0)
    out("\r\n" + prompt)
    time.sleep(3600)


def x11():
    x = ctypes.CDLL("libX11.so.6")
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong),
                             ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)), ctypes.POINTER(ctypes.c_uint)]
    x.XFetchName.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p)]
    x.XMoveResizeWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint]
    x.XFlush.argtypes = [ctypes.c_void_p]
    return x


def place(title, x0, y0, w, h):
    """Moves the top-level window called title: there is no window manager."""
    x = x11()
    d = x.XOpenDisplay(None)
    r, p = ctypes.c_ulong(), ctypes.c_ulong()
    kids, n = ctypes.POINTER(ctypes.c_ulong)(), ctypes.c_uint()
    x.XQueryTree(d, x.XDefaultRootWindow(d), ctypes.byref(r), ctypes.byref(p), ctypes.byref(kids), ctypes.byref(n))
    for i in range(n.value):
        name = ctypes.c_char_p()
        if x.XFetchName(d, kids[i], ctypes.byref(name)) and name.value and name.value.decode() == title:
            x.XMoveResizeWindow(d, kids[i], x0, y0, w, h)
            x.XFlush(d)
            return


def record(out):
    import gi

    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi

    random.seed(5)

    def app():
        desk = Atspi.get_desktop(0)
        for i in range(desk.get_child_count()):
            a = desk.get_child_at_index(i)
            if a is not None and a.get_name() == "gosftpd-gui":
                return a
        return None

    def find(acc, role, name):
        try:
            if acc.get_role_name() == role and (name is None or acc.get_name() == name) and \
                    acc.get_state_set().contains(Atspi.StateType.SHOWING):
                return acc
        except Exception:  # noqa: BLE001
            return None
        for i in range(acc.get_child_count()):
            c = acc.get_child_at_index(i)
            f = find(c, role, name) if c is not None else None
            if f is not None:
                return f
        return None

    def wait(role, name, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            a = app()
            f = find(a, role, name) if a is not None else None
            if f is not None:
                return f
            time.sleep(0.1)
        raise SystemExit(f"timed out waiting for {role} {name!r}")

    def press(acc):
        acc.get_action_iface().do_action(0)

    def type_slowly(acc, text):
        et = acc.get_editable_text_iface()
        for i in range(1, len(text) + 1):
            et.set_text_contents(text[:i])
            time.sleep(random.uniform(0.06, 0.13))

    def scroll_to(fraction):
        bars = []

        def walk(acc):
            if acc.get_role_name() == "scroll bar" and acc.get_state_set().contains(Atspi.StateType.VERTICAL):
                v = acc.get_value_iface()
                if v is not None and v.get_maximum_value() > 0:
                    bars.append(v)
            for i in range(acc.get_child_count()):
                c = acc.get_child_at_index(i)
                if c is not None:
                    walk(c)

        walk(app())
        if bars:
            bar = max(bars, key=lambda v: v.get_maximum_value())  # the window's, not the table's
            start, target = bar.get_current_value(), bar.get_maximum_value() * fraction
            for i in range(1, 13):
                bar.set_current_value(start + (target - start) * i / 12)
                time.sleep(0.04)

    for f in (UPLOADED, KNOWN):
        if os.path.exists(f):
            os.remove(f)
    rec = None
    # Qt's own switch: the session's org.a11y.Status is not set without a
    # desktop.
    gui = subprocess.Popen([os.path.join(HOME, "bin", "gosftpd-gui"), "--gosftpd", os.path.join(HOME, "bin", "gosftpd")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=dict(os.environ, QT_LINUX_ACCESSIBILITY_ALWAYS_ON="1"))
    term = None
    try:
        wait("push button", "Add folder…")
        place("gosftpd: share a folder", 0, 0, 760, H)
        term = subprocess.Popen(["xterm", "-geometry", "84x56+768+0", "-fa", "DejaVu Sans Mono", "-fs", "11",
                                 "-bg", "#1e1e2e", "-fg", "#cdd6f4", "-T", "partner",
                                 "-e", sys.executable, os.path.abspath(__file__), "typist"])
        time.sleep(1.5)
        rec = subprocess.Popen(["ffmpeg", "-loglevel", "error", "-y", "-f", "x11grab", "-draw_mouse", "0",
                                "-framerate", "12", "-video_size", f"{W}x{H}", "-i", os.environ["DISPLAY"],
                                "-c:v", "libx264rgb", "-crf", "0", "-preset", "ultrafast", out], stdin=subprocess.PIPE)
        time.sleep(2.5)

        # A folder to share, chosen in the folder dialog.
        press(wait("push button", "Add folder…"))
        dlg = wait("dialog", None)
        time.sleep(1.2)
        type_slowly(find(dlg, "text", None), os.path.join(HOME, "Inbox"))
        time.sleep(0.6)
        press(find(dlg, "push button", "Choose"))
        time.sleep(1.5)

        # The person who may upload, with their public key.
        type_slowly(wait("text", "Name"), "partner")
        time.sleep(0.5)
        press(wait("radio button", "Public key"))
        time.sleep(0.6)
        with open(os.path.join(HOME, "partner", "id_ed25519.pub")) as f:
            wait("text", "Public key").get_editable_text_iface().set_text_contents(f.read().strip())
        time.sleep(1.5)
        press(wait("push button", "Start sharing"))
        known = wait("text", "known_hosts line")
        time.sleep(3.5)

        # The partner gets the details; the known_hosts line checks the
        # host key (StrictHostKeyChecking yes), and they upload.
        t = known.get_text_iface()
        with open(KNOWN, "w") as f:
            f.write(Atspi.Text.get_text(t, 0, Atspi.Text.get_character_count(t)) + "\n")
        end = time.time() + 90
        while not os.path.exists(UPLOADED) and time.time() < end:
            time.sleep(0.2)
        time.sleep(2.0)

        # The uploads, in the activity.
        scroll_to(1.0)
        time.sleep(4.5)

        # Disabling the partner ends their connection.
        scroll_to(0.0)
        time.sleep(1.5)
        press(wait("push button", "Disable partner"))
        time.sleep(4.5)
    finally:
        if rec is not None:
            rec.communicate(b"q", timeout=30)
        if term is not None:
            term.terminate()
        gui.send_signal(signal.SIGTERM)
        try:
            gui.wait(timeout=40)
        except subprocess.TimeoutExpired:
            gui.kill()


if __name__ == "__main__":
    {"session": lambda: session(), "typist": lambda: typist(), "record": lambda: record(sys.argv[2])}[sys.argv[1]]()
