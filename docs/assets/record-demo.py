#!/usr/bin/env python3
"""Records the real gosftpd session shown in docs/assets/demo.gif.

A tmux session with two panes (server, client) runs real commands; this
script types them key by key with human-like delays and records everything
the terminal shows, with timestamps, as an asciicast v2 file. Nothing is
staged: the output is what gosftpd, sftp and jq print.

Run it as an ordinary user (gosftpd refuses root) whose ~/.ssh holds an
ed25519 key in authorized_keys, with gosftpd, sftp, tmux and jq installed,
an empty ~/inbox, a 48 kB ~/report.pdf, no ~/.config/gosftpd (so the host
key is generated) and "StrictHostKeyChecking accept-new" plus "LogLevel
ERROR" for localhost in ~/.ssh/config. Then:

    python3 record-demo.py demo.cast
    agg --font-family "JetBrains Mono" --font-size 16 --theme dracula \
        --idle-time-limit 2 --last-frame-duration 5 demo.cast demo.gif

(agg: https://github.com/asciinema/agg, v1.5.0)
"""
import fcntl
import json
import os
import pty
import random
import select
import struct
import subprocess
import sys
import termios
import threading
import time

W, H = 110, 34
SOCK = "demo"
CONF = os.path.expanduser("~/.tmux.demo.conf")
PROMPT = r"\[\e[1;32m\]❯\[\e[0m\] "

random.seed(7)


def tmux(*args):
    subprocess.run(["tmux", "-L", SOCK, "-f", CONF, *args], check=True)


def setup():
    with open(CONF, "w") as f:
        f.write(
            "set -g status off\n"
            "set -g escape-time 0\n"
            'set -g default-terminal "xterm-256color"\n'
            "set -g pane-border-status top\n"
            'set -g pane-border-format "#[fg=colour245] #{pane_title} "\n'
            "set -g pane-border-style fg=colour239\n"
            "set -g pane-active-border-style fg=colour239\n"
            "set -g allow-rename off\n"
        )
    subprocess.run(["tmux", "-L", SOCK, "kill-server"], stderr=subprocess.DEVNULL)
    shell = f"env PS1='{PROMPT}' HISTFILE=/dev/null bash --norc --noprofile"
    tmux("new-session", "-d", "-s", "demo", "-x", str(W), "-y", str(H), "-c", os.path.expanduser("~"), shell)
    tmux("split-window", "-v", "-t", "demo:0", "-l", str(H - 12), "-c", os.path.expanduser("~"), shell)
    tmux("select-pane", "-t", "demo:0.0", "-T", "server")
    tmux("select-pane", "-t", "demo:0.1", "-T", "client")
    tmux("select-pane", "-t", "demo:0.1")
    for p in ("0.0", "0.1"):
        tmux("send-keys", "-t", f"demo:{p}", "clear", "Enter")


def record(out, stop):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("tmux", ["tmux", "-L", SOCK, "-f", CONF, "attach", "-t", "demo"])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", H, W, 0, 0))
    start = time.monotonic()
    events = []
    while not stop.is_set():
        r, _, _ = select.select([fd], [], [], 0.05)
        if fd in r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            events.append([round(time.monotonic() - start, 4), "o", data.decode("utf-8", "replace")])
    with open(out, "w") as f:
        f.write(json.dumps({"version": 2, "width": W, "height": H,
                            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}) + "\n")
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    os.kill(pid, 9)


def type_(pane, text, enter=True):
    for ch in text:
        tmux("send-keys", "-t", f"demo:{pane}", "-l", ch)
        d = random.uniform(0.035, 0.085)
        if ch == " ":
            d += 0.04
        time.sleep(d)
    if enter:
        time.sleep(0.25)
        tmux("send-keys", "-t", f"demo:{pane}", "Enter")


def main():
    out = sys.argv[1]
    setup()
    stop = threading.Event()
    t = threading.Thread(target=record, args=(out, stop))
    t.start()
    time.sleep(1.0)
    type_("0.0", "gosftpd serve --dir ./inbox --audit-output audit.jsonl")
    time.sleep(2.2)
    type_("0.1", "sftp -P 2022 alex@localhost")
    time.sleep(1.2)
    for cmd, pause in [
        ("put report.pdf", 1.0),
        ("put report.pdf", 1.2),
        ("ls -l", 2.2),
        ("cd ..", 0.5),
        ("pwd", 1.2),
        ("ls /etc", 1.8),
        ("bye", 0.8),
    ]:
        type_("0.1", cmd)
        time.sleep(pause)
    type_("0.1", "grep renamed audit.jsonl | jq '{event, user, path, final_path, conflict, bytes}'")
    time.sleep(4.5)
    stop.set()
    t.join()
    tmux("send-keys", "-t", "demo:0.0", "C-c")
    time.sleep(0.3)
    tmux("kill-server")


if __name__ == "__main__":
    main()
