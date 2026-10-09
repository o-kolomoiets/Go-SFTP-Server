#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""paramiko against gosftpd, called by test/interop/run.sh.

Usage: paramiko_check.py PORT KNOWN_HOSTS KEYDIR INBOX LOCAL_FILE
KEYDIR holds id_reader, id_partner and id_admin; INBOX is the host path of
the "inbox" mount (partner: upload preset, on_conflict=rename). The
environment variable COURIER_PASSWORD is the password of the user courier.
"""

import io
import os
import sys
import threading

import paramiko
from paramiko.message import Message

port, known_hosts, keydir, inbox, local = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
failed = False


def check(ok, what):
    global failed
    print(("ok:   " if ok else "FAIL: ") + "paramiko: " + what)
    failed = failed or not ok


def connect(user):
    client = paramiko.SSHClient()
    client.load_host_keys(known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    key = paramiko.Ed25519Key.from_private_key_file(os.path.join(keydir, "id_" + user))
    client.connect("127.0.0.1", port=int(port), username=user, pkey=key,
                   allow_agent=False, look_for_keys=False, timeout=10)
    return client, client.open_sftp()


with open(local, "rb") as f:
    data = f.read()

# partner: put(confirm=True) over an existing file passes thanks to the stat
# redirect; the original is untouched and a copy holds the upload (DoD M2).
ssh, sftp = connect("partner")
original = open(os.path.join(inbox, "report.txt"), "rb").read()
before = set(os.listdir(inbox))
try:
    attrs = sftp.put(local, "report.txt", confirm=True)
    check(attrs.st_size == len(data), "put(confirm=True) over an existing file")
except Exception as e:  # noqa: BLE001
    check(False, "put(confirm=True) over an existing file: %r" % e)
new = sorted(set(os.listdir(inbox)) - before)
check(open(os.path.join(inbox, "report.txt"), "rb").read() == original, "original kept")
check(len(new) == 1 and new[0].startswith("report (") and
      open(os.path.join(inbox, new[0]), "rb").read() == data, "upload went to a copy: %s" % new)

# partner: resume with mode "a" completes a partial upload.
half = len(data) // 2
sftp.putfo(io.BytesIO(data[:half]), "resume.bin")
with sftp.open("resume.bin", "a") as f:
    f.write(data[half:])
check(open(os.path.join(inbox, "resume.bin"), "rb").read() == data, "append mode completes a partial upload")

# A write into the existing bytes is refused.
try:
    with sftp.open("resume.bin", "r+") as f:
        f.write(b"EVIL")
    check(False, "overwriting existing bytes was allowed")
except IOError:
    check(open(os.path.join(inbox, "resume.bin"), "rb").read() == data, "overwriting existing bytes refused")

# Listings show the virtual owner, not host accounts.
attrs = sftp.listdir_attr(".")
check(attrs and all(a.st_uid == 1000 and a.st_gid == 1000 for a in attrs), "virtual owners in listings")

# No download for the upload preset.
try:
    sftp.getfo("report.txt", io.BytesIO())
    check(False, "partner could download")
except IOError:
    check(True, "download refused for the upload preset")
sftp.close()
ssh.close()

# reader: downloads work, uploads do not.
ssh, sftp = connect("reader")
check(sftp.open("readme.txt").read() == b"public file\n", "reader download")
try:
    sftp.putfo(io.BytesIO(b"x"), "new.txt")
    check(False, "reader could upload")
except IOError:
    check(True, "upload refused for the read preset")
sftp.close()
ssh.close()

# courier: password login (COURIER_PASSWORD), uploads only.
client = paramiko.SSHClient()
client.load_host_keys(known_hosts)
client.set_missing_host_key_policy(paramiko.RejectPolicy())
client.connect("127.0.0.1", port=int(port), username="courier", password=os.environ["COURIER_PASSWORD"],
               allow_agent=False, look_for_keys=False, timeout=10)
sftp = client.open_sftp()
sftp.putfo(io.BytesIO(b"by password\n"), "paramiko-courier.txt")
check(open(os.path.join(inbox, "paramiko-courier.txt"), "rb").read() == b"by password\n", "password login and upload")
sftp.close()
client.close()
try:
    client = paramiko.SSHClient()
    client.load_host_keys(known_hosts)
    client.connect("127.0.0.1", port=int(port), username="courier", password="wrong",
                   allow_agent=False, look_for_keys=False, timeout=10)
    client.close()
    check(False, "wrong password accepted")
except paramiko.AuthenticationException:
    check(True, "wrong password refused")

# A change of user name within one connection is refused, as sshd does: a
# wrong password for courier, then admin's key on the same connection.
# This drives paramiko's auth handler directly (no public API for it).
t = paramiko.Transport(("127.0.0.1", int(port)))
t.start_client(timeout=10)
try:
    t.auth_password("courier", "wrong", fallback=False)
except paramiko.AuthenticationException:
    pass
ah = t.auth_handler
event = threading.Event()
ah.auth_event = event
ah.username = "admin"
ah.auth_method = "publickey"
ah.private_key = paramiko.Ed25519Key.from_private_key_file(os.path.join(keydir, "id_admin"))
accept = Message()
accept.add_string("ssh-userauth")
accept.rewind()
ah._parse_service_accept(accept)
try:
    ah.wait_for_response(event)
    check(False, "user name changed within a connection")
except paramiko.AuthenticationException:
    check(True, "user name change within a connection refused")
t.close()

sys.exit(1 if failed else 0)
