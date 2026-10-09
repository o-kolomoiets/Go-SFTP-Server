#!/usr/bin/env bash
# Audits gosftpd's SSH configuration with ssh-audit (ROADMAP §7.6):
# crypto_policy = "modern" with an ed25519 host key must have no failure,
# and "compat" may fail only on the NIST curves documented in
# docs/security/hardening.md. Usage: test/ssh-audit.sh [SSH_AUDIT]
set -euo pipefail

SSH_AUDIT=${1:-ssh-audit}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PID=
cleanup() {
	[ -z "$PID" ] || kill "$PID" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

ROOT_FLAG=()
if [ "$(id -u)" = 0 ]; then ROOT_FLAG=(--allow-root); fi
(cd "$ROOT" && go build -o "$WORK/gosftpd" ./cmd/gosftpd)
ssh-keygen -q -t ed25519 -N '' -f "$WORK/user"
mkdir -p "$WORK/share"
"$WORK/gosftpd" hostkey generate --out "$WORK/host_key" >/dev/null

# audit POLICY ALLOWED_FAILURES: prints the failures and warnings; fails if
# a failure is not in ALLOWED_FAILURES (space-separated algorithm names).
audit() {
	local policy=$1 allowed=$2 port=$((20000 + RANDOM % 20000))
	cat >"$WORK/$policy.toml" <<TOML
config_version = 1
[server]
listen = ["127.0.0.1:$port"]
host_keys = ["$WORK/host_key"]
crypto_policy = "$policy"
[mounts.share]
path = "$WORK/share"
[users.u]
authorized_keys_file = "$WORK/user.pub"
access = { share = "read" }
TOML
	chmod 600 "$WORK/$policy.toml"
	"$WORK/gosftpd" serve --config "$WORK/$policy.toml" "${ROOT_FLAG[@]}" >"$WORK/$policy.log" 2>&1 &
	PID=$!
	for _ in $(seq 100); do
		if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
		sleep 0.1
	done
	set +e
	"$SSH_AUDIT" --skip-rate-test -j -p "$port" 127.0.0.1 >"$WORK/$policy.json"
	set -e
	kill "$PID"
	wait "$PID" || true
	PID=
	python3 - "$WORK/$policy.json" "$policy" "$allowed" <<'PY'
import json, sys
path, policy, allowed = sys.argv[1], sys.argv[2], set(sys.argv[3].split())
d = json.load(open(path))
bad = []
for section in ("kex", "key", "enc", "mac"):
    for alg in d.get(section, []):
        notes = alg.get("notes", {})
        for level in ("fail", "warn"):
            for text in notes.get(level, []):
                print(f"{policy}: {level}: {section} {alg['algorithm']}: {text}")
        if notes.get("fail") and alg["algorithm"] not in allowed:
            bad.append(alg["algorithm"])
for cve in d.get("cves", []):
    print(f"{policy}: CVE: {cve}")
    bad.append(cve.get("name", "CVE"))
if bad:
    sys.exit(f"{policy}: unexpected failures: {', '.join(bad)}")
print(f"{policy}: no unexpected failures")
PY
}

audit modern ""
audit compat "ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521"
