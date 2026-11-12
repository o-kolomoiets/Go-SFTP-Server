# Rocky Linux 9 (EL9) with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). The image runs /sbin/init and
# has dnf; its systemd 252 knows Type=notify-reload (from 252-21).
FROM rockylinux/rockylinux:9-ubi-init@sha256:535cbdf9607fba5db5678d368193661ef3012c35d06782fdb4ed0e27af4af0b4
