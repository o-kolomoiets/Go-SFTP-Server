# Rocky Linux 9 (EL9) with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). The image runs /sbin/init and
# has dnf; its systemd 252 knows Type=notify-reload (from 252-21).
FROM rockylinux/rockylinux:9-ubi-init@sha256:b11518949b4ddca4c8be8e5c1d57fd8a5f1f9cde5cf5de95cccfcaa266b8e114
