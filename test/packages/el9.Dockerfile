# Rocky Linux 9 (EL9) with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). The image runs /sbin/init and
# has dnf; its systemd 252 knows Type=notify-reload (from 252-21).
FROM rockylinux/rockylinux:10-ubi-init@sha256:81a2afe3645266b059214fc91bff27c5a51862abc61bf244b867e51d1093567c
