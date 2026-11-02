# Rocky Linux 9 (EL9) with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). The image runs /sbin/init and
# has dnf; its systemd 252 knows Type=notify-reload (from 252-21).
FROM rockylinux/rockylinux:9-ubi-init@sha256:4a0c9370f20d3598bacf9d43393f85fd356ef1caa9bf93f7745a5cf5f23edab3
