# Rocky Linux 9 (EL9) with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). The image runs /sbin/init and
# has dnf; its systemd 252 knows Type=notify-reload (from 252-21).
FROM rockylinux/rockylinux:9-ubi-init@sha256:feb9a468e35facf41bf77d875cd75be2f8c91173899f47ef68c67b7d073662f1
