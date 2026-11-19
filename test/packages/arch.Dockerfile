# Arch Linux with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). Its systemd needs cgroup v2.
FROM archlinux:latest@sha256:d4594bb2300cba11f41c2f27923eb56f63d9988909c402f9c95517d1e362c899
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
