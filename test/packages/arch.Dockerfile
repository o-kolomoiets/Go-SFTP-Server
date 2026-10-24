# Arch Linux with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). Its systemd needs cgroup v2.
FROM archlinux:latest@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
