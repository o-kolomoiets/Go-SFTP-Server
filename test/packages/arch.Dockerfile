# Arch Linux with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). Its systemd needs cgroup v2.
FROM archlinux:latest@sha256:e82623936fa1a69700b48e98b058df6eaab18b737c27473a7234a40fdecb9413
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
