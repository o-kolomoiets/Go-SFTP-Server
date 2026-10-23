# Debian 13 with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). Only systemd, systemd-sysv and
# sudo: apt install of the deb has to resolve its Depends: procps, a
# check that could not fail with procps in the image. The package
# lists stay, for that apt install.
FROM debian:13@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308
RUN apt-get update -q \
	&& apt-get install -y -q --no-install-recommends systemd systemd-sysv sudo \
	&& ! dpkg -s procps >/dev/null 2>&1
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
