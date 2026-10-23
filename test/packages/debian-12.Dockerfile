# Debian 12 with systemd as PID 1, for the CI job "packages"
# (test/packages/container.sh, ADR 0012). Only systemd, systemd-sysv and
# sudo: apt install of the deb has to resolve its Depends: procps, a
# check that could not fail with procps in the image. Its systemd 252
# lacks Type=notify-reload, so postinstall installs the drop-in, whose
# ExecReload= runs /bin/kill from procps. The package lists stay, for
# that apt install.
FROM debian:12@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61
RUN apt-get update -q \
	&& apt-get install -y -q --no-install-recommends systemd systemd-sysv sudo \
	&& ! dpkg -s procps >/dev/null 2>&1
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
