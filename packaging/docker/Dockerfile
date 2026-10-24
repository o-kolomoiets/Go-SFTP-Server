# The image ghcr.io/o-kolomoiets/gosftpd (ADR 0012). GoReleaser builds it
# (dockers_v2 in .goreleaser.yaml) from its own context: the binary under
# $TARGETPLATFORM and out/docker from make generate, so docker build in the
# repository does not work. No RUN: the arm64 image builds without
# emulation. The base image is pinned by its index digest; Dependabot
# updates it.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
ARG TARGETPLATFORM
COPY --chmod=0755 $TARGETPLATFORM/gosftpd /usr/bin/gosftpd
# Owned by 65532, so that named volumes start with that owner and mode.
COPY --chown=65532:65532 --chmod=0700 out/docker/empty/ /var/lib/gosftpd/
COPY --chmod=0755 out/docker/empty/ /srv/
COPY --chown=65532:65532 --chmod=0750 out/docker/empty/ /srv/sftp/
# /home as an entry of the copied tree: COPY keeps the owner of a target
# directory that exists. For atmoz compatibility (/home/<user>/<dir>).
COPY --chown=65532:65532 --chmod=0755 out/docker/home-root/ /
# atmoz mode's container conventions: /etc/sftp/users.conf, /home discovery,
# /etc/ssh host keys.
ENV GOSFTPD_ATMOZ_IMAGE=1
# The base image's working directory, /home/nonroot, is 0700 65532: under
# --user another uid could not search it for ./gosftpd.toml.
WORKDIR /
USER 65532:65532
EXPOSE 2022 9090
HEALTHCHECK --start-period=10s --start-interval=2s CMD ["/usr/bin/gosftpd","healthcheck"]
ENTRYPOINT ["/usr/bin/gosftpd"]
CMD ["serve"]
