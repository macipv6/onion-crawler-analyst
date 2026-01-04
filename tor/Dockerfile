# tor/Dockerfile (Alpine 3.20, feste Repos & Retry)
FROM alpine:3.20

# Feste Mirrors eintragen (main + community) – vermeidet temporäre 404/Timeouts
RUN printf '%s\n' \
    'https://dl-cdn.alpinelinux.org/alpine/v3.20/main' \
    'https://dl-cdn.alpinelinux.org/alpine/v3.20/community' \
    > /etc/apk/repositories

# Update + Install mit Retry-Loop, plus explizite Runtimes
# tor zieht libevent, libcap, libseccomp, xz-libs, zstd-libs etc.
RUN set -eux; \
    for i in 1 2 3; do \
      apk update && apk add --no-cache tor curl \
      && break || (echo "apk retry $i/3..." && sleep 3); \
    done

COPY torrc /etc/tor/torrc

EXPOSE 9050 9051
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
