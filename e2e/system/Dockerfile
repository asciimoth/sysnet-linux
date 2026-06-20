FROM debian:bookworm

ARG FLAVOR=direct

RUN set -eux; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		iproute2; \
	case "$FLAVOR" in \
		direct) ;; \
		systemd-resolved) \
			DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
				dbus \
				systemd \
				systemd-resolved; \
			;; \
		*) echo "unknown FLAVOR=$FLAVOR" >&2; exit 2 ;; \
	esac; \
	rm -rf /var/lib/apt/lists/*

COPY system-e2e /usr/local/bin/system-e2e

ENTRYPOINT ["/usr/local/bin/system-e2e"]
