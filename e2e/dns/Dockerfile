ARG BASE=debian:bookworm
FROM ${BASE}

ARG FLAVOR=direct

RUN set -eux; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		bash \
		bind9-dnsutils \
		ca-certificates \
		dbus \
		iproute2 \
		python3; \
	rm -rf /var/lib/apt/lists/*

RUN set -eux; \
	apt-get update; \
	case "$FLAVOR" in \
		direct) ;; \
		debian-resolvconf) \
			DEBIAN_FRONTEND=noninteractive apt-get install -y --download-only --no-install-recommends resolvconf; \
			dpkg --unpack /var/cache/apt/archives/resolvconf_*.deb; \
			sed -i 's@^[[:space:]]*ln -nsf .* /etc/resolv.conf@        true # Docker e2e keeps /etc/resolv.conf as a writable file@' /var/lib/dpkg/info/resolvconf.postinst; \
			dpkg --configure resolvconf; \
			;; \
		openresolv) \
			DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openresolv; \
			;; \
		systemd-resolved) \
			DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-resolved; \
			;; \
		*) echo "unknown FLAVOR=$FLAVOR" >&2; exit 2 ;; \
	esac; \
	rm -rf /var/lib/apt/lists/*

COPY debug /usr/local/bin/sysnet-debug
COPY e2e/dns/upstream_dns.py /usr/local/lib/sysnet-dns-e2e/upstream_dns.py
COPY e2e/dns/run-case.sh /usr/local/bin/sysnet-dns-e2e

ENTRYPOINT ["/usr/local/bin/sysnet-dns-e2e"]
