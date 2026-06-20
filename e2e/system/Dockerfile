FROM debian:bookworm

RUN set -eux; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		iproute2; \
	rm -rf /var/lib/apt/lists/*

COPY system-e2e /usr/local/bin/system-e2e

ENTRYPOINT ["/usr/local/bin/system-e2e"]
