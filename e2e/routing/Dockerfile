FROM debian:bookworm

RUN set -eux; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		iproute2; \
	rm -rf /var/lib/apt/lists/*

COPY routing-e2e /usr/local/bin/routing-e2e

ENTRYPOINT ["/usr/local/bin/routing-e2e"]
