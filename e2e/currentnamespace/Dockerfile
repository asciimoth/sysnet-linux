FROM debian:bookworm

RUN set -eux; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		util-linux; \
	rm -rf /var/lib/apt/lists/*

COPY currentnamespace-e2e /usr/local/bin/currentnamespace-e2e

ENTRYPOINT ["/usr/local/bin/currentnamespace-e2e"]
