#!/usr/bin/env python3
"""Tiny UDP DNS upstream for sysnet-linux DNS e2e tests.

The debug binary should never forward provider requests to the DNS server it
installed through SetDNS. Each test therefore makes this process the "original"
upstream at 127.0.0.54:53 before starting `debug dns`; successful queries prove
that the selected DNSProvider preserved and used that original upstream.
"""

import signal
import socket
import struct
import sys
import os


ADDR = (os.environ.get("SYSNET_DNS_E2E_UPSTREAM_ADDR", "127.0.0.54"), 53)
ANSWER = socket.inet_aton("203.0.113.10")


def question_end(packet: bytes, offset: int) -> int:
	while offset < len(packet):
		length = packet[offset]
		offset += 1
		if length == 0:
			return offset + 4
		offset += length
	raise ValueError("truncated DNS question")


def response(packet: bytes) -> bytes:
	if len(packet) < 12:
		raise ValueError("truncated DNS header")
	qend = question_end(packet, 12)
	header = bytearray(packet[:12])
	header[2:4] = b"\x81\x80"
	header[4:12] = b"\x00\x01\x00\x01\x00\x00\x00\x00"
	answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + ANSWER
	return bytes(header) + packet[12:qend] + answer


def main() -> int:
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(ADDR)
	print(f"upstream DNS listening on {ADDR[0]}:{ADDR[1]}", flush=True)

	stop = False

	def handle_stop(signum, frame):
		nonlocal stop
		stop = True
		sock.close()

	signal.signal(signal.SIGTERM, handle_stop)
	signal.signal(signal.SIGINT, handle_stop)

	while not stop:
		try:
			packet, peer = sock.recvfrom(4096)
		except OSError:
			break
		try:
			sock.sendto(response(packet), peer)
		except Exception as exc:  # noqa: BLE001
			print(f"upstream DNS error: {exc}", file=sys.stderr, flush=True)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
