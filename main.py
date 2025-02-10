#!/usr/bin/env python3

from __future__ import annotations

from argparse import ArgumentParser, Namespace

from scapy.all import rdpcap

from lib.rfb import process_pcap


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Replay a VNC session from a pcap file")
    parser.add_argument("pcap", help="Path to the pcap file")
    parser.add_argument(
        "-o", "--outdir", help="Output directory for screenshots", default="./screenshots"
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pcap = rdpcap(args.pcap)

    process_pcap(pcap, args.outdir)


if __name__ == "__main__":
    main()
