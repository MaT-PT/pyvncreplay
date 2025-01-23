#!/usr/bin/env python3

from __future__ import annotations

from argparse import ArgumentParser, Namespace

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP

from lib.packet_stream import get_streams
from lib.struct.data_structures import (
    ClientInit,
    ProtocolVersion,
    SecurityResult,
    SecurityResultVal,
    SecurityTypeVal,
    SelectedSecurityType,
    ServerInit,
    SupportedSecurityTypes,
    VNCSecurityChallenge,
)


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Replay a VNC session from a pcap file")
    parser.add_argument("pcap", help="Path to the pcap file")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pcap = rdpcap(args.pcap)

    stream = get_streams(pcap)

    srv0 = stream.next_server()
    cli0 = stream.next_client()
    srv_ip, srv_port = srv0[IP].src, srv0[TCP].sport
    cli_ip, cli_port = cli0[IP].src, cli0[TCP].sport
    print(f"Server: {srv_ip}:{srv_port}")
    print(f"Client: {cli_ip}:{cli_port}")

    srv_version = ProtocolVersion.unpack(srv0.load)
    cli_version = ProtocolVersion.unpack(cli0.load)
    print(f"Server version: {srv_version}")
    print(f"Client version: {cli_version}")

    # TODO: support protocol version 3.3 with no security selection
    srv_security_types = SupportedSecurityTypes.unpack(stream.next_srv_load())
    print(f"Server supported security types: {srv_security_types}")

    cli_security_selected = SelectedSecurityType.unpack(stream.next_cli_load())
    print(f"Client selected security type: {cli_security_selected}")

    if cli_security_selected.type is SecurityTypeVal.NONE:
        print("Client selected no security")
    elif cli_security_selected.type is SecurityTypeVal.VNC_AUTHENTICATION:
        print("Client selected VNC authentication")
        srv_vnc_challenge = VNCSecurityChallenge.unpack(stream.next_srv_load())
        print(f"Server VNC security challenge: {srv_vnc_challenge}")
        cli_vnc_challenge = VNCSecurityChallenge.unpack(stream.next_cli_load())
        print(f"Client VNC security challenge: {cli_vnc_challenge}")
    else:
        raise ValueError(f"Unsupported security type: {cli_security_selected.type}")

    srv_security_result = SecurityResult.unpack(stream.next_srv_load())
    print(f"Server security result: {srv_security_result}")
    # TODO: Support unsuccessful security result message
    if srv_security_result.result is not SecurityResultVal.OK:
        raise ValueError(f"Handshake failed: {srv_security_result}")

    cli_init = ClientInit.unpack(stream.next_cli_load())
    print(f"Client init: {cli_init}")

    srv_init = ServerInit.unpack(stream.next_srv_load())
    print(f"Server init: {srv_init}")


if __name__ == "__main__":
    main()
