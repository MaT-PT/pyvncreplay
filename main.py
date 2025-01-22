#!/usr/bin/env python3

from __future__ import annotations

from argparse import ArgumentParser, Namespace
from typing import Iterable

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from scapy.plist import PacketList

from lib.data_structures import (
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


class PacketStream:
    def __init__(self, packets: Iterable[Packet]) -> None:
        self._iter = iter(packets)
        self._next: Packet | None = next(self._iter, None)

    def __iter__(self) -> PacketStream:
        return self

    def __next__(self) -> Packet:
        pkt = self._next
        if pkt is None:
            raise StopIteration
        self._next = next(self._iter, None)
        return pkt

    @property
    def next_load(self) -> bytes:
        load = next(self).load
        assert isinstance(load, bytes)
        return load

    @property
    def timestamp(self) -> float:
        if self._next is None:
            raise StopIteration
        return float(self._next.time)


class ClientServerPacketStream:
    def __init__(
        self,
        cli_stream: PacketStream | Iterable[Packet],
        srv_stream: PacketStream | Iterable[Packet],
    ) -> None:
        if not isinstance(cli_stream, PacketStream):
            cli_stream = PacketStream(cli_stream)
        if not isinstance(srv_stream, PacketStream):
            srv_stream = PacketStream(srv_stream)
        self.cli_stream = cli_stream
        self.srv_stream = srv_stream
        self._next_cli: Packet | None = next(self.cli_stream, None)
        self._next_srv: Packet | None = next(self.srv_stream, None)

    def __iter__(self) -> ClientServerPacketStream:
        return self

    def next_client(self) -> Packet:
        pkt = self._next_cli
        if pkt is None:
            raise StopIteration
        self._next_cli = next(self.cli_stream, None)
        return pkt

    def next_server(self) -> Packet:
        pkt = self._next_srv
        if pkt is None:
            raise StopIteration
        self._next_srv = next(self.srv_stream, None)
        return pkt

    def next_cli_load(self) -> bytes:
        load = self.next_client().load
        assert isinstance(load, bytes)
        return load

    def next_srv_load(self) -> bytes:
        load = self.next_server().load
        assert isinstance(load, bytes)
        return load

    def __next__(self) -> Packet:
        if self._next_cli is None:
            return self.next_server()
        if self._next_srv is None:
            return self.next_client()
        if self._next_cli.time < self._next_srv.time:
            return self.next_client()
        return self.next_server()

    @property
    def timestamp(self) -> float:
        if self._next_cli is None:
            return self.srv_stream.timestamp
        if self._next_srv is None:
            return self.cli_stream.timestamp
        return min(self.cli_stream.timestamp, self.srv_stream.timestamp)


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Replay a VNC session from a pcap file")
    parser.add_argument("pcap", help="Path to the pcap file")

    return parser.parse_args()


def get_streams(pcap: PacketList) -> ClientServerPacketStream:
    srv_packets: list[Packet] = []
    cli_packets: list[Packet] = []

    for sess_name, packets in pcap.sessions().items():
        if TCP not in packets[0]:
            continue

        # Assume the first packet with data should be the RFB ProtocolVersion exchange
        raw0 = next((p for p in packets if Raw in p), None)
        if raw0 is None:
            continue
        load: bytes = raw0.load
        if not (len(load) == 12 and load.startswith(b"RFB ") and load.endswith(b"\n")):
            continue
        print(f"Found VNC session: {sess_name}")
        srv_packets = list(p for p in packets if TCP in p and Raw in p)
        if not cli_packets:
            cli_packets, srv_packets = srv_packets, cli_packets

        if cli_packets and srv_packets:
            break
    else:
        not_found: list[str] = []
        if not cli_packets:
            not_found.append("client")
        if not srv_packets:
            not_found.append("server")
        # print(f"Error getting VNC session: could not find {' and '.join(not_found)} packets")
        raise ValueError(
            f"Error getting VNC session: could not find {' and '.join(not_found)} packets"
        )

    # Swap packet streams if order is wrong: first packet should be server's ProtocolVersion
    if cli_packets[0].time < srv_packets[0].time:
        cli_packets, srv_packets = srv_packets, cli_packets

    print(f"Client packets: {len(cli_packets)}")
    print(f"Server packets: {len(srv_packets)}")

    return ClientServerPacketStream(cli_stream=cli_packets, srv_stream=srv_packets)


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
