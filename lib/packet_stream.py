from __future__ import annotations

from collections.abc import Buffer
from enum import Enum, auto
from io import SEEK_CUR, SEEK_END, SEEK_SET, BufferedIOBase
from typing import BinaryIO, Iterable, Self

from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw
from scapy.plist import PacketList


class PacketOrigin(Enum):
    CLIENT = auto()
    SERVER = auto()


class PacketStreamBytes(Iterable[bytes]):
    def __init__(self, packets: Iterable[Packet]) -> None:
        self.packets = iter(packets)

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> bytes:
        return next(self.packets).load

    def __str__(self) -> str:
        return f"{type(self).__name__}({self.packets})"


class DataStreamReader(BufferedIOBase, BinaryIO):
    def __init__(self, datastream: Iterable[bytes]) -> None:
        self._datastream = iter(datastream)
        self._buffer = bytearray()
        self._buffer_offset: int = 0

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return True

    def read(self, size: int | None = -1, /) -> bytes:
        if size == 0:
            return b""

        if size is not None and size < 0:
            size = None

        while size is None or len(self._buffer) - self._buffer_offset < size:
            try:
                data = next(self._datastream)
            except StopIteration:
                break
            self._buffer += data

        if size is None:
            new_offset = len(self._buffer)
        else:
            new_offset = self._buffer_offset + size
        data = bytes(self._buffer[self._buffer_offset : new_offset])
        self._buffer_offset = new_offset
        return data

    read1 = read

    def readall(self) -> bytes:
        return self.read()

    def tell(self) -> int:
        return self._buffer_offset

    def seek(self, offset: int, whence: int = SEEK_SET, /) -> int:
        to_read: int | None = None  # None means read all
        if whence == SEEK_SET:
            if offset < 0:
                raise ValueError(f"negative seek value {offset}")
            to_read = offset - self._buffer_offset
        elif whence == SEEK_CUR:
            to_read = offset
        elif whence == SEEK_END:
            to_read = None
        else:
            raise ValueError(f"invalid whence ({whence}, should be 0, 1 or 2)")

        if to_read is not None and to_read < 0:
            self._buffer_offset += to_read
            if self._buffer_offset < 0:
                self._buffer_offset = 0
            return self._buffer_offset

        self.read(to_read)
        if whence == SEEK_END:
            self._buffer_offset = len(self._buffer) + offset
        return self._buffer_offset

    def peek(self, size: int = 0, /) -> bytes:
        if size == 0:
            return b""
        data = self.read(size)
        self.seek(-size, SEEK_CUR)
        return data

    def __str__(self) -> str:
        try:
            ds = self._datastream
        except AttributeError:
            ds = None
        try:
            bo = self._buffer_offset
        except AttributeError:
            bo = None
        return f"{type(self).__name__}({ds}, offset={bo})"

    # The following methods are necessary to prevent type checking errors

    def write(self, buffer: Buffer, /) -> int:
        return super().write(buffer)

    def writelines(self, lines: Iterable[Buffer], /) -> None:
        return super().writelines(lines)

    def __enter__(self) -> Self:
        return self


class PacketStream(Iterable[Packet]):
    def __init__(self, packets: Iterable[Packet], origin: PacketOrigin | None = None) -> None:
        self._iter = iter(packets)
        self._next: Packet | None = next(self._iter, None)
        self._timestamp = self.next_timestamp
        self._origin = origin
        self._bytestream = DataStreamReader(PacketStreamBytes(self))

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Packet:
        pkt = self._next
        if pkt is None:
            raise StopIteration
        self._timestamp = float(pkt.time)
        self._next = next(self._iter, None)
        return pkt

    @property
    def peek_next(self) -> Packet | None:
        return self._next

    @property
    def next_load(self) -> bytes:
        load = next(self).load
        assert isinstance(load, bytes)
        return load

    @property
    def timestamp(self) -> float | None:
        return self._timestamp

    @property
    def next_timestamp(self) -> float | None:
        if self._next is None:
            return None
        return float(self._next.time)

    @property
    def bytestream(self) -> DataStreamReader:
        return self._bytestream

    @property
    def origin(self) -> PacketOrigin | None:
        return self._origin

    def __str__(self) -> str:
        return f"{type(self).__name__}(timestamp={self.timestamp}, origin={self.origin})"


class ClientServerPacketStream(Iterable[Packet]):
    def __init__(
        self,
        cli_stream: PacketStream | Iterable[Packet],
        srv_stream: PacketStream | Iterable[Packet],
    ) -> None:
        if not isinstance(cli_stream, PacketStream):
            cli_stream = PacketStream(cli_stream, PacketOrigin.CLIENT)
        if not isinstance(srv_stream, PacketStream):
            srv_stream = PacketStream(srv_stream, PacketOrigin.SERVER)
        self.cli_stream = cli_stream
        self.srv_stream = srv_stream
        self.packet_origin: PacketOrigin = PacketOrigin.CLIENT

    def __iter__(self) -> Self:
        return self

    def next_client(self) -> Packet:
        pkt = next(self.cli_stream)
        self.packet_origin = PacketOrigin.CLIENT
        return pkt

    def next_server(self) -> Packet:
        pkt = next(self.srv_stream)
        self.packet_origin = PacketOrigin.SERVER
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
        next_cli = self.cli_stream.peek_next
        next_srv = self.srv_stream.peek_next
        if next_cli is None:
            return self.next_server()
        if next_srv is None:
            return self.next_client()
        if next_cli.time < next_srv.time:
            return self.next_client()
        return self.next_server()

    @property
    def client_timestamp(self) -> float | None:
        return self.cli_stream.timestamp

    @property
    def server_timestamp(self) -> float | None:
        return self.srv_stream.timestamp

    @property
    def timestamp(self) -> float | None:
        origin = self.packet_origin
        match origin:
            case PacketOrigin.CLIENT:
                return self.client_timestamp
            case PacketOrigin.SERVER:
                return self.server_timestamp
        return None  # type: ignore[unreachable]

    @property
    def next_packet_origin(self) -> PacketOrigin | None:
        cli_time = self.cli_stream.next_timestamp
        srv_time = self.srv_stream.next_timestamp
        if srv_time is None:
            if cli_time is None:
                return None
            return PacketOrigin.CLIENT
        if cli_time is None:
            return PacketOrigin.SERVER
        return PacketOrigin.SERVER if srv_time < cli_time else PacketOrigin.CLIENT


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
        raise ValueError(
            f"Error getting VNC session: could not find {' and '.join(not_found)} packets"
        )

    # Swap packet streams if order is wrong: first packet should be server's ProtocolVersion
    if cli_packets[0].time < srv_packets[0].time:
        cli_packets, srv_packets = srv_packets, cli_packets

    print(f"Client packets: {len(cli_packets)}")
    print(f"Server packets: {len(srv_packets)}")

    return ClientServerPacketStream(cli_stream=cli_packets, srv_stream=srv_packets)
