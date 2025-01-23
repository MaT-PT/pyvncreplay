from __future__ import annotations

from dataclasses import dataclass, field
from typing import Self

from PIL import Image
from scapy.layers.inet import IP, TCP
from scapy.plist import PacketList

from .packet_stream import ClientServerPacketStream, get_streams
from .struct.data_structures import (
    ButtonMask,
    ClientInit,
    MouseButton,
    PixelFormat,
    PointerEvent,
    ProtocolVersion,
    SecurityResult,
    SecurityResultVal,
    SecurityTypeVal,
    SelectedSecurityType,
    ServerInit,
    SupportedSecurityTypes,
    VNCSecurityChallenge,
)


@dataclass
class Framebuffer:
    width: int
    height: int
    pix_fmt: PixelFormat
    image: Image.Image = field(init=False)

    def __post_init__(self) -> None:
        self.image = Image.new("RGBA", (self.width, self.height))

    @classmethod
    def from_serverinit(cls, serverinit: ServerInit) -> Self:
        return cls(serverinit.width, serverinit.height, serverinit.pix_fmt)


@dataclass
class CursorStatus:
    button_mask: ButtonMask
    x: int
    y: int

    @classmethod
    def from_pointer_event(cls, pointer_event: PointerEvent) -> Self:
        return cls(button_mask=pointer_event.button_mask, x=pointer_event.x, y=pointer_event.y)

    def update(self, pointer_event: PointerEvent) -> None:
        self.button_mask = pointer_event.button_mask
        self.x = pointer_event.x
        self.y = pointer_event.y

    def is_pressed(self, button: MouseButton) -> bool:
        return self.button_mask.is_pressed(button)

    def __str__(self) -> str:
        return f"Cursor at ({self.x}, {self.y}) with buttons {self.button_mask}"


@dataclass
class RFBContext:
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    client_version: ProtocolVersion | None = None
    server_version: ProtocolVersion | None = None
    security: SecurityTypeVal | None = None
    shared_access: bool | None = None
    name: str | None = None
    framebuffer: Framebuffer | None = None

    @property
    def client_ip_port(self) -> str | None:
        if self.client is None:
            return "None"
        return f"{self.client[0]}:{self.client[1]}"

    @property
    def server_ip_port(self) -> str | None:
        if self.server is None:
            return "None"
        return f"{self.server[0]}:{self.server[1]}"


def process_handshake(stream: ClientServerPacketStream, rfb_status: RFBContext) -> None:
    srv0 = stream.next_server()
    cli0 = stream.next_client()
    rfb_status.server = srv0[IP].src, srv0[TCP].sport
    rfb_status.client = cli0[IP].src, cli0[TCP].sport
    print(f"Server: {rfb_status.server_ip_port}")
    print(f"Client: {rfb_status.client_ip_port}")

    rfb_status.server_version = ProtocolVersion.unpack(srv0.load)
    rfb_status.client_version = ProtocolVersion.unpack(cli0.load)
    print(f"Server version: {rfb_status.server_version}")
    print(f"Client version: {rfb_status.client_version}")

    # TODO: support protocol version 3.3 with no security selection
    srv_security_types = SupportedSecurityTypes.unpack(stream.next_srv_load())
    print(f"Server supported security types: {srv_security_types}")

    cli_security_selected = SelectedSecurityType.unpack(stream.next_cli_load())
    print(f"Client selected security type: {cli_security_selected}")
    rfb_status.security = cli_security_selected.type

    match rfb_status.security:
        case SecurityTypeVal.NONE:
            print("Client selected no security")

        case SecurityTypeVal.VNC_AUTHENTICATION:
            print("Client selected VNC authentication")

            srv_vnc_challenge = VNCSecurityChallenge.unpack(stream.next_srv_load())
            print(f"Server VNC security challenge: {srv_vnc_challenge}")
            cli_vnc_challenge = VNCSecurityChallenge.unpack(stream.next_cli_load())
            print(f"Client VNC security challenge: {cli_vnc_challenge}")

        case _:
            raise ValueError(f"Unsupported security type: {cli_security_selected.type}")

    srv_security_result = SecurityResult.unpack(stream.next_srv_load())
    print(f"Server security result: {srv_security_result}")
    # TODO: Support unsuccessful security result message
    if srv_security_result.result is not SecurityResultVal.OK:
        raise ValueError(f"Handshake failed: {srv_security_result}")

    cli_init = ClientInit.unpack(stream.next_cli_load())
    print(f"Client init: {cli_init}")
    rfb_status.shared_access = cli_init.shared

    srv_init = ServerInit.unpack(stream.next_srv_load())
    print(f"Server init: {srv_init}")
    rfb_status.framebuffer = Framebuffer.from_serverinit(srv_init)


def process_events(stream: ClientServerPacketStream, rfb_context: RFBContext) -> None:
    pass


def process_pcap(pcap: PacketList) -> None:
    stream = get_streams(pcap)
    rfb_status = RFBContext()
    process_handshake(stream, rfb_status)
    process_events(stream, rfb_status)

    print("Done")
