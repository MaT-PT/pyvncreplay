from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.plist import PacketList

from .constants import SecurityResultVal, SecurityTypeVal
from .data_structures import (
    ClientEvent,
    ClientInit,
    Framebuffer,
    ProtocolVersion,
    RFBContext,
    SecurityResult,
    SelectedSecurityType,
    ServerEvent,
    ServerInit,
    ServerSecurityType,
    SupportedSecurityTypes,
    VNCSecurityChallenge,
)
from .packet_stream import ClientServerPacketStream, PacketOrigin, get_streams


def process_handshake(stream: ClientServerPacketStream, rfb_context: RFBContext) -> None:
    srv_bytestream = stream.srv_stream.bytestream
    cli_bytestream = stream.cli_stream.bytestream
    srv0 = stream.next_server()
    cli0 = stream.next_client()
    rfb_context.server = srv0[IP].src, srv0[TCP].sport
    rfb_context.client = cli0[IP].src, cli0[TCP].sport
    print(f"Server: {rfb_context.server_ip_port}")
    print(f"Client: {rfb_context.client_ip_port}")

    rfb_context.server_version = ProtocolVersion.unpack(srv0.load)
    rfb_context.client_version = ProtocolVersion.unpack(cli0.load)
    print(f"Server version: {rfb_context.server_version}")
    print(f"Client version: {rfb_context.client_version}")

    effective_version = min(rfb_context.server_version, rfb_context.client_version)

    if effective_version > "3.3":
        srv_security_types = SupportedSecurityTypes.unpack(srv_bytestream)
        print(f"Server supported security types: {srv_security_types}")

        cli_security_selected = SelectedSecurityType.unpack(cli_bytestream)
        print(f"Client selected security type: {cli_security_selected}")
        rfb_context.security = cli_security_selected.type
    else:
        srv_security = ServerSecurityType.unpack(srv_bytestream)
        print(f"Server selected security type: {srv_security}")
        rfb_context.security = srv_security.type

    match rfb_context.security:
        case SecurityTypeVal.NONE:
            print("Client selected no security")

        case SecurityTypeVal.VNC_AUTHENTICATION:
            print("Client selected VNC authentication")

            srv_vnc_challenge = VNCSecurityChallenge.unpack(srv_bytestream)
            print(f"Server VNC security challenge: {srv_vnc_challenge}")
            cli_vnc_challenge = VNCSecurityChallenge.unpack(cli_bytestream)
            print(f"Client VNC security challenge: {cli_vnc_challenge}")

        case _:
            raise ValueError(f"Unsupported security type: {rfb_context.security}")

    srv_security_result = SecurityResult.unpack(srv_bytestream)
    print(f"Server security result: {srv_security_result}")
    # TODO: Support unsuccessful security result message
    if srv_security_result.result is not SecurityResultVal.OK:
        raise ValueError(f"Handshake failed: {srv_security_result}")

    cli_init = ClientInit.unpack(cli_bytestream)
    print(f"Client init: {cli_init}")
    rfb_context.shared_access = cli_init.shared

    srv_init = ServerInit.unpack(srv_bytestream)
    print(f"Server init: {srv_init}")
    rfb_context.framebuffer = Framebuffer.from_serverinit(srv_init)


def process_events(stream: ClientServerPacketStream, rfb_context: RFBContext) -> None:
    event: ClientEvent | ServerEvent
    while True:
        match stream.next_packet_origin:
            case PacketOrigin.SERVER:
                print("[Server]", stream.next_srv_load())
                continue
                # event = ServerEvent.unpack(stream.srv_stream.bytestream, rfb_context=rfb_context)
                # print(event)
                # event.process(rfb_context)

            case PacketOrigin.CLIENT:
                event = ClientEvent.unpack(stream.cli_stream.bytestream, rfb_context=rfb_context)
                print(event)
                event.process(rfb_context)

            case _:  # None: no more packets in either stream
                break


def process_pcap(pcap: PacketList) -> None:
    stream = get_streams(pcap)
    rfb_context = RFBContext(stream)
    process_handshake(stream, rfb_context)
    process_events(stream, rfb_context)

    print()
    print("Typed text:")
    print("-" * 80)
    print(rfb_context.typed_text)
    print("-" * 80)

    # if rfb_context.framebuffer is not None:
    #     rfb_context.framebuffer._cursor_image.show()

    print("Done")
