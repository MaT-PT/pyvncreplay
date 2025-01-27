from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from functools import partial, total_ordering
from types import EllipsisType
from typing import Self

from datastruct import NETWORK, Context, DataStruct, datastruct_config
from datastruct.fields import (
    align,
    built,
    const,
    field,
    padding,
    probe,
    repeat,
    subfield,
    switch,
    text,
    virtual,
)
from PIL import Image

from .constants import ButtonMask, Encoding, MouseButton, SecurityResultVal, SecurityTypeVal
from .keysymdef import XKey
from .packet_stream import ClientServerPacketStream

datastruct_config(endianness=NETWORK, padding_pattern=b"\0")

ascii = partial(text, encoding="ascii")
latin1 = partial(text, encoding="latin-1")


@dataclass
class CursorStatus:
    button_mask: ButtonMask
    x: int
    y: int

    @classmethod
    def from_pointer_event(cls, pointer_event: "PointerEvent") -> Self:
        return cls(button_mask=pointer_event.button_mask, x=pointer_event.x, y=pointer_event.y)

    def update(self, pointer_event: "PointerEvent") -> None:
        self.button_mask = pointer_event.button_mask
        self.x = pointer_event.x
        self.y = pointer_event.y

    def is_pressed(self, button: MouseButton) -> bool:
        return self.button_mask.is_pressed(button)

    def __str__(self) -> str:
        return f"Cursor at ({self.x}, {self.y}) with buttons {self.button_mask}"


@dataclass
class Framebuffer:
    width: int
    height: int
    pix_fmt: "PixelFormat"
    _cursor: CursorStatus | None = None
    _image: Image.Image = dataclass_field(init=False)
    _cursor_image: Image.Image = dataclass_field(init=False)

    def __post_init__(self) -> None:
        self._image = Image.new("RGBA", (self.width, self.height))
        self._cursor_image = Image.new("RGBA", (self.width, self.height))

    def update_cursor(self, cursor_event: "PointerEvent") -> None:
        if self._cursor is None:
            self._cursor = CursorStatus.from_pointer_event(cursor_event)
        else:
            self._cursor.update(cursor_event)

        try:
            self._cursor_image.putpixel((cursor_event.x, cursor_event.y), (255, 0, 0, 255))
        except IndexError:
            pass

    @classmethod
    def from_serverinit(cls, serverinit: "ServerInit") -> Self:
        return cls(serverinit.width, serverinit.height, serverinit.pix_fmt)


@dataclass
class RFBContext:
    packet_stream: ClientServerPacketStream
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    client_version: "ProtocolVersion | None" = None
    server_version: "ProtocolVersion | None" = None
    security: SecurityTypeVal | None = None
    shared_access: bool | None = None
    name: str | None = None
    framebuffer: Framebuffer | None = None
    _typed_text: str = ""
    _clipboard: str = ""

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

    def type_key(self, key: int) -> None:
        self._typed_text += XKey.get_name(key, raw_chars=True)

    @property
    def typed_text(self) -> str:
        return self._typed_text

    @property
    def clipboard(self) -> str:
        return self._clipboard

    @clipboard.setter
    def clipboard(self, value: str) -> None:
        self._clipboard = value


@dataclass
class StringBase(DataStruct, ABC):
    length: int
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass
class StringUtf8(StringBase):
    length: int = built("I", lambda ctx: len(ctx.value.encode("utf-8")))
    value: str = text(lambda ctx: ctx.length)


@dataclass
class StringLatin1(StringBase):
    length: int = built("I", lambda ctx: len(ctx.value.encode("latin-1")))
    value: str = latin1(lambda ctx: ctx.length)


@dataclass
class StringAscii(StringBase):
    length: int = built("I", lambda ctx: len(ctx.value.encode("ascii")))
    value: str = ascii(lambda ctx: ctx.length)


@dataclass
@total_ordering
class ProtocolVersion(DataStruct):
    signature: bytes = const(b"RFB ")(field("4s"))
    ver_major: str = ascii(3)
    ver_sep: bytes = const(b".")(field("1s"))
    ver_minor: str = ascii(3)
    newline: bytes = const(b"\n")(field("1s"))

    @classmethod
    def create(cls, value: str | tuple[int | str, int | str]) -> Self:
        if isinstance(value, str) and len(parts := value.split(".")) == 2:
            return cls(ver_major=parts[0], ver_minor=parts[1])
        if isinstance(value, tuple) and len(value) == 2:
            return cls(ver_major=f"{value[0]:03}", ver_minor=f"{value[1]:03}")
        raise ValueError("Invalid version format")

    @property
    def version(self) -> tuple[int, int]:
        return int(self.ver_major), int(self.ver_minor)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProtocolVersion):
            try:
                other = ProtocolVersion.create(other)  # type: ignore[arg-type]
            except ValueError:
                return False
        return self.version == other.version

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ProtocolVersion):
            try:
                other = ProtocolVersion.create(other)  # type: ignore[arg-type]
            except ValueError:
                raise NotImplementedError
        return self.version < other.version

    def __str__(self) -> str:
        ver_maj, ver_min = self.version
        return f"{ver_maj}{self.ver_sep.decode()}{ver_min}"


@dataclass
class SupportedSecurityTypes(DataStruct):
    num_types: int = built("B", lambda ctx: len(ctx.types))
    _types: StringUtf8 | list[int] = switch(lambda ctx: ctx.num_types)(
        _0=(StringUtf8, subfield()),
        default=(list[int], repeat(lambda ctx: ctx.num_types)(field("B"))),
    )

    @property
    def types(self) -> list[int]:
        if isinstance(self._types, StringBase):
            raise ValueError(f"Server sent error instead of security types: {self._types}")
        return self._types

    def __str__(self) -> str:
        return ", ".join(str(t) for t in self.types)


@dataclass
class SelectedSecurityType(DataStruct):
    type: SecurityTypeVal = field("B")

    def __str__(self) -> str:
        return str(self.type)


@dataclass
class ServerSecurityType(DataStruct):
    type: SecurityTypeVal = field("I")

    def __str__(self) -> str:
        return str(self.type)


@dataclass
class SecurityResult(DataStruct):
    result: SecurityResultVal = field("I")

    def __str__(self) -> str:
        return str(self.result)


@dataclass
class VNCSecurityChallenge(DataStruct):
    challenge: bytes = field("16s")

    def __str__(self) -> str:
        return self.challenge.hex()


@dataclass
class ClientInit(DataStruct):
    shared: bool = field("?")

    def __str__(self) -> str:
        return f"Requested {'shared' if self.shared else 'exclusive'} access"


@dataclass
class PixelFormat(DataStruct):
    bits_per_pixel: int = field("B")
    depth: int = field("B")
    big_endian: bool = field("?")
    true_colour: bool = field("?")
    red_max: int = field("H")
    green_max: int = field("H")
    blue_max: int = field("H")
    red_shift: int = field("B")
    green_shift: int = field("B")
    blue_shift: int = field("B")
    _pad: EllipsisType = align(16)

    def __str__(self) -> str:
        return (
            f"{self.bits_per_pixel} bpp, {self.depth}-bit depth, "
            f"{'big' if self.big_endian else 'little'} endian, "
            f"true color: {'yes' if self.true_colour else 'no'}, "
            f"RGB max: ({self.red_max}, {self.green_max}, {self.blue_max}), "
            f"shifts: ({self.red_shift}, {self.green_shift}, {self.blue_shift})"
        )

    def pretty(self) -> str:
        return (
            f"- Bits per pixel: {self.bits_per_pixel}\n"
            f"- Depth: {self.depth}\n"
            f"- Big endian: {self.big_endian}\n"
            f"- True color: {self.true_colour}\n"
            f"- Red max: {self.red_max}\n"
            f"- Green max: {self.green_max}\n"
            f"- Blue max: {self.blue_max}\n"
            f"- Red shift: {self.red_shift}\n"
            f"- Green shift: {self.green_shift}\n"
            f"- Blue shift: {self.blue_shift}"
        )


@dataclass
class ServerInit(DataStruct):
    width: int = field("H")
    height: int = field("H")
    pix_fmt: PixelFormat = subfield()
    name: StringUtf8 = subfield()

    def __str__(self) -> str:
        return (
            f"Size: {self.width}x{self.height} | Name: {self.name} | Pixel format: {self.pix_fmt}"
        )


@dataclass
class EventBase(DataStruct, ABC):
    """Base class for client and server events.
    All events must implement the `process` and `__str__` methods."""

    @abstractmethod
    def process(self, ctx: RFBContext) -> None: ...

    @abstractmethod
    def __str__(self) -> str: ...


@dataclass
class ClientEventBase(EventBase, ABC):
    """Base class for client events."""


@dataclass
class SetPixelFormat(ClientEventBase):
    _pad: EllipsisType = padding(3)
    pix_fmt: PixelFormat = subfield()

    def process(self, ctx: RFBContext) -> None:
        print(f"Set pixel format: {self}")
        if ctx.framebuffer is None:
            raise ValueError("Framebuffer not initialized")
        ctx.framebuffer.pix_fmt = self.pix_fmt

    def __str__(self) -> str:
        return str(self.pix_fmt)


@dataclass
class SetEncodings(ClientEventBase):
    _pad: EllipsisType = padding(1)
    num_encodings: int = built("H", lambda ctx: len(ctx.encodings))
    encodings: list[int] = repeat(lambda ctx: ctx.num_encodings)(field("i"))

    def process(self, ctx: RFBContext) -> None:
        print(f"Set encodings: {self}")

    def __str__(self) -> str:
        return ", ".join(Encoding.get_name(e) for e in self.encodings)


@dataclass
class FramebufferUpdateRequest(ClientEventBase):
    incremental: bool = field("?")
    x: int = field("H")
    y: int = field("H")
    width: int = field("H")
    height: int = field("H")

    def process(self, ctx: RFBContext) -> None:
        print(f"Framebuffer update request: {self}")

    def __str__(self) -> str:
        return (
            f"{'Incremental' if self.incremental else 'Full'} update {self.width}x{self.height} "
            f"at ({self.x}, {self.y})"
        )


@dataclass
class KeyEvent(ClientEventBase):
    is_down: bool = field("?")
    _pad: EllipsisType = padding(2)
    key: int = field("I")

    def process(self, ctx: RFBContext) -> None:
        print(f"Key event: {self}")
        if self.is_down:
            ctx.type_key(self.key)

    def __str__(self) -> str:
        return f"Key {'down' if self.is_down else 'up'}: {XKey.get_name(self.key)}"


@dataclass
class PointerEvent(ClientEventBase):
    button_mask: ButtonMask = field("B")
    x: int = field("H")
    y: int = field("H")

    def process(self, ctx: RFBContext) -> None:
        print(f"Pointer event: {self}")
        if ctx.framebuffer is None:
            raise ValueError("Framebuffer not initialized")
        ctx.framebuffer.update_cursor(self)

    def __str__(self) -> str:
        return f"Pointer at ({self.x}, {self.y}) with buttons {self.button_mask}"


@dataclass
class ClientCutText(ClientEventBase):
    _pad: EllipsisType = padding(3)
    text: StringLatin1 = subfield()

    def process(self, ctx: RFBContext) -> None:
        print(f"Client cut text: {self}")
        ctx.clipboard = str(self.text)

    def __str__(self) -> str:
        return str(self.text)


@dataclass
class ClientEvent(DataStruct):
    msg_type: int = field("B")
    timestamp: float = virtual(lambda ctx: ctx._.rfb_context.packet_stream.client_timestamp)
    event: ClientEventBase = switch(lambda ctx: ctx.msg_type)(
        _0=(SetPixelFormat, subfield()),
        _2=(SetEncodings, subfield()),
        _3=(FramebufferUpdateRequest, subfield()),
        _4=(KeyEvent, subfield()),
        _5=(PointerEvent, subfield()),
        _6=(ClientCutText, subfield()),
    )

    def process(self, ctx: RFBContext) -> None:
        self.event.process(ctx)

    def __str__(self) -> str:
        return f"[CLIENT] Event type {self.msg_type}: {self.event!r}"


@dataclass
class ServerEventBase(EventBase, ABC):
    """Base class for server events."""


@dataclass
class FramebufferUpdatePixelData(DataStruct, ABC): ...


@dataclass
class FramebufferUpdateRaw(FramebufferUpdatePixelData):
    _: EllipsisType = probe()
    # pixels: bytes = subfield()

    # def __str__(self) -> str:
    #     return f"Raw data: {len(self.pixels)} bytes"


@dataclass
class FramebufferUpdateRectangle(DataStruct):
    x: int = field("H")
    y: int = field("H")
    width: int = field("H")
    height: int = field("H")
    encoding: Encoding = field("i")
    data: FramebufferUpdatePixelData = switch(lambda ctx: ctx.encoding)(
        RAW=(FramebufferUpdateRaw, subfield()),
        ZRLE=(FramebufferUpdateRaw, subfield()),
        PSEUDO_CURSOR_WITH_ALPHA=(FramebufferUpdateRaw, subfield()),
    )

    def __str__(self) -> str:
        return f"Update {self.width}x{self.height} at ({self.x}, {self.y}) with encoding {self.encoding}"


@dataclass
class FramebufferUpdate(ServerEventBase):
    _pad: EllipsisType = padding(1)
    num_rects: int = built("H", lambda ctx: len(ctx.rects))
    rectangles: list[FramebufferUpdateRectangle] = repeat(lambda ctx: ctx.num_rects)(subfield())

    def process(self, ctx: RFBContext) -> None:
        print(f"Framebuffer update: {self}")

    def __str__(self) -> str:
        return f"Rectangles: {self.num_rects}"


@dataclass
class Colour(DataStruct):
    red: int = field("H")
    green: int = field("H")
    blue: int = field("H")

    def __str__(self) -> str:
        return f"({self.red}, {self.green}, {self.blue})"


@dataclass
class SetColourMapEntries(ServerEventBase):
    _pad: EllipsisType = padding(1)
    first_colour: int = field("H")
    num_colours: int = built("H", lambda ctx: len(ctx.colours))
    colours: list[Colour] = repeat(lambda ctx: ctx.num_colours)(subfield())

    def process(self, ctx: RFBContext) -> None:
        print(f"Set colour map entries: {self}")

    def __str__(self) -> str:
        cols = ", ".join(str(c) for c in self.colours)
        return f"First colour: {self.first_colour}, colours: {cols}"


@dataclass
class Bell(ServerEventBase):
    def process(self, ctx: RFBContext) -> None:
        print("*DING!*")

    def __str__(self) -> str:
        return "Bell event"


@dataclass
class ServerCutText(ServerEventBase):
    _pad: EllipsisType = padding(3)
    text: StringLatin1 = subfield()

    def process(self, ctx: RFBContext) -> None:
        print(f"Server cut text: {self}")
        ctx.clipboard = str(self.text)

    def __str__(self) -> str:
        return str(self.text)


@dataclass
class ServerEvent(DataStruct):
    msg_type: int = field("B")
    timestamp: float = virtual(lambda ctx: ctx._.rfb_context.packet_stream.server_timestamp)
    event: ServerEventBase = switch(lambda ctx: ctx.msg_type)(
        _0=(FramebufferUpdate, subfield()),
        _1=(SetColourMapEntries, subfield()),
        _2=(Bell, subfield()),
        _3=(ServerCutText, subfield()),
    )

    def process(self, ctx: RFBContext) -> None:
        self.event.process(ctx)

    def __str__(self) -> str:
        return f"[SERVER] Event type {self.msg_type}: {self.event!r}"


def not_eof(ctx: Context) -> bool:
    peek = ctx.P.peek
    if peek is None:
        return False
    return len(peek(1)) > 0


@dataclass
class ClientEventStream(DataStruct):
    events: list[ClientEvent] = repeat(when=not_eof)(subfield())


@dataclass
class ServerEventStream(DataStruct):
    events: list[ServerEvent] = repeat(when=not_eof)(subfield())
