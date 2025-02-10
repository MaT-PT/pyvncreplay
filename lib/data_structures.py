from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from functools import partial, total_ordering
from types import EllipsisType
from typing import TYPE_CHECKING, Callable, Self
from zlib import decompressobj

from datastruct import NETWORK, Context, DataStruct, datastruct_config
from datastruct.fields import align, built, const, field, repeat, subfield, switch, text
from PIL import Image

from .constants import ButtonMask, MouseButton, SecurityResultVal, SecurityTypeVal
from .keysymdef import XKey

if TYPE_CHECKING:
    from zlib import _Decompress

    from .client_events import PointerEvent
    from .packet_stream import ClientServerPacketStream

datastruct_config(endianness=NETWORK, padding_pattern=b"\0")

# TODO: Add event callbacks to eg. save screenshots after each framebuffer update

ascii = partial(text, encoding="ascii")
latin1 = partial(text, encoding="latin-1")


def get_timestamp(ctx: Context, is_server: bool) -> float | None:
    rfb_context: RFBContext | None = (ctx._ or ctx).rfb_context
    if rfb_context is None:
        return None
    stream = rfb_context.packet_stream
    return stream.server_timestamp if is_server else stream.client_timestamp


def not_eof(ctx: Context) -> bool:
    peek = ctx.P.peek
    if peek is None:
        return False
    return len(peek(1)) > 0


@dataclass
class Rectangle(DataStruct):
    x: int = field("H")
    y: int = field("H")
    width: int = field("H")
    height: int = field("H")

    @property
    def pos(self) -> tuple[int, int]:
        return self.x, self.y

    @property
    def size(self) -> tuple[int, int]:
        return self.width, self.height

    @property
    def corners(self) -> tuple[int, int, int, int]:
        return (self.x, self.y, self.x + self.width, self.y + self.height)

    def __str__(self) -> str:
        return f"{self.width}x{self.height} @ ({self.x}, {self.y})"


@dataclass
class BasicPixelFormat(DataStruct):
    bits_per_pixel: int = field("B")
    depth: int = field("B")
    big_endian: bool = field("?")
    true_colour: bool = field("?")

    @property
    def bytes_per_pixel(self) -> int:
        return self.bits_per_pixel // 8

    @property
    def cpixel_size(self) -> int:
        if self.true_colour and self.bits_per_pixel == 32 and self.depth <= 24:
            return 3
        return self.bytes_per_pixel

    def decode_cpixel(self, cpixel: bytes) -> bytes:
        if self.cpixel_size == 3:
            return b"\x00" + cpixel
        return cpixel


@dataclass
class PixelFormat(BasicPixelFormat):
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
    pix_fmt: PixelFormat
    _cursor: CursorStatus | None = dataclass_field(init=False, default=None)
    _screen: Image.Image = dataclass_field(init=False)
    _cursor_img: Image.Image | None = dataclass_field(init=False, default=None)
    _cursor_path_img: Image.Image = dataclass_field(init=False)
    _cursor_center: tuple[int, int] = (0, 0)
    _event_handlers: dict[str, Callable[..., None]] = dataclass_field(
        init=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        self._screen = Image.new("RGB", (self.width, self.height))
        self._cursor_path_img = Image.new("RGBA", (self.width, self.height))

    def on(self, event: str, handler: Callable[..., None]) -> None:
        self._event_handlers[event] = handler

    def decode_pixel_data(self, pix_data: bytes) -> bytearray:
        if not self.pix_fmt.true_colour:
            raise ValueError("Unsupported Palette pixel format")

        # TODO: make sure endianness is handled correctly:
        # > Swap the pixel value according to big-endian-flag
        # > (e.g. if big-endian-flag is zero (false) and host byte order is big endian, then swap).
        data = bytearray()
        for i in range(0, len(pix_data), self.pix_fmt.bytes_per_pixel):
            pixel = pix_data[i : i + self.pix_fmt.bytes_per_pixel]
            pix_int = int.from_bytes(pixel, "big" if self.pix_fmt.big_endian else "little")
            red = (pix_int >> self.pix_fmt.red_shift) & self.pix_fmt.red_max
            green = (pix_int >> self.pix_fmt.green_shift) & self.pix_fmt.green_max
            blue = (pix_int >> self.pix_fmt.blue_shift) & self.pix_fmt.blue_max
            red = red * 255 // self.pix_fmt.red_max
            green = green * 255 // self.pix_fmt.green_max
            blue = blue * 255 // self.pix_fmt.blue_max
            data.extend((red, green, blue))
        return data

    def update_screen(
        self, img: bytes | Image.Image, rectangle: Rectangle | tuple[int, int] = (0, 0)
    ) -> None:
        if isinstance(rectangle, tuple):
            x, y = rectangle
            w, h = self.width, self.height
        else:
            x, y = rectangle.pos
            w, h = rectangle.size

        if isinstance(img, bytes):
            img = Image.frombytes("RGB", (w, h), self.decode_pixel_data(img))
        self._screen.paste(img, (x, y))

        handler = self._event_handlers.get("screen_update", None)
        if handler is not None:
            handler(self._screen, Rectangle(x, y, w, h))
        # self._screen.show()
        # input("Press Enter to continue...")

    def update_cursor(
        self, img: bytes | Image.Image, size: tuple[int, int], center: tuple[int, int]
    ) -> None:
        # Cursor pixel data is always 32-bit RGBA
        if isinstance(img, bytes):
            data = bytearray()
            for i in range(0, len(img), 4):
                pixel = img[i : i + 4]
                data.extend(pixel)
            img = Image.frombytes("RGBA", size, data)
        self._cursor_img = img
        self._cursor_center = center

        handler = self._event_handlers.get("update_cursor", None)
        if handler is not None:
            handler(self._cursor_img, size, center)
        # img.show()

    def update_cursor_position(self, cursor_event: "PointerEvent") -> None:
        if self._cursor is None:
            self._cursor = CursorStatus.from_pointer_event(cursor_event)
        else:
            self._cursor.update(cursor_event)

        try:
            self._cursor_path_img.putpixel((cursor_event.x, cursor_event.y), (255, 0, 0, 255))
        except IndexError:
            pass

        handler = self._event_handlers.get("update_cursor_position", None)
        if handler is not None:
            handler(self._cursor)

    def get_screen_rectangle(self, rectangle: Rectangle) -> Image.Image:
        return self._screen.crop(rectangle.corners)

    @property
    def byte_size(self) -> int:
        return self.width * self.height * self.pix_fmt.bytes_per_pixel

    @classmethod
    def from_serverinit(cls, serverinit: "ServerInit") -> Self:
        return cls(serverinit.width, serverinit.height, serverinit.pix_fmt)


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
class RFBContext:
    packet_stream: "ClientServerPacketStream"
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    client_version: ProtocolVersion | None = None
    server_version: ProtocolVersion | None = None
    security: SecurityTypeVal | None = None
    shared_access: bool | None = None
    name: str | None = None
    framebuffer: Framebuffer | None = None
    zlib_decompressor: "_Decompress" = dataclass_field(init=False, default_factory=decompressobj)
    _typed_text: str = dataclass_field(init=False, default="")
    _clipboard: str = dataclass_field(init=False, default="")
    _event_handlers: dict[str, Callable[..., None] | None] = dataclass_field(
        init=False, default_factory=dict
    )

    def on(self, event: str, handler: Callable[..., None]) -> None:
        self._event_handlers[event] = handler

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

        handler = self._event_handlers.get("type_key", None)
        if handler is not None:
            handler(key)

    @property
    def typed_text(self) -> str:
        return self._typed_text

    @property
    def clipboard(self) -> str:
        return self._clipboard

    @clipboard.setter
    def clipboard(self, value: str) -> None:
        self._clipboard = value

        handler = self._event_handlers.get("clipboard", None)
        if handler is not None:
            handler(value)

    @property
    def fb_byte_size(self) -> int:
        if self.framebuffer is None:
            raise ValueError("Framebuffer not initialized")
        return self.framebuffer.byte_size

    def update_screen(
        self, pix_data: bytes | Image.Image, rectangle: Rectangle | tuple[int, int] = (0, 0)
    ) -> None:
        if self.framebuffer is None:
            raise ValueError("Framebuffer not initialized")
        self.framebuffer.update_screen(pix_data, rectangle)


def get_rfb_context(ctx: Context) -> RFBContext:
    root_ctx = ctx.G.root
    if root_ctx is None:
        raise ValueError("Could not find root context")
    rfb_ctx: RFBContext | None = root_ctx.rfb_context
    if rfb_ctx is None:
        raise ValueError("Could not find rfb_context in root context")
    return rfb_ctx


def get_framebuffer(ctx: Context) -> Framebuffer:
    rfb_ctx = get_rfb_context(ctx)
    fb = rfb_ctx.framebuffer
    if fb is None:
        raise ValueError("Framebuffer not initialized")
    return fb


def get_bpp(ctx: Context) -> int:
    pix_bpp: int | None = ctx.pix_bpp
    # Allow overriding the bytes-per-pixel value for cursor pixels (always 32-bit RGBA)
    if pix_bpp is not None:
        return pix_bpp
    fb = get_framebuffer(ctx)
    return fb.pix_fmt.bits_per_pixel


def get_depth(ctx: Context) -> int:
    pix_depth: int | None = ctx.pix_depth
    if pix_depth is not None:
        return pix_depth
    fb = get_framebuffer(ctx)
    return fb.pix_fmt.depth


def get_frame_size_bytes(ctx: Context) -> int:
    bpp = get_bpp(ctx)
    fb = get_framebuffer(ctx)
    return fb.width * fb.height * bpp // 8


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
class Colour(DataStruct):
    red: int = field("H")
    green: int = field("H")
    blue: int = field("H")

    def __str__(self) -> str:
        return f"({self.red}, {self.green}, {self.blue})"


class EventBase(DataStruct, ABC):
    """Base class for client and server events.
    All events must implement the `process` and `__str__` methods."""

    @abstractmethod
    def process(self, ctx: RFBContext) -> None: ...

    @abstractmethod
    def __str__(self) -> str: ...
