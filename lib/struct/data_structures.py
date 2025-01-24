from abc import ABC, abstractmethod
from dataclasses import Field, dataclass
from dataclasses import field as dataclass_field
from enum import Enum, Flag, IntEnum
from functools import partial, total_ordering
from types import EllipsisType
from typing import Iterable, Self

from datastruct import NETWORK, Context, DataStruct, datastruct_config
from datastruct.fields import (
    adapter,
    align,
    built,
    const,
    field,
    padding,
    repeat,
    subfield,
    switch,
    text,
)
from PIL import Image

from .constants import Encoding
from .keysymdef import XKey

datastruct_config(endianness=NETWORK, padding_pattern=b"\0")

ascii = partial(text, encoding="ascii")
latin1 = partial(text, encoding="latin-1")


class EnumAdapter(Enum):
    __FORMAT__: str = "I"

    @classmethod
    def _encode(cls, value: Self, ctx: Context) -> int:
        return value.value

    @classmethod
    def _decode(cls, value: int, ctx: Context) -> Self:
        return cls(value)

    @classmethod
    def adapter(cls, fmt: str | None = None) -> Field[Self]:
        if fmt is None:
            fmt = cls.__FORMAT__
        return adapter(encode=cls._encode, decode=cls._decode)(field(fmt))

    def __str__(self) -> str:
        return f"{self.name} ({self.value})"


class SecurityTypeVal(int, EnumAdapter):
    __FORMAT__ = "B"

    INVALID = 0
    NONE = 1
    VNC_AUTHENTICATION = 2
    RSA_AES = 5
    RSA_AES_UNENCRYPTED = 6
    RSA_AES_TWO_STEP = 13
    TIGHT = 16
    VENCRYPT = 19
    SASL = 20
    XVP_AUTHENTICATION = 22
    DIFFIE_HELLMAN_AUTHENTICATION = 30
    MSLOGONII_AUTHENTICATION = 113
    RSA_AES_256 = 129
    RSA_AES_256_UNENCRYPTED = 130
    RSA_AES_256_TWO_STEP = 133


class SecurityResultVal(int, EnumAdapter):
    __FORMAT__ = "I"

    OK = 0
    FAILED = 1


class MouseButton(IntEnum):
    LEFT = 1
    MIDDLE = 2
    RIGHT = 3
    SCROLL_UP = 4
    SCROLL_DOWN = 5
    SCROLL_LEFT = 6
    SCROLL_RIGHT = 7
    BACK = 8

    @property
    def mask_index(self) -> int:
        return self - 1

    @property
    def mask(self) -> int:
        return 1 << self.mask_index


class ButtonMask(EnumAdapter, Flag):
    __FORMAT__ = "B"

    LEFT = MouseButton.LEFT.mask
    MIDDLE = MouseButton.MIDDLE.mask
    RIGHT = MouseButton.RIGHT.mask
    SCROLL_UP = MouseButton.SCROLL_UP.mask
    SCROLL_DOWN = MouseButton.SCROLL_DOWN.mask
    SCROLL_LEFT = MouseButton.SCROLL_LEFT.mask
    SCROLL_RIGHT = MouseButton.SCROLL_RIGHT.mask
    BACK = MouseButton.BACK.mask

    @classmethod
    def from_pressed(cls, pressed_buttons: Iterable[MouseButton]) -> Self:
        return cls(sum(button.mask for button in pressed_buttons))

    def is_pressed(self, button: MouseButton) -> bool:
        return bool(self & type(self)(button.mask))


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
class String(DataStruct):
    length: int = built("I", lambda ctx: len(ctx.value))
    value: str = text(lambda ctx: ctx.length)

    def __str__(self) -> str:
        return self.value


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
    # TODO: support case where num_types is 0 (error with message [int, vartext])
    num_types: int = built("B", lambda ctx: len(ctx.types))
    types: list[int] = repeat(lambda ctx: ctx.num_types)(field("B"))

    def __str__(self) -> str:
        return ", ".join(str(t) for t in self.types)


@dataclass
class SelectedSecurityType(DataStruct):
    type: SecurityTypeVal = SecurityTypeVal.adapter()  # type: ignore[assignment]

    def __str__(self) -> str:
        return str(self.type)


@dataclass
class ServerSecurityType(DataStruct):
    type: SecurityTypeVal = SecurityTypeVal.adapter(fmt="I")  # type: ignore[assignment]

    def __str__(self) -> str:
        return str(self.type)


@dataclass
class SecurityResult(DataStruct):
    result: SecurityResultVal = SecurityResultVal.adapter()  # type: ignore[assignment]

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
    name: String = subfield()

    def __str__(self) -> str:
        return (
            f"Size: {self.width}x{self.height} | Name: {self.name} | Pixel format: {self.pix_fmt}"
        )


@dataclass
class ClientEventBase(DataStruct, ABC):
    """Base class for client events.
    All client events must implement the `process` method."""

    @abstractmethod
    def process(self, ctx: RFBContext) -> None: ...


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
    button_mask: ButtonMask = ButtonMask.adapter()  # type: ignore[assignment]
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
    text: String = subfield()

    def process(self, ctx: RFBContext) -> None:
        print(f"Client cut text: {self}")
        ctx.clipboard = str(self.text)

    def __str__(self) -> str:
        return f"Text: {self.text}"


@dataclass
class ClientEvent(DataStruct):
    msg_type: int = field("B")
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
