from abc import ABC
from dataclasses import dataclass
from types import EllipsisType

from datastruct import DataStruct
from datastruct.fields import built, field, padding, repeat, subfield, switch, virtual

from .constants import ButtonMask, Encoding
from .data_structures import (
    EventBase,
    PixelFormat,
    RFBContext,
    StringLatin1,
    get_timestamp,
    not_eof,
)
from .keysymdef import XKey


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
        ctx.framebuffer.update_cursor_position(self)

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
    timestamp: float = virtual(lambda ctx: get_timestamp(ctx, is_server=False))  # type: ignore[arg-type, return-value]
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
        return f"[CLIENT] [{self.timestamp:.6f}] Event type {self.msg_type}: {self.event!r}"


@dataclass
class ClientEventStream(DataStruct):
    events: list[ClientEvent] = repeat(when=not_eof)(subfield())
