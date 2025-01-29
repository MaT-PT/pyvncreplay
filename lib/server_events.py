from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import EllipsisType

from datastruct import DataStruct
from datastruct.fields import (
    action,
    built,
    field,
    padding,
    probe,
    repeat,
    subfield,
    switch,
    virtual,
)
from PIL import Image

from .constants import Encoding
from .data_structures import (
    Colour,
    EventBase,
    Rectangle,
    RFBContext,
    StringLatin1,
    get_fb_byte_size,
    get_timestamp,
    not_eof,
)


class ServerEventBase(EventBase, ABC):
    """Base class for server events."""


class FramebufferUpdateBase(DataStruct, ABC):
    @abstractmethod
    def process(self, ctx: RFBContext, rectangle: Rectangle) -> None: ...


class FramebufferUpdatePixelData(FramebufferUpdateBase, ABC):
    pixdata: bytes

    @abstractmethod
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes | Image.Image: ...

    def process(self, ctx: RFBContext, rectangle: Rectangle) -> None:
        print(f"Framebuffer update pixel data: {self}")
        ctx.update_screen(self.decode_pixdata(ctx, rectangle), rectangle)


class FramebufferUpdatePseudo(FramebufferUpdateBase, ABC): ...


@dataclass
class FramebufferUpdateRaw(FramebufferUpdatePixelData):
    _msg: EllipsisType = action(lambda ctx: print("[*] Raw pixel data"))
    pixdata: bytes = field(get_fb_byte_size)

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        return self.pixdata


@dataclass
class FramebufferUpdateCopyRect(FramebufferUpdatePixelData):
    _msg: EllipsisType = action(lambda ctx: print("[*] CopyRect pixel data"))
    src_x: int = field("H")
    src_y: int = field("H")

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> Image.Image:
        fb = ctx.framebuffer
        if fb is None:
            raise ValueError("Framebuffer not initialized")
        src_rect = Rectangle(self.src_x, self.src_y, rectangle.width, rectangle.height)
        return fb.get_screen_rectangle(src_rect)


@dataclass
class FramebufferUpdateRre(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateCorre(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateHextile(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateZlib(FramebufferUpdatePixelData):
    _msg: EllipsisType = action(lambda ctx: print("[*] ZLIB pixel data"))
    length: int = built("I", lambda ctx: len(ctx.zlib_data))
    zlib_data: bytes = field(lambda ctx: ctx.length)

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        return ctx.zlib_decompressor.decompress(self.zlib_data)


@dataclass
class FramebufferUpdateTight(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateZlibHex(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateZrle(FramebufferUpdateZlib):
    _msg: EllipsisType = action(lambda ctx: print("[*] ZRLE pixel data"))
    _probe: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        data = super().decode_pixdata(ctx, rectangle)
        print("Decompressed data:", data)
        raise NotImplementedError


@dataclass
class FramebufferUpdateJpeg(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateOpenH264(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FramebufferUpdateTightPng(FramebufferUpdatePixelData):
    _: EllipsisType = probe()

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError


@dataclass
class FrameBufferUpdatePseudoCursorWithAlpha(FramebufferUpdatePseudo):
    _msg: EllipsisType = action(lambda ctx: print("[*] Pseudo cursor with alpha"))
    encoding: Encoding = field("i")
    _probe: EllipsisType = probe()
    cursor_pixels: FramebufferUpdatePixelData = switch(lambda ctx: ctx.encoding)(
        RAW=(FramebufferUpdateRaw, subfield(Bpp=4)),
        COPYRECT=(FramebufferUpdateCopyRect, subfield(Bpp=4)),
        RRE=(FramebufferUpdateRre, subfield(Bpp=4)),
        CORRE=(FramebufferUpdateCorre, subfield(Bpp=4)),
        HEXTILE=(FramebufferUpdateHextile, subfield(Bpp=4)),
        ZLIB=(FramebufferUpdateZlib, subfield(Bpp=4)),
        TIGHT=(FramebufferUpdateTight, subfield(Bpp=4)),
        ZLIBHEX=(FramebufferUpdateZlibHex, subfield(Bpp=4)),
        ZRLE=(FramebufferUpdateZrle, subfield(Bpp=4)),
        JPEG=(FramebufferUpdateJpeg, subfield(Bpp=4)),
        OPENH264=(FramebufferUpdateOpenH264, subfield(Bpp=4)),
        TIGHT_PNG=(FramebufferUpdateTightPng, subfield(Bpp=4)),
    )

    def process(self, ctx: RFBContext, rectangle: Rectangle) -> None:
        print(f"Framebuffer update pseudo cursor with alpha: {self}")
        fb = ctx.framebuffer
        if fb is None:
            raise ValueError("Framebuffer not initialized")
        fb.update_cursor(
            self.cursor_pixels.decode_pixdata(ctx, rectangle), rectangle.size, rectangle.pos
        )

    def __str__(self) -> str:
        return f"Pseudo cursor with alpha: {self.cursor_pixels}"


@dataclass
class FramebufferUpdateRectangle(DataStruct):
    rectangle: Rectangle = subfield()
    encoding: Encoding = field("i")
    _: EllipsisType = probe()
    data: FramebufferUpdateBase = switch(lambda ctx: ctx.encoding)(
        RAW=(FramebufferUpdateRaw, subfield()),
        COPYRECT=(FramebufferUpdateCopyRect, subfield()),
        RRE=(FramebufferUpdateRre, subfield()),
        CORRE=(FramebufferUpdateCorre, subfield()),
        HEXTILE=(FramebufferUpdateHextile, subfield()),
        ZLIB=(FramebufferUpdateZlib, subfield()),
        TIGHT=(FramebufferUpdateTight, subfield()),
        ZLIBHEX=(FramebufferUpdateZlibHex, subfield()),
        ZRLE=(FramebufferUpdateZrle, subfield()),
        JPEG=(FramebufferUpdateJpeg, subfield()),
        OPENH264=(FramebufferUpdateOpenH264, subfield()),
        TIGHT_PNG=(FramebufferUpdateTightPng, subfield()),
        PSEUDO_CURSOR_WITH_ALPHA=(FrameBufferUpdatePseudoCursorWithAlpha, subfield()),
    )

    def process(self, ctx: RFBContext) -> None:
        print(f"Framebuffer update rectangle: {self}")
        self.data.process(ctx, self.rectangle)

    def __str__(self) -> str:
        return f"Update {self.rectangle} with encoding {self.encoding}"


@dataclass
class FramebufferUpdate(ServerEventBase):
    _pad: EllipsisType = padding(1)
    num_rects: int = built("H", lambda ctx: len(ctx.rectangles))
    __: EllipsisType = action(
        lambda ctx: print(f"[*] Framebuffer update: {ctx.num_rects} rectangles")
    )
    rectangles: list[FramebufferUpdateRectangle] = repeat(lambda ctx: ctx.num_rects)(subfield())

    def process(self, ctx: RFBContext) -> None:
        print(f"Framebuffer update: {self}")
        for rect in self.rectangles:
            rect.process(ctx)

    def __str__(self) -> str:
        return f"Rectangles: {self.num_rects}"


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
    timestamp: float = virtual(lambda ctx: get_timestamp(ctx, is_server=True))  # type: ignore[arg-type, return-value]
    event: ServerEventBase = switch(lambda ctx: ctx.msg_type)(
        _0=(FramebufferUpdate, subfield()),
        _1=(SetColourMapEntries, subfield()),
        _2=(Bell, subfield()),
        _3=(ServerCutText, subfield()),
    )

    def process(self, ctx: RFBContext) -> None:
        self.event.process(ctx)

    def __str__(self) -> str:
        return f"[SERVER] [{self.timestamp:.6f}] Event type {self.msg_type}: {self.event!r}"


@dataclass
class ServerEventStream(DataStruct):
    events: list[ServerEvent] = repeat(when=not_eof)(subfield())
