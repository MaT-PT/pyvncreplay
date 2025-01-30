from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import EllipsisType

from datastruct import DataStruct
from datastruct.fields import built, field, padding, repeat, subfield, switch, virtual
from PIL import Image

from .constants import Encoding
from .data_structures import (
    BasicPixelFormat,
    Colour,
    EventBase,
    Rectangle,
    RFBContext,
    StringLatin1,
    get_bpp,
    get_depth,
    get_frame_size_bytes,
    get_timestamp,
    not_eof,
)
from .encodings import decode_zrle


class ServerEventBase(EventBase, ABC):
    """Base class for server events."""


class FramebufferUpdateBase(DataStruct, ABC):
    @abstractmethod
    def process(self, ctx: RFBContext, rectangle: Rectangle) -> None: ...

    @abstractmethod
    def __str__(self) -> str: ...


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
    pixdata: bytes = field(get_frame_size_bytes)

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        return self.pixdata

    def __str__(self) -> str:
        return f"Raw pixel data: {len(self.pixdata)} bytes"


@dataclass
class FramebufferUpdateCopyRect(FramebufferUpdatePixelData):
    src_x: int = field("H")
    src_y: int = field("H")

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> Image.Image:
        fb = ctx.framebuffer
        if fb is None:
            raise ValueError("Framebuffer not initialized")
        src_rect = Rectangle(self.src_x, self.src_y, rectangle.width, rectangle.height)
        return fb.get_screen_rectangle(src_rect)

    def __str__(self) -> str:
        return f"CopyRect from ({self.src_x}, {self.src_y})"


@dataclass
class FramebufferUpdateRre(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "RRE pixel data"


@dataclass
class FramebufferUpdateCorre(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "CoRRE pixel data"


@dataclass
class FramebufferUpdateHextile(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "Hextile pixel data"


@dataclass
class FramebufferUpdateZlib(FramebufferUpdatePixelData):
    length: int = built("I", lambda ctx: len(ctx.zlib_data))
    zlib_data: bytes = field(lambda ctx: ctx.length)

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        return ctx.zlib_decompressor.decompress(self.zlib_data)

    def __str__(self) -> str:
        return f"Zlib pixel data: {self.length} bytes"


@dataclass
class FramebufferUpdateTight(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "Tight pixel data"


@dataclass
class FramebufferUpdateZlibHex(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "ZlibHex pixel data"


@dataclass
class FramebufferUpdateZrle(FramebufferUpdateZlib):
    pix_bpp: int = virtual(get_bpp)  # type: ignore[arg-type]
    pix_depth: int = virtual(get_depth)  # type: ignore[arg-type]

    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        fb = ctx.framebuffer
        if fb is None:
            raise ValueError("Framebuffer not initialized")
        data = super().decode_pixdata(ctx, rectangle)
        # print("Decompressed data:", data)
        pix_fmt: BasicPixelFormat = fb.pix_fmt
        pix_fmt = BasicPixelFormat(self.pix_bpp, self.pix_depth, pix_fmt.big_endian, True)
        return decode_zrle(data, rectangle.size, pix_fmt)

    def __str__(self) -> str:
        return f"ZRLE pixel data: {self.length} bytes"


@dataclass
class FramebufferUpdateJpeg(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "JPEG pixel data"


@dataclass
class FramebufferUpdateOpenH264(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "Open H.264 pixel data"


@dataclass
class FramebufferUpdateTightPng(FramebufferUpdatePixelData):
    def decode_pixdata(self, ctx: RFBContext, rectangle: Rectangle) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return "Tight PNG pixel data"


@dataclass
class FrameBufferUpdatePseudoCursorWithAlpha(FramebufferUpdatePseudo):
    encoding: Encoding = field("i")
    cursor_pixels: FramebufferUpdatePixelData = switch(lambda ctx: ctx.encoding)(
        RAW=(FramebufferUpdateRaw, subfield(pix_bpp=32, pix_depth=32)),
        COPYRECT=(FramebufferUpdateCopyRect, subfield(pix_bpp=32, pix_depth=32)),
        RRE=(FramebufferUpdateRre, subfield(pix_bpp=32, pix_depth=32)),
        CORRE=(FramebufferUpdateCorre, subfield(pix_bpp=32, pix_depth=32)),
        HEXTILE=(FramebufferUpdateHextile, subfield(pix_bpp=32, pix_depth=32)),
        ZLIB=(FramebufferUpdateZlib, subfield(pix_bpp=32, pix_depth=32)),
        TIGHT=(FramebufferUpdateTight, subfield(pix_bpp=32, pix_depth=32)),
        ZLIBHEX=(FramebufferUpdateZlibHex, subfield(pix_bpp=32, pix_depth=32)),
        ZRLE=(FramebufferUpdateZrle, subfield(pix_bpp=32, pix_depth=32)),
        JPEG=(FramebufferUpdateJpeg, subfield(pix_bpp=32, pix_depth=32)),
        OPENH264=(FramebufferUpdateOpenH264, subfield(pix_bpp=32, pix_depth=32)),
        TIGHT_PNG=(FramebufferUpdateTightPng, subfield(pix_bpp=32, pix_depth=32)),
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
    rectangles: list[FramebufferUpdateRectangle] = repeat(lambda ctx: ctx.num_rects)(subfield())

    def process(self, ctx: RFBContext) -> None:
        for rect in self.rectangles:
            rect.process(ctx)

    def __str__(self) -> str:
        return f"Framebuffer update | Rectangles: {self.num_rects}\n" + "\n".join(
            "  - " + str(r) for r in self.rectangles
        )


@dataclass
class SetColourMapEntries(ServerEventBase):
    _pad: EllipsisType = padding(1)
    first_colour: int = field("H")
    num_colours: int = built("H", lambda ctx: len(ctx.colours))
    colours: list[Colour] = repeat(lambda ctx: ctx.num_colours)(subfield())

    def process(self, ctx: RFBContext) -> None:
        print(f"Set colour map entries: {self}")
        raise NotImplementedError

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
        return f"[SERVER] [{self.timestamp:.6f}] Event type {self.msg_type}: {self.event}"


@dataclass
class ServerEventStream(DataStruct):
    events: list[ServerEvent] = repeat(when=not_eof)(subfield())
