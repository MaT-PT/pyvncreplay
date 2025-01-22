from dataclasses import Field, dataclass
from enum import Enum
from functools import partial
from types import EllipsisType
from typing import Self

from datastruct import NETWORK, Context, DataStruct, datastruct_config
from datastruct.fields import adapter, align, built, const, field, repeat, subfield, text

datastruct_config(endianness=NETWORK, padding_pattern=b"\0")

ascii = partial(text, encoding="ascii")


class EnumAdapter(Enum):
    __FORMAT__: str = "I"

    @classmethod
    def _encode(cls, value: Self, ctx: Context) -> int:
        return value.value

    @classmethod
    def _decode(cls, value: int, ctx: Context) -> Self:
        return cls(value)

    @classmethod
    def adapter(cls) -> Field[Self]:
        return adapter(encode=cls._encode, decode=cls._decode)(field(cls.__FORMAT__))

    def __str__(self) -> str:
        return f"{self.name} ({self.value})"


class SecurityTypeVal(int, EnumAdapter):
    __FORMAT__ = "B"

    # TODO: Support more security types
    INVALID = 0
    NONE = 1
    VNC_AUTHENTICATION = 2


class SecurityResultVal(int, EnumAdapter):
    __FORMAT__ = "I"

    OK = 0
    FAILED = 1


@dataclass
class ProtocolVersion(DataStruct):
    signature: bytes = const(b"RFB ")(field("4s"))  # pyright: ignore[reportAssignmentType]
    ver_major: str = ascii(3)  # pyright: ignore[reportAssignmentType]
    ver_sep: bytes = const(b".")(field("1s"))  # pyright: ignore[reportAssignmentType]
    ver_minor: str = ascii(3)  # pyright: ignore[reportAssignmentType]
    newline: bytes = const(b"\n")(field("1s"))  # pyright: ignore[reportAssignmentType]

    def __str__(self) -> str:
        ver_maj = int(self.ver_major)
        ver_min = int(self.ver_minor)
        return f"{ver_maj}{self.ver_sep.decode()}{ver_min}"


@dataclass
class SupportedSecurityTypes(DataStruct):
    # TODO: support case where num_types is 0 (error with message [int, vartext])
    num_types: int = built("B", lambda ctx: len(ctx.types))  # pyright: ignore[reportAssignmentType]
    types: list[int] = repeat(lambda ctx: ctx.num_types)(field("B"))  # pyright: ignore[reportAssignmentType]

    def __str__(self) -> str:
        return ", ".join(str(t) for t in self.types)


@dataclass
class SelectedSecurityType(DataStruct):
    type: SecurityTypeVal = SecurityTypeVal.adapter()  # type: ignore[assignment]

    def __str__(self) -> str:
        return str(self.type)


@dataclass
class SecurityResult(DataStruct):
    result: SecurityResultVal = SecurityResultVal.adapter()  # type: ignore[assignment]

    def __str__(self) -> str:
        return str(self.result)


@dataclass
class VNCSecurityChallenge(DataStruct):
    challenge: bytes = field("16s")  # pyright: ignore[reportAssignmentType]

    def __str__(self) -> str:
        return self.challenge.hex()


@dataclass
class ClientInit(DataStruct):
    shared: bool = field("?")  # pyright: ignore[reportAssignmentType]

    def __str__(self) -> str:
        return f"Requested {'shared' if self.shared else 'exclusive'} access"


@dataclass
class PixelFormat(DataStruct):
    bits_per_pixel: int = field("B")  # pyright: ignore[reportAssignmentType]
    depth: int = field("B")  # pyright: ignore[reportAssignmentType]
    big_endian: bool = field("?")  # pyright: ignore[reportAssignmentType]
    true_color: bool = field("?")  # pyright: ignore[reportAssignmentType]
    red_max: int = field("H")  # pyright: ignore[reportAssignmentType]
    green_max: int = field("H")  # pyright: ignore[reportAssignmentType]
    blue_max: int = field("H")  # pyright: ignore[reportAssignmentType]
    red_shift: int = field("B")  # pyright: ignore[reportAssignmentType]
    green_shift: int = field("B")  # pyright: ignore[reportAssignmentType]
    blue_shift: int = field("B")  # pyright: ignore[reportAssignmentType]
    _pad: EllipsisType = align(16)  # pyright: ignore[reportAssignmentType]

    def __str__(self) -> str:
        return (
            f"- Bits per pixel: {self.bits_per_pixel}\n"
            f"- Depth: {self.depth}\n"
            f"- Big endian: {self.big_endian}\n"
            f"- True color: {self.true_color}\n"
            f"- Red max: {self.red_max}\n"
            f"- Green max: {self.green_max}\n"
            f"- Blue max: {self.blue_max}\n"
            f"- Red shift: {self.red_shift}\n"
            f"- Green shift: {self.green_shift}\n"
            f"- Blue shift: {self.blue_shift}"
        )


@dataclass
class ServerInit(DataStruct):
    width: int = field("H")  # pyright: ignore[reportAssignmentType]
    height: int = field("H")  # pyright: ignore[reportAssignmentType]
    pix_fmt: PixelFormat = subfield()  # pyright: ignore[reportAssignmentType]
    name_len: int = built("I", lambda ctx: len(ctx.name))  # pyright: ignore[reportAssignmentType]
    name: str = text(lambda ctx: ctx.name_len)  # pyright: ignore[reportAssignmentType]

    def __str__(self) -> str:
        return (
            f"Size: {self.width}x{self.height} | Name: {self.name}\nPixel format:\n{self.pix_fmt}"
        )
