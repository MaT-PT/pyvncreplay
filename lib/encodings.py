from io import BytesIO
from typing import IO, Generator

from .data_structures import BasicPixelFormat


def read_byte(io: IO[bytes]) -> int:
    b = io.read(1)
    if not b:
        return -1
    return b[0]


def read_cpixel(io: IO[bytes], pix_fmt: BasicPixelFormat) -> bytes:
    return pix_fmt.decode_cpixel(io.read(pix_fmt.cpixel_size))


def get_palette(data: IO[bytes], pix_fmt: BasicPixelFormat, palette_size: int) -> list[bytes]:
    palette = [read_cpixel(data, pix_fmt) for _ in range(palette_size)]
    return palette


def get_rle_length(data: IO[bytes]) -> int:
    length = 1
    while True:
        b = read_byte(data)
        if b < 0:
            raise ValueError(f"Unexpected end of data while decoding RLE length ({length=})")
        length += b
        if b < 0xFF:
            break
    return length


def iterate_bitfields(data: bytes, bitfield_size: int) -> Generator[int, bool | None, None]:
    assert 8 % bitfield_size == 0, "Bitfield size must divide 8"
    mask = (1 << bitfield_size) - 1
    for b in data:
        for i in range(0, 8, bitfield_size):
            skip = yield (b >> (8 - bitfield_size - i)) & mask
            if skip:
                break


def decode_zrle_tile(
    data: bytes | IO[bytes], size: tuple[int, int], pix_fmt: BasicPixelFormat
) -> bytearray:
    if isinstance(data, bytes):
        data = BytesIO(data)
    width, height = size
    cpixel_size = pix_fmt.cpixel_size
    total_size = width * height * cpixel_size

    pixdata = bytearray()
    subencoding = read_byte(data)
    if subencoding < 0:
        print("[WARNING] Unexpected end of data while decoding ZRLE tile")
        pixdata += b"\x00" * total_size
        return pixdata

    if subencoding == 0:  # Raw
        pixdata += data.read(width * height * cpixel_size)
        if len(pixdata) < width * height * cpixel_size:
            print("[WARNING] [RAW] Not enough data to decode ZRLE tile")

    elif subencoding == 1:  # Solid colour
        pix = data.read(cpixel_size)
        pixdata += pix * (width * height)

    elif 2 <= subencoding <= 16:  # Packed palette
        palette = get_palette(data, pix_fmt, subencoding)
        if subencoding == 2:
            m = ((width + 7) // 8) * height
            bitfield_size = 1
        elif 3 <= subencoding <= 4:
            m = ((width + 3) // 4) * height
            bitfield_size = 2
        else:  # 5 <= subencoding <= 16
            m = ((width + 1) // 2) * height
            bitfield_size = 4
        packed_pixels = data.read(m)
        if len(packed_pixels) < m:
            print("[WARNING] [PACKED PALETTE] Not enough data to decode ZRLE tile")
        iter_bitfields = iterate_bitfields(packed_pixels, bitfield_size)
        for _ in range(height):
            try:
                pixdata += b"".join(palette[next(iter_bitfields)] for _ in range(width - 1))
                last = iter_bitfields.send(True)  # Align to byte boundary at the end of each row
                pixdata += palette[last]
            except (StopIteration, RuntimeError):
                pass

    elif 17 <= subencoding <= 127:  # Unused
        print(f"[WARNING] Unsupported ZRLE subencoding: {subencoding}")

    elif subencoding == 128:  # Plain RLE
        while len(pixdata) < total_size:
            pix = read_cpixel(data, pix_fmt)
            try:
                rle_length = get_rle_length(data)
            except ValueError as e:
                print(f"[WARNING] [PLAIN RLE] {e}")
                break
            pixdata += pix * rle_length

    elif subencoding == 129:  # Unused
        print(f"[WARNING] Unsupported ZRLE subencoding: {subencoding}")

    else:  # 130 <= subencoding <= 255: Palette RLE
        palette = get_palette(data, pix_fmt, subencoding - 128)
        while len(pixdata) < total_size:
            palette_idx = read_byte(data)
            if palette_idx < 0:
                print("[WARNING] [PALETTE RLE] Unexpected end of data while decoding ZRLE palette index in RLE")
                break
            if palette_idx < 128:
                pixdata += palette[palette_idx]
            else:
                try:
                    rle_length = get_rle_length(data)
                except ValueError as e:
                    print(f"[WARNING] [PALETTE RLE] {e}")
                    break
                pixdata += palette[palette_idx - 128] * rle_length

    if len(pixdata) > total_size:
        print("[WARNING] ZRLE tile data is longer than expected")
        del pixdata[total_size:]
    elif len(pixdata) < total_size:
        print("[WARNING] ZRLE tile data is shorter than expected")
        pixdata += b"\x00" * (total_size - len(pixdata))
    return pixdata


def decode_zrle(data: bytes, size: tuple[int, int], pix_fmt: BasicPixelFormat) -> bytes:
    width, height = size
    tile_x = 0
    tile_y = 0
    data_io = BytesIO(data)
    pixdata = bytearray(width * height * pix_fmt.bytes_per_pixel)

    while tile_y < height:
        tile_w = min(64, width - tile_x)
        while tile_x < width:
            tile_h = min(64, height - tile_y)
            tile_data = decode_zrle_tile(data_io, (tile_w, tile_h), pix_fmt)
            for row in range(tile_h):
                start = (tile_x + (tile_y + row) * width) * pix_fmt.bytes_per_pixel
                end = start + tile_w * pix_fmt.bytes_per_pixel
                pixdata[start:end] = tile_data[
                    row * tile_w * pix_fmt.bytes_per_pixel : (row + 1)
                    * tile_w
                    * pix_fmt.bytes_per_pixel
                ]
            tile_x += 64
        tile_y += 64

    return bytes(pixdata)
