from enum import Flag, IntEnum
from typing import Iterable, Self


class PrettyEnum(IntEnum):
    def __str__(self) -> str:
        return f"{self.name} ({self.value})"


class SecurityTypeVal(PrettyEnum):
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


class SecurityResultVal(PrettyEnum):
    OK = 0
    FAILED = 1
    FAILED_TOO_MANY_ATTEMPTS = 2


class MouseButton(PrettyEnum):
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


class ButtonMask(Flag):
    NONE = 0
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

    def __str__(self) -> str:
        return super().__str__().removeprefix(f"{type(self).__name__}.")


class Encoding(PrettyEnum):
    RAW = 0
    COPYRECT = 1
    RRE = 2
    CORRE = 4
    HEXTILE = 5
    ZLIB = 6
    TIGHT = 7
    ZLIBHEX = 8
    ZRLE = 16
    JPEG = 21
    OPEN_H264 = 50
    TIGHT_PNG = -260

    PSEUDO_JPEG_QUALITY_LEVEL_9 = -23
    PSEUDO_JPEG_QUALITY_LEVEL_8 = -24
    PSEUDO_JPEG_QUALITY_LEVEL_7 = -25
    PSEUDO_JPEG_QUALITY_LEVEL_6 = -26
    PSEUDO_JPEG_QUALITY_LEVEL_5 = -27
    PSEUDO_JPEG_QUALITY_LEVEL_4 = -28
    PSEUDO_JPEG_QUALITY_LEVEL_3 = -29
    PSEUDO_JPEG_QUALITY_LEVEL_2 = -30
    PSEUDO_JPEG_QUALITY_LEVEL_1 = -31
    PSEUDO_JPEG_QUALITY_LEVEL_0 = -32
    PSEUDO_DESKTOPSIZE = -223
    PSEUDO_LASTRECT = -224
    PSEUDO_CURSOR = -239
    PSEUDO_X_CURSOR = -240
    PSEUDO_COMPRESSION_LEVEL_9 = -247
    PSEUDO_COMPRESSION_LEVEL_8 = -248
    PSEUDO_COMPRESSION_LEVEL_7 = -249
    PSEUDO_COMPRESSION_LEVEL_6 = -250
    PSEUDO_COMPRESSION_LEVEL_5 = -251
    PSEUDO_COMPRESSION_LEVEL_4 = -252
    PSEUDO_COMPRESSION_LEVEL_3 = -253
    PSEUDO_COMPRESSION_LEVEL_2 = -254
    PSEUDO_COMPRESSION_LEVEL_1 = -255
    PSEUDO_COMPRESSION_LEVEL_0 = -256
    PSEUDO_QEMU_POINTER_MOTION_CHANGE = -257
    PSEUDO_QEMU_EXTENDED_KEY_EVENT = -258
    PSEUDO_QEMU_AUDIO = -259
    PSEUDO_QEMU_LED_STATE = -261
    PSEUDO_GII = -305
    PSEUDO_DESKTOPNAME = -307
    PSEUDO_EXTENDEDDESKTOPSIZE = -308
    PSEUDO_XVP = -309
    PSEUDO_FENCE = -312
    PSEUDO_CONTINUOUSUPDATES = -313
    PSEUDO_CURSOR_WITH_ALPHA = -314
    PSEUDO_EXTENDEDMOUSEBUTTONS = -316
    PSEUDO_TIGHT_ENCODING_WITHOUT_ZLIB = -317
    # PSEUDO_JPEG_FINE_GRAINED_QUALITY_LEVEL = -412  # to -512
    PSEUDO_JPEG_SUBSAMPLING_LEVEL_16X = -763
    PSEUDO_JPEG_SUBSAMPLING_LEVEL_8X = -764
    PSEUDO_JPEG_SUBSAMPLING_LEVEL_GRAYSCALE = -765
    PSEUDO_JPEG_SUBSAMPLING_LEVEL_2X = -766
    PSEUDO_JPEG_SUBSAMPLING_LEVEL_4X = -767
    PSEUDO_JPEG_SUBSAMPLING_LEVEL_1X = -768
    PSEUDO_VMWARE_CURSOR = 0x574D5664
    PSEUDO_VMWARE_CURSOR_STATE = 0x574D5665
    PSEUDO_VMWARE_CURSOR_POSITION = 0x574D5666
    PSEUDO_VMWARE_KEY_REPEAT = 0x574D5667
    PSEUDO_VMWARE_LED_STATE = 0x574D5668
    PSEUDO_VMWARE_DISPLAY_MODE_CHANGE = 0x574D5669
    PSEUDO_VMWARE_VIRTUAL_MACHINE_STATE = 0x574D566A
    PSEUDO_EXTENDED_CLIPBOARD = -1063131698  # 0xC0A1E5CE

    @classmethod
    def get_name(cls, encoding: int) -> str:
        try:
            return str(cls(encoding))
        except ValueError:
            return f"Unknown ({encoding})"

    def __str__(self) -> str:
        return f"{self.name} ({self.value})"
