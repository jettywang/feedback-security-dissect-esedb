from __future__ import annotations

import struct

from dissect.util.compression import lzxpress, sevenbit

from dissect.esedb.c_esedb import COMPRESSION_SCHEME


def scheme(buf: bytes) -> COMPRESSION_SCHEME | None:
    """Return the compression scheme advertised by the given bytes, if any.

    The compression scheme identifier is stored in the upper 5 bits of the first byte. A scheme of
    ``COMPRESS_NONE`` is reported as ``None``.

    Args:
        buf: The (possibly compressed) bytes to inspect.

    Raises:
        ValueError: If the bytes do not advertise a known compression scheme.
    """
    if not buf:
        raise ValueError("cannot determine compression scheme of empty data")

    identifier = buf[0] >> 3
    scheme = COMPRESSION_SCHEME(identifier)
    if scheme not in COMPRESSION_SCHEME.__members__.values():
        raise ValueError(f"unknown compression scheme: {identifier}")

    return None if scheme == COMPRESSION_SCHEME.COMPRESS_NONE else scheme


def decompress(buf: bytes) -> bytes:
    """Decompress the given bytes according to the encoded compression scheme.

    Args:
        buf: The compressed bytes to decompress.

    Raises:
        NotImplementedError: If the buffer is compressed with an unsupported compression algorithm (XPRESS9/XPRESS10).
    """
    identifier = buf[0] >> 3
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
        return sevenbit.decompress(buf[1:])
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
        return sevenbit.decompress(buf[1:], wide=True)
    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS:
        return lzxpress.decompress(buf[3:])
    if identifier in (COMPRESSION_SCHEME.COMPRESS_XPRESS9, COMPRESSION_SCHEME.COMPRESS_XPRESS10):
        raise NotImplementedError(f"Compression not yet implemented: {COMPRESSION_SCHEME(identifier)}")
    # Not compressed
    return buf


def decompress_size(buf: bytes) -> int | None:
    """Return the decompressed size of the given bytes according to the encoded compression scheme.

    Args:
        buf: The compressed bytes to return the decompressed size of.

    Raises:
        NotImplementedError: If the buffer is compressed with an unsupported compression algorithm (XPRESS9/XPRESS10).
    """
    identifier = buf[0] >> 3
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
        return ((buf[0] & 7) + (8 * len(buf))) // 7
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
        return 2 * (((buf[0] & 7) + (8 * len(buf))) // 7)
    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS:
        return struct.unpack("<H", buf[1:2])[0]
    if identifier in (COMPRESSION_SCHEME.COMPRESS_XPRESS9, COMPRESSION_SCHEME.COMPRESS_XPRESS10):
        raise NotImplementedError(f"Compression not yet implemented: {COMPRESSION_SCHEME(identifier)}")
    return None
