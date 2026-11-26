"""Compact Int parsing / serialization"""

import io

# Largest length or count a serialized object may declare, as MAX_SIZE in
# Bitcoin Core's src/serialize.h. Checked before any data is read.
MAX_SIZE = 0x02000000


def to_bytes(i: int) -> bytes:
    """encodes an integer as a compact int"""
    if i < 0:
        raise ValueError("integer can't be negative: {}".format(i))
    order = 0
    while i >> (8 * (2**order)):
        order += 1
    if order == 0:
        if i < 0xFD:
            return bytes([i])
        order = 1
    if order > 3:
        raise ValueError("integer too large: {}".format(i))
    return bytes([0xFC + order]) + i.to_bytes(2**order, "little")


def from_bytes(b: bytes) -> int:
    """Decodes a canonical compact int, raises ValueError otherwise."""
    s = io.BytesIO(b)
    res = read_from(s)
    if len(s.read(1)) > 0:
        raise ValueError("Too many bytes")
    return res


def read_from(stream) -> int:
    """Reads a compact integer from a stream.

    Raises ValueError if the stream ends early or the integer doesn't use
    its shortest encoding, like Bitcoin Core's ReadCompactSize().
    """
    c = stream.read(1)
    if not isinstance(c, bytes):
        raise TypeError("Bytes must be returned from stream.read()")
    if len(c) != 1:
        raise ValueError("Can't read one byte from the stream")
    i = c[0]
    if i < 0xFD:
        return i
    bytes_to_read = 2 ** (i - 0xFC)
    data = stream.read(bytes_to_read)
    if len(data) != bytes_to_read:
        raise ValueError("Incomplete compact integer")
    res = int.from_bytes(data, "little")
    # 0xfd needs at least 253, 0xfe at least 2**16 and 0xff at least 2**32
    if res < (0xFD if bytes_to_read == 2 else 1 << (4 * bytes_to_read)):
        raise ValueError("Non-canonical compact integer")
    return res


def read_size(stream) -> int:
    """Reads a compact int that is a length or a count of items.

    Raises ValueError if it is larger than MAX_SIZE, before the caller reads
    or allocates anything for it.
    """
    size = read_from(stream)
    if size > MAX_SIZE:
        raise ValueError("Size %d is larger than MAX_SIZE" % size)
    return size
