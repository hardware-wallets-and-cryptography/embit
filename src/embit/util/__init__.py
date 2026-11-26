from . import secp256k1

try:
    from micropython import const
except ImportError:
    const = lambda x: x
