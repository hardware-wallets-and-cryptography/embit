"""SLIP-0039 test vectors, see data/vectors/README.md. CPython only.

test_slip39.py has copies of vectors 1 to 40 so that MicroPython runs them
too; this file checks every vector of the upstream file, and the master key
derived from each valid secret.

Vectors 42 to 45 are extendable backups, which embit doesn't support: they
are skipped while they still fail.
"""

import json
import os
from binascii import unhexlify
from unittest import TestCase

from embit.bip32 import HDKey
from embit.slip39 import Share, ShareSet

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors")


def load_json(*path):
    with open(os.path.join(VECTORS, *path), encoding="utf-8") as f:
        return json.load(f)


SLIP39 = load_json("python-shamir-mnemonic", "vectors.json")


def recover(mnemonics):
    # SLIP-0039: "The passphrase "TREZOR" is used for all valid sets"
    return ShareSet([Share.parse(m) for m in mnemonics]).recover(b"TREZOR")


class SLIP39Test(TestCase):
    def test_vectors(self):
        for description, mnemonics, secret, xprv in SLIP39:
            with self.subTest(description):
                if "extendable" in description.lower():
                    with self.assertRaises(ValueError, msg="remove this skip"):
                        recover(mnemonics)
                    self.skipTest("extendable backups aren't supported")
                if not secret:
                    with self.assertRaises(ValueError):
                        recover(mnemonics)
                    continue
                master_secret = recover(mnemonics)
                self.assertEqual(master_secret, unhexlify(secret))
                self.assertEqual(HDKey.from_seed(master_secret).to_base58(), xprv)
