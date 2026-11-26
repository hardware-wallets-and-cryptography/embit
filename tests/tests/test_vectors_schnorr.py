"""BIP340 test vectors, see data/vectors/README.md. CPython only.

Every row is verified, and every row with a secret key is signed again with
its aux_rand. Rows 15 to 18 use messages that aren't 32 bytes long, which
embit doesn't sign or verify: they are skipped while both still raise.
"""

import csv
import os
from binascii import unhexlify
from unittest import TestCase

from embit import ec
from embit.ec import ECError
from embit.util import secp256k1

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors")

FIELDS = ("secret key", "public key", "aux_rand", "message", "signature")


def load_csv(*path):
    with open(os.path.join(VECTORS, *path), encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


BIP340 = load_csv("bitcoin-bips", "bip-0340", "test-vectors.csv")


def verifies(pub, sig, msg):
    """Whether the signature verifies; a key that isn't on the curve doesn't."""
    try:
        key = ec.PublicKey.from_xonly(pub)
    except ECError:
        return False
    return key.schnorr_verify(ec.SchnorrSig(sig), msg)


class BIP340Test(TestCase):
    def test_vectors(self):
        for row in BIP340:
            sk, pk, aux, msg, sig = (unhexlify(row[field]) for field in FIELDS)
            valid = row["verification result"] == "TRUE"
            with self.subTest(index=row["index"]):
                if sk:
                    self.assertEqual(ec.PrivateKey(sk).xonly(), pk)
                if len(msg) != 32:
                    with self.assertRaises(ValueError, msg="remove this skip"):
                        verifies(pk, sig, msg)
                    if sk:
                        with self.assertRaises(ValueError, msg="remove this skip"):
                            secp256k1.schnorrsig_sign(msg, sk, None, aux)
                    self.skipTest("embit signs and verifies 32-byte messages only")
                if sk:
                    self.assertEqual(secp256k1.schnorrsig_sign(msg, sk, None, aux), sig)
                self.assertEqual(verifies(pk, sig, msg), valid)
