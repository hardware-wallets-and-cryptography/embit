"""Bitcoin Core's tx_valid.json, see data/vectors/README.md. CPython only.

embit has no script interpreter, so only inputs that spend P2PKH, P2PK or
P2WPKH outputs are checked: their signatures must verify against the sighash
that embit computes for them.
"""

import json
import os
from binascii import unhexlify
from unittest import TestCase

from embit import ec
from embit.base import EmbitError
from embit.script import Script
from embit.transaction import SIGHASH, Transaction

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors")

OPCODES = {
    "0": 0x00,
    "DUP": 0x76,
    "HASH160": 0xA9,
    "EQUALVERIFY": 0x88,
    "CHECKSIG": 0xAC,
}


def load_json(*path):
    with open(os.path.join(VECTORS, *path), encoding="utf-8") as f:
        return json.load(f)


# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def high_s(der):
    """Whether a DER signature's S is above n/2; False if it isn't DER."""
    try:
        r_len = der[3]
        s_len = der[5 + r_len]
        s = int.from_bytes(der[6 + r_len : 6 + r_len + s_len], "big")
    except IndexError:
        return False
    return s > N // 2


def verifies(der, pub, message):
    """Whether the signature verifies, or None if it doesn't parse."""
    try:
        signature = ec.Signature.parse(der)
    except (ValueError, EmbitError):
        return None
    return ec.PublicKey.parse(pub).verify(signature, message())


def script_from_asm(asm):
    """Script bytes for the subset of Core's test asm used here, else None."""
    script = b""
    for token in asm.split():
        if token.startswith("0x"):
            script += unhexlify(token[2:])
        elif token in OPCODES:
            script += bytes([OPCODES[token]])
        else:
            return None
    return script


def pushes(data):
    """The items of a script made only of direct pushes, else None."""
    items = []
    while data:
        size = data[0]
        if not 1 <= size <= 75 or len(data) < 1 + size:
            return None
        items.append(data[1 : 1 + size])
        data = data[1 + size :]
    return items


def spends(prevouts, tx):
    """(input index, sighash function, signature, public key) of each input
    that spends a P2PKH, P2PK or P2WPKH output with the usual signature."""
    known = {}
    for prevout in prevouts:
        amount = prevout[3] if len(prevout) > 3 else None
        key = (prevout[0], prevout[1] & 0xFFFFFFFF)
        known[key] = (script_from_asm(prevout[2]), amount)
    for i, inp in enumerate(tx.vin):
        script, amount = known.get((inp.txid.hex(), inp.vout), (None, None))
        if script is None:
            continue
        items = pushes(inp.script_sig.data)
        witness = inp.witness.items if inp.witness else []
        if (
            len(script) == 25
            and script[:3] == b"\x76\xa9\x14"
            and script[23:] == b"\x88\xac"
        ):
            if items is None or len(items) != 2 or witness:
                continue
            sighash = lambda ht, i=i, code=Script(script): tx.sighash_legacy(
                i, code, ht
            )
            yield i, sighash, items[0], items[1], True
        elif (
            len(script) in (35, 67)
            and script[0] == len(script) - 2
            and script[-1] == 0xAC
        ):
            if items is None or len(items) != 1 or witness:
                continue
            sighash = lambda ht, i=i, code=Script(script): tx.sighash_legacy(
                i, code, ht
            )
            yield i, sighash, items[0], script[1:-1], True
        elif len(script) == 22 and script[:2] == b"\x00\x14" and amount is not None:
            if inp.script_sig.data or len(witness) != 2:
                continue
            code = Script(b"\x76\xa9\x14" + script[2:] + b"\x88\xac")
            sighash = lambda ht, i=i, code=code, a=amount: tx.sighash_segwit(
                i, code, a, ht
            )
            yield i, sighash, witness[0], witness[1], False


class TxValidTest(TestCase):
    def test_signatures_verify(self):
        checked = 0
        for case in load_json("bitcoin-core", "tx_valid.json"):
            if len(case) != 3 or not isinstance(case[0], list):
                continue  # a comment
            prevouts, raw, _ = case
            tx = Transaction.parse(unhexlify(raw))
            for i, sighash, sig, pub, legacy in spends(prevouts, tx):
                checked += 1
                der, hash_type = sig[:-1], sig[-1]
                with self.subTest(txid=tx.txid().hex(), input=i, hash_type=hash_type):
                    valid = verifies(der, pub, lambda: sighash(hash_type))
                    if high_s(der):
                        # pure Python rejects it when parsing, libsecp256k1
                        # when verifying; Core normalizes S first
                        self.assertFalse(valid, "verifies now, remove this skip")
                        self.skipTest("S above n/2, which embit rejects (BIP146)")
                    if valid is None:
                        self.skipTest("not a strict DER signature")
                    if (
                        legacy
                        and hash_type & 0x1F == SIGHASH.SINGLE
                        and i >= len(tx.vout)
                    ):
                        # Core signs the constant uint256 ONE here, which embit
                        # doesn't: such a signature fits every transaction
                        self.assertFalse(valid, "verifies now, remove this skip")
                        self.skipTest(
                            "SIGHASH_SINGLE without an output: Core signs ONE"
                        )
                    self.assertTrue(valid)
        # the subset this test understands must not shrink unnoticed
        self.assertEqual(checked, 49)
