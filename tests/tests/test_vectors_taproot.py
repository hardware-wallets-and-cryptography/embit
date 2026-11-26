"""BIP341 wallet test vectors, see data/vectors/README.md. CPython only.

embit doesn't build control blocks (PSBT signing takes them as given), so
the scriptPathControlBlocks of the scriptPubKey cases aren't checked.
"""

import json
import os
from binascii import unhexlify
from io import BytesIO
from unittest import TestCase

from embit import ec
from embit.descriptor.taptree import TapLeaf, TapTree
from embit.networks import NETWORKS
from embit.psbt import PSBT
from embit.psbtview import PSBTView
from embit.script import Script, address_to_scriptpubkey, p2tr
from embit.transaction import Transaction, TransactionOutput
from embit.util import secp256k1

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors")

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def load_json(*path):
    with open(os.path.join(VECTORS, *path), encoding="utf-8") as f:
        return json.load(f)


BIP341 = load_json("bitcoin-bips", "bip-0341", "wallet-test-vectors.json")


class RawScript:
    """Stands in for a leaf's miniscript: the vectors' leaf scripts aren't
    all miniscript, but TapLeaf.serialize() only needs compile()."""

    keys = []

    def __init__(self, script):
        self.script = script

    def compile(self):
        return self.script


def taptree(node):
    """The TapTree of a vector's scriptTree, or None."""
    if node is None:
        return None
    if isinstance(node, list):
        left, right = node
        return TapTree((taptree(left), taptree(right)))
    leaf = TapLeaf(version=node["leafVersion"])
    leaf.miniscript = RawScript(unhexlify(node["script"]))
    return TapTree(leaf)


class BIP341Test(TestCase):
    def test_script_pubkeys(self):
        """Each output's Merkle root, tweaked key, scriptPubKey and address."""
        for i, case in enumerate(BIP341["scriptPubKey"]):
            given, intermediary = case["given"], case["intermediary"]
            expected = case["expected"]
            with self.subTest(case=i):
                internal = ec.PublicKey.from_xonly(unhexlify(given["internalPubkey"]))
                tree = taptree(given["scriptTree"])
                merkle_root = tree.tweak() if tree else b""
                self.assertEqual(
                    merkle_root, unhexlify(intermediary["merkleRoot"] or "")
                )
                self.assertEqual(
                    internal.taproot_tweak(merkle_root).xonly(),
                    unhexlify(intermediary["tweakedPubkey"]),
                )
                script_pubkey = p2tr(internal, tree)
                self.assertEqual(
                    script_pubkey.data, unhexlify(expected["scriptPubKey"])
                )
                address = expected["bip350Address"]
                self.assertEqual(script_pubkey.address(NETWORKS["main"]), address)
                self.assertEqual(address_to_scriptpubkey(address), script_pubkey)

    def test_key_path_sighashes(self):
        """Each input's sighash, computed by Transaction and by PSBTView, and
        the vector's signature for it, for every hash type in the vectors."""
        for case in BIP341["keyPathSpending"]:
            given = case["given"]
            tx = Transaction.parse(unhexlify(given["rawUnsignedTx"]))
            utxos = [
                TransactionOutput(u["amountSats"], Script(unhexlify(u["scriptPubKey"])))
                for u in given["utxosSpent"]
            ]
            scripts = [utxo.script_pubkey for utxo in utxos]
            values = [utxo.value for utxo in utxos]
            psbt = PSBT(tx)
            for inp, utxo in zip(psbt.inputs, utxos):
                inp.witness_utxo = utxo
            view = PSBTView.view(BytesIO(psbt.serialize()))
            for spend in case["inputSpending"]:
                i = spend["given"]["txinIndex"]
                hash_type = spend["given"]["hashType"]
                expected = unhexlify(spend["intermediary"]["sigHash"])
                with self.subTest(input=i, hash_type=hash_type):
                    for sighash in (tx.sighash_taproot, view.sighash_taproot):
                        self.assertEqual(
                            sighash(i, scripts, values, sighash=hash_type), expected
                        )
                    sig = unhexlify(spend["expected"]["witness"][0])
                    output_key = ec.PublicKey.from_xonly(scripts[i].data[2:])
                    self.assertTrue(
                        output_key.schnorr_verify(ec.SchnorrSig(sig[:64]), expected)
                    )

    def test_key_path_signatures(self):
        """Each input's tweaked private key, and the vector's signature made
        again with it and BIP341's all-zero aux_rand."""
        for case in BIP341["keyPathSpending"]:
            utxos = case["given"]["utxosSpent"]
            for spend in case["inputSpending"]:
                given, intermediary = spend["given"], spend["intermediary"]
                i = given["txinIndex"]
                with self.subTest(input=i, hash_type=given["hashType"]):
                    key = ec.PrivateKey(unhexlify(given["internalPrivkey"]))
                    self.assertEqual(
                        key.xonly(), unhexlify(intermediary["internalPubkey"])
                    )
                    tweaked = key.taproot_tweak(unhexlify(given["merkleRoot"] or ""))
                    # embit returns the even-Y form, which BIP341 doesn't
                    # negate: the output key and the signatures are the same
                    secret = int.from_bytes(tweaked.secret, "big")
                    expected = int(intermediary["tweakedPrivkey"], 16)
                    self.assertIn(secret, (expected, N - expected))
                    self.assertEqual(
                        tweaked.xonly(), unhexlify(utxos[i]["scriptPubKey"])[2:]
                    )
                    sighash = unhexlify(intermediary["sigHash"])
                    sig = unhexlify(spend["expected"]["witness"][0])
                    self.assertEqual(
                        secp256k1.schnorrsig_sign(
                            sighash, tweaked.secret, None, bytes(32)
                        ),
                        sig[:64],
                    )

    def test_fully_signed_transaction(self):
        """The signed transaction serializes back and holds the witnesses."""
        for case in BIP341["keyPathSpending"]:
            signed = unhexlify(case["auxiliary"]["fullySignedTx"])
            tx = Transaction.parse(signed)
            self.assertEqual(tx.serialize(), signed)
            for spend in case["inputSpending"]:
                witness = tx.vin[spend["given"]["txinIndex"]].witness
                self.assertEqual(
                    witness.items,
                    [unhexlify(item) for item in spend["expected"]["witness"]],
                )
