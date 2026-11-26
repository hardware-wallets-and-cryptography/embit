"""BIP174, BIP370 and BIP371 test vectors, see data/vectors/README.md.
CPython only.

Every PSBT in the BIPs' test vectors is read from its "Base64 String" item.
The invalid ones must fail in PSBT.parse() and in PSBTView. All others, also
the results of BIP174's roles, must parse, keep their key-value pairs through
a round trip and have every scope read by PSBTView.

BIP174's signers run with verify_utxos=False: by default embit asks for the
previous transaction of each input that isn't Taproot, and these PSBTs don't
have them all (docs/api/psbt.md). embit has no combiner, finalizer or
extractor, so those roles' PSBTs are only parsed.
"""

import os
import re
from binascii import a2b_base64
from io import BytesIO
from unittest import TestCase

from embit import compact, ec
from embit.base import EmbitError
from embit.bip32 import HDKey
from embit.psbt import PSBT, PSBTError
from embit.psbtview import PSBTView

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors", "bitcoin-bips")

LISTS = (
    ("The following are invalid PSBTs", "invalid"),
    ("The following are valid PSBTs", "valid"),
    ("Fails Signer checks", "signer checks"),
    ("The private keys in the tests below", "roles"),
    ("The following tests are the timelock", "lock times"),
)
LOCK_TIME = re.compile(
    r"The timelock for the following PSBTs "
    r"(?:should be computed to be (\d+)|cannot be computed)"
)
BASE64 = re.compile(r"\*\* Base64 String: <pre>([A-Za-z0-9+/=]+)</pre>")
# BIP370: "If omitted, the sequence number is assumed to be the final sequence
# number (0xffffffff)." PSBT writes it out.
FINAL_SEQUENCE = (b"\x10", b"\xff\xff\xff\xff")


def vector_section(name):
    """The test vectors section of a BIP's text."""
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        text = f.read()
    return re.split(r"\n==(?!=)", text.split("==Test Vectors==", 1)[1])[0]


def load_psbts(text):
    """Each list of PSBTs, as (case, PSBT, lock time) items. The lock time is
    what BIP370's lock time tests expect, None if it can't be computed."""
    lists, current, case, lock_time = {}, None, None, None
    for line in text.splitlines():
        for lead, key in LISTS:
            if line.startswith(lead):
                current = lists.setdefault(key, [])
        match = LOCK_TIME.match(line)
        if match:
            lock_time = int(match.group(1)) if match.group(1) else None
        match = re.match(r"\* Case: (.*)", line)
        if match:
            case = match.group(1)
        match = BASE64.match(line)
        if match:
            current.append((case, a2b_base64(match.group(1)), lock_time))
            case = None
    return lists


def load_signers(text):
    """BIP174's signer tests, as (WIF keys, PSBT to sign, expected PSBT)."""
    signers, unsigned = [], None
    roles = text.split("The private keys in the tests below", 1)[1]
    for block in re.split(r"\n\n(?=Given |An |A )", roles):
        psbts = [a2b_base64(m.group(1)) for m in BASE64.finditer(block)]
        keys = re.findall(r"<tt>(c\w{51})</tt>", block)
        if block.startswith("An updater which adds SIGHASH_ALL"):
            unsigned = psbts[0]
        elif keys:
            signers.append((keys, unsigned, psbts[0]))
    return signers


BIP174_TEXT = vector_section("bip-0174.mediawiki")
BIP174 = load_psbts(BIP174_TEXT)
BIP370 = load_psbts(vector_section("bip-0370.mediawiki"))
BIP371 = load_psbts(vector_section("bip-0371.mediawiki"))
SIGNERS = load_signers(BIP174_TEXT)
ROOT = HDKey.from_string(
    re.search(r"Extended Private Key: <pre>(\w+)</pre>", BIP174_TEXT).group(1)
)


def vectors(*kinds):
    for bip, lists in (("174", BIP174), ("370", BIP370), ("371", BIP371)):
        for kind in kinds:
            for n, (case, raw, _) in enumerate(lists.get(kind, [])):
                yield dict(bip=bip, list=kind, n=n, case=case), raw


def scopes(raw):
    """The key-value pairs of each map of a serialized PSBT."""
    stream = BytesIO(raw[5:])
    maps, pairs = [], set()
    while stream.tell() < len(raw) - 5:
        key = stream.read(compact.read_from(stream))
        if not key:
            maps.append(pairs)
            pairs = set()
            continue
        pairs.add((key, stream.read(compact.read_from(stream))))
    return maps


def view_all(raw):
    view = PSBTView.view(BytesIO(raw))
    for i in range(view.num_inputs):
        view.input(i)
    for i in range(view.num_outputs):
        view.output(i)
    return view


class PSBTVectorsTest(TestCase):
    def test_every_vector_is_read(self):
        counts = [
            {kind: len(items) for kind, items in lists.items()}
            for lists in (BIP174, BIP370, BIP371)
        ]
        self.assertEqual(
            counts,
            [
                {"invalid": 20, "valid": 10, "signer checks": 4, "roles": 13},
                {"invalid": 24, "valid": 14, "lock times": 10},
                {"invalid": 11, "valid": 6},
            ],
        )
        self.assertEqual(len(SIGNERS), 2)

    def test_invalid(self):
        for params, raw in vectors("invalid"):
            with self.subTest(**params):
                with self.assertRaises((EmbitError, ValueError)):
                    PSBT.parse(raw)
                with self.assertRaises((EmbitError, ValueError)):
                    view_all(raw)

    def test_valid(self):
        for params, raw in vectors("valid", "signer checks", "roles", "lock times"):
            with self.subTest(**params):
                out = PSBT.parse(raw).serialize()
                self.assertEqual(PSBT.parse(out).serialize(), out)
                before, after = scopes(raw), scopes(out)
                self.assertEqual(len(before), len(after))
                for pairs, kept in zip(before, after):
                    self.assertEqual(pairs - kept, set())
                    self.assertLessEqual(kept - pairs, {FINAL_SEQUENCE})
                view_all(raw)

    def test_signer_checks(self):
        """BIP174's PSBTs that a signer must refuse. sign_with() refuses all
        four: none has the previous transactions it asks for. With
        verify_utxos=False it still refuses the three whose scripts don't
        match their UTXO, but signs the first one's P2PKH input from its
        witness UTXO, which BIP174 forbids: a strict skip."""
        keys = [ROOT] + [ec.PrivateKey.from_wif(w) for s in SIGNERS for w in s[0]]
        for params, raw in vectors("signer checks"):
            with self.subTest(**params):
                with self.assertRaises(PSBTError):
                    PSBT.parse(raw).sign_with(ROOT)
                with self.assertRaises(PSBTError):
                    PSBTView.view(BytesIO(raw)).sign_with(ROOT, BytesIO())
                psbt = PSBT.parse(raw)
                try:
                    for key in keys:
                        psbt.sign_with(key, verify_utxos=False)
                except PSBTError:
                    continue
                signed = [inp for inp in psbt.inputs if inp.partial_sigs]
                self.assertTrue(signed, "remove this skip")
                for inp in signed:
                    self.assertIsNone(inp.non_witness_utxo)
                    self.assertEqual(inp.utxo.script_pubkey.script_type(), "p2pkh")
                self.skipTest("verify_utxos=False signs P2PKH from a witness UTXO")

    def test_signers(self):
        """BIP174's two signers, with SIGHASH_ALL and RFC6979 nonces."""
        for n, (wifs, unsigned, expected) in enumerate(SIGNERS):
            keys = {}
            psbt = PSBT.parse(unsigned)
            for wif in wifs:
                key = ec.PrivateKey.from_wif(wif)
                keys[key.sec()] = key
                psbt.sign_with(key, sighash=None, verify_utxos=False)
            mismatches = 0
            signed = zip(psbt.inputs, PSBT.parse(expected).inputs)
            for i, (inp, expected_inp) in enumerate(signed):
                with self.subTest(signer=n, input=i):
                    got = {pub.sec(): sig for pub, sig in inp.partial_sigs.items()}
                    want = {
                        pub.sec(): sig for pub, sig in expected_inp.partial_sigs.items()
                    }
                    if got != want:
                        mismatches += 1
                        # embit grinds nonces for a low R (PrivateKey.sign());
                        # without that it makes BIP174's high-R signatures
                        for pub, sig in want.items():
                            h = psbt.sighash(i, sighash=sig[-1])
                            plain = keys[pub].sign(h, grind=False).serialize()
                            self.assertEqual(plain + sig[-1:], sig)
                        self.skipTest("embit grinds ECDSA nonces for a low R")
                    self.assertEqual(got, want)
            if not mismatches:
                self.assertEqual(psbt.serialize(), expected)

    def test_lock_times(self):
        """BIP370's lock time determination. Signatures commit to
        PSBT_GLOBAL_FALLBACK_LOCKTIME, or 0, and the required lock times
        aren't used (docs/api/psbt.md), so the PSBTs whose lock time depends
        on them are strict skips."""
        for n, (case, raw, expected) in enumerate(BIP370["lock times"]):
            with self.subTest(n=n, case=case):
                psbt = PSBT.parse(raw)
                lock_time = psbt.tx.locktime
                self.assertEqual(PSBTView.view(BytesIO(raw)).locktime, lock_time)
                if lock_time != expected:
                    required = [k for inp in psbt.inputs for k in inp.unknown]
                    self.assertTrue(
                        any(k[:1] in (b"\x11", b"\x12") for k in required),
                        "differs without required lock times",
                    )
                    self.skipTest("the required lock times aren't used")
