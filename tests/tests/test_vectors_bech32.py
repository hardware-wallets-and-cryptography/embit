"""BIP173 and BIP350 test vectors, see data/vectors/README.md. CPython only.

The vectors are the <tt> items of the lists in each BIP's text. Addresses are
checked under BIP350's rules: its Bech32m checksums replace Bech32 for
witness versions 1 to 16, so BIP173's valid addresses of those versions are
invalid now.

address_to_scriptpubkey() takes witness version 0 and Taproot (version 1, 32
bytes). The valid addresses of other versions and sizes are skipped while it
rejects them; they still decode.
"""

import os
import re
from binascii import unhexlify
from unittest import TestCase

from embit import bech32
from embit.base import EmbitError
from embit.script import address_to_scriptpubkey

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors", "bitcoin-bips")

# "* <tt>a12uel5l</tt>", "* 0x20 + <tt>1nwldj5</tt>: reason",
# "* <tt>de1lg7wt</tt> + 0xFF: reason", "* <tt>address</tt>: <tt>script</tt>"
ITEM = re.compile(
    r"\* (?:0x([0-9A-F]{2}) \+ )?<tt>([^<]*)</tt>(?: \+ 0x([0-9A-F]{2}))?(?:: (.*))?"
)
LISTS = {
    "The following strings are valid": "valid",
    "The following string are not valid": "invalid",
    "The following list gives valid segwit addresses": "valid addresses",
    "The following list gives invalid segwit addresses": "invalid addresses",
}


def load_lists(name):
    """Each test vector list of a BIP, as (string, rest of the line) pairs."""
    lists = {}
    current = None
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        for line in f:
            if line.startswith("="):
                current = None
            for lead, key in LISTS.items():
                if line.startswith(lead):
                    current = lists.setdefault(key, [])
            match = ITEM.match(line)
            if match and current is not None:
                before, text, after, rest = match.groups()
                if before:
                    text = chr(int(before, 16)) + text
                if after:
                    text += chr(int(after, 16))
                current.append((text, rest))
    return lists


BIP173 = load_lists("bip-0173.mediawiki")
BIP350 = load_lists("bip-0350.mediawiki")


def script_pubkey(rest):
    """The scriptPubKey of a valid address, from "<tt>hex</tt>"."""
    return unhexlify(re.match("<tt>([0-9a-f]+)</tt>$", rest).group(1))


class Bech32Test(TestCase):
    def test_every_vector_is_read(self):
        for lists, sizes in ((BIP173, (7, 12, 6, 10)), (BIP350, (7, 14, 8, 15))):
            self.assertEqual(tuple(len(lists[key]) for key in LISTS.values()), sizes)

    def test_strings(self):
        for lists, encoding in (
            (BIP173, bech32.Encoding.BECH32),
            (BIP350, bech32.Encoding.BECH32M),
        ):
            for string, _ in lists["valid"]:
                with self.subTest(valid=string):
                    decoded, hrp, data = bech32.bech32_decode(string)
                    self.assertEqual(decoded, encoding)
                    self.assertEqual(
                        bech32.bech32_encode(encoding, hrp, data), string.lower()
                    )
            for string, reason in lists["invalid"]:
                with self.subTest(invalid=string, reason=reason):
                    self.assertEqual(bech32.bech32_decode(string), (None, None, None))

    def test_valid_addresses(self):
        # BIP173's addresses of version 1+ are in test_invalid_addresses
        addresses = [
            item for item in BIP173["valid addresses"] if script_pubkey(item[1])[0] == 0
        ]
        for address, rest in addresses + BIP350["valid addresses"]:
            expected = script_pubkey(rest)
            hrp = address[: address.rfind("1")].lower()
            with self.subTest(address=address):
                version, program = bech32.decode(hrp, address)
                op = version + 0x50 if version else 0
                self.assertEqual(bytes([op, len(program)] + program), expected)
                self.assertEqual(bech32.encode(hrp, version, program), address.lower())
                if version == 0 or (version == 1 and len(program) == 32):
                    self.assertEqual(address_to_scriptpubkey(address).data, expected)
                else:
                    with self.assertRaises(EmbitError, msg="remove this skip"):
                        address_to_scriptpubkey(address)
                    self.skipTest("only witness v0 and Taproot addresses are taken")

    def test_invalid_addresses(self):
        cases = BIP173["invalid addresses"] + BIP350["invalid addresses"]
        for address, rest in BIP173["valid addresses"]:
            if script_pubkey(rest)[0] != 0:
                cases.append((address, "Bech32 for witness version 1+ (BIP350)"))
        for address, reason in cases:
            with self.subTest(address=address, reason=reason):
                for hrp in ("bc", "tb"):
                    self.assertEqual(bech32.decode(hrp, address), (None, None))
                with self.assertRaises(EmbitError):
                    address_to_scriptpubkey(address)
