"""Regression tests for malformed input, found by review and by test_fuzz.py.

Each test names the defect it covers. Before its fix every input here raised
an exception outside the error contract (EmbitError or ValueError), hung or
returned an unusable value.
"""

from binascii import hexlify
from io import BytesIO
from unittest import TestCase

from embit import base58, bech32, ec
from embit.base import EmbitBase, EmbitError
from embit.bip32 import HARDENED_INDEX, HDError, HDKey, parse_path
from embit.descriptor import Descriptor
from embit.descriptor.arguments import AllowedDerivation
from embit.descriptor.checksum import add_checksum, checksum
from embit.descriptor.errors import DescriptorError
from embit.psbt import PSBT, InputScope, OutputScope
from embit.script import Witness
from embit.transaction import Transaction, TransactionInput
from embit.script import address_to_scriptpubkey
from embit.slip39 import Share, ShareSet, rs1024_create_checksum
from embit.wordlists.slip39 import SLIP39_WORDS

XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Ru"
    "pje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)


class RegressionTest(TestCase):
    def test_hdkey_short_input(self):
        """D4: IndexError for an extended key shorter than 78 bytes."""
        raw = base58.decode_check(XPUB)
        self.assertEqual(HDKey.parse(raw).to_base58(), XPUB)
        for n in range(len(raw)):
            with self.assertRaises(HDError):
                HDKey.parse(raw[:n])
            with self.assertRaises(HDError):
                HDKey.from_base58(base58.encode_check(raw[:n]))

    def test_empty_derivation_element(self):
        """D5: IndexError for an empty element in a derivation path."""
        for path in ("m//1", "/", "", "m/0//1", "m/h/1"):
            with self.assertRaises((HDError, ValueError)):
                parse_path(path)
        self.assertEqual(parse_path("m/"), [])
        for der in ("/0//1", "//*", "/<0;;1>/*", "/<>/*", "/0/"):
            with self.assertRaises(DescriptorError):
                Descriptor.from_string("wpkh(%s%s)" % (XPUB, der))
        with self.assertRaises(EmbitError):
            Descriptor.from_string("wpkh([deadbeef//1]%s)" % XPUB)

    def test_derivation_index_range(self):
        """Out-of-range indexes used to parse and fail later with OverflowError,
        and -1h became the non-hardened index 2^31 - 1."""
        for path in ("m/-1", "m/-1h", "m/2147483648h", "m/4294967296"):
            with self.assertRaises(HDError):
                parse_path(path)
        root = HDKey.from_base58(XPUB)
        with self.assertRaises(HDError):
            root.derive("m/-1")
        self.assertEqual(parse_path("m/2147483647h/4294967295"), [2**32 - 1] * 2)
        # a non-hardened index in the hardened range keeps working
        self.assertEqual(parse_path("m/2147483648"), [HARDENED_INDEX])

    def test_derivation_depth_and_index(self):
        """D12: depth 256 raised ValueError from bytes([256]), only after
        the child key was computed; a negative index raised OverflowError."""
        key = HDKey.from_base58(XPUB)
        key.depth = 254
        child = key.child(7)
        self.assertEqual(child.depth, 255)
        for parent in (child, HDKey.parse(child.serialize())):
            with self.assertRaises(HDError):
                parent.child(0)
            with self.assertRaises(HDError):
                parent.derive([0])
        for index in (-1, 2**32):
            with self.assertRaises(HDError):
                key.child(index)

    def test_signature_short_input(self):
        """ec.Signature.read_from() indexed a short read: IndexError."""
        sig = ec.PrivateKey(b"\x11" * 32).sign(b"\x22" * 32).serialize()
        self.assertEqual(ec.Signature.parse(sig).serialize(), sig)
        for n in range(len(sig)):
            with self.assertRaises((ec.ECError, ValueError)):
                ec.Signature.parse(sig[:n])
        for n in (0, 1):
            with self.assertRaises(ec.ECError):
                ec.Signature.parse(sig[:n])

    def test_base58_address_prefix_and_length(self):
        """D8: unknown prefixes returned None, any payload length went into
        the script."""
        h = bytes(range(20))
        for prefix, script in ((b"\x00", "76a914%s88ac"), (b"\xc4", "a914%s87")):
            addr = base58.encode_check(prefix + h)
            sc = address_to_scriptpubkey(addr)
            self.assertEqual(hexlify(sc.data).decode(), script % hexlify(h).decode())
            for payload in (prefix, prefix + h[:5], prefix + h + b"\x00"):
                with self.assertRaises(EmbitError):
                    address_to_scriptpubkey(base58.encode_check(payload))
        # Litecoin's p2pkh prefix and an empty payload
        for payload in (b"\x30" + h, b""):
            with self.assertRaises(EmbitError):
                address_to_scriptpubkey(base58.encode_check(payload))

    def test_uppercase_bech32_address(self):
        """BIP173 allows all-uppercase addresses; they were rejected because
        the human-readable part was compared in upper case."""
        for addr, script in (
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            (
                "TB1QRP33G0Q5C5TXSP9ARYSRX4K6ZDKFS4NCE4XJ0GDCCCEFVPYSXF3Q0SL5K7",
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            ),
        ):
            for s in (addr, addr.lower()):
                self.assertEqual(
                    hexlify(address_to_scriptpubkey(s).data).decode(), script
                )
            # mixed case stays invalid
            with self.assertRaises(EmbitError):
                address_to_scriptpubkey(addr[:3].lower() + addr[3:])

    def test_bech32_address_network(self):
        """A bech32 address whose human-readable part belongs to no known
        network, like BIP173's and BIP350's tc1 vectors, returned a script."""
        for ver, prog, prefix in (
            (0, bytes(range(20)), "0014"),
            (1, bytes(range(32)), "5120"),
        ):
            script = prefix + hexlify(prog).decode()
            for hrp in ("bc", "tb", "bcrt"):
                sc = address_to_scriptpubkey(bech32.encode(hrp, ver, prog))
                self.assertEqual(hexlify(sc.data).decode(), script)
            # BIP173's invalid example, Litecoin and Liquid
            for hrp in ("tc", "ltc", "ex"):
                with self.assertRaises(EmbitError):
                    address_to_scriptpubkey(bech32.encode(hrp, ver, prog))

    def test_slip39_share_length(self):
        """Shares with a valid checksum but too few words raised IndexError,
        more than 8 bits of padding were accepted and bad padding raised
        SyntaxError."""
        share = (
            "duckling enlarge academic academic agency result length solution "
            "fridge kidney coal piece deal husband erode duke ajar critical "
            "decision keyboard"
        )
        self.assertEqual(Share.parse(share).mnemonic(), share)
        data = [SLIP39_WORDS.index(w) for w in share.split()[:-3]]

        def mnemonic(data):
            indices = data + rs1024_create_checksum(b"shamir", data)
            return " ".join(SLIP39_WORDS[i] for i in indices)

        for bad in (
            [],
            data[:4],
            data[:-1],
            # a zero word: valid padding bits, but 12 of them
            data[:4] + [0] + data[4:],
            # a non-zero padding bit
            data[:4] + [data[4] | 512] + data[5:],
        ):
            with self.assertRaises(ValueError):
                Share.parse(mnemonic(bad))

    def test_slip39_share_set(self):
        """An empty share list and a group index at or above the group count
        raised IndexError; shares of different secrets raised TypeError."""
        share = Share.parse(
            "duckling enlarge academic academic agency result length solution "
            "fridge kidney coal piece deal husband erode duke ajar critical "
            "decision keyboard"
        )
        with self.assertRaises(ValueError):
            ShareSet.recover_mnemonic([])
        # 1-of-1 group 5 of a 1-of-2 group split: a valid x coordinate
        moved = Share(
            share.share_bit_length, share.id, share.exponent, 5, 1, 2, 0, 1, share.value
        )
        self.assertEqual(
            ShareSet.recover_mnemonic([moved.mnemonic()]),
            ShareSet.recover_mnemonic([share.mnemonic()]),
        )
        other = Share(
            share.share_bit_length,
            share.id ^ 1,
            share.exponent,
            1,
            2,
            2,
            0,
            1,
            share.value,
        )
        mine = Share(
            share.share_bit_length, share.id, share.exponent, 0, 2, 2, 0, 1, share.value
        )
        with self.assertRaises(ValueError):
            ShareSet.recover_mnemonic([mine.mnemonic(), other.mnemonic()])

    def test_mutable_defaults_are_not_shared(self):
        """D7: default dicts and lists were shared by every instance, so state
        leaked between unrelated objects."""
        for cls in (InputScope, OutputScope, PSBT):
            a, b = cls(), cls()
            self.assertTrue(a.unknown is not b.unknown)
            a.unknown[b"\xfc"] = b"x"
            self.assertEqual(cls().unknown, {})
        # an unknown key read into one scope made the next one report a duplicate
        InputScope().read_value(BytesIO(b"\x01x"), b"\xf0")
        InputScope().read_value(BytesIO(b"\x01y"), b"\xf0")
        tx = Transaction()
        tx.vin.append(TransactionInput(bytes(32), 0))
        self.assertEqual(Transaction().vin, [])
        self.assertEqual(Transaction().vout, [])
        Witness().items.append(b"x")
        self.assertEqual(Witness().items, [])
        AllowedDerivation().indexes[0].append(2)
        self.assertEqual(AllowedDerivation().indexes, [[0, 1], None])

    def test_slip39_share_without_padding(self):
        """mnemonic() added 10 bits of padding to 160-bit shares, which need
        none, and produced 24 words that don't parse back."""
        data = [5, 6, 7, 8] + [i * 37 % 1024 for i in range(16)]
        share = " ".join(
            SLIP39_WORDS[i] for i in data + rs1024_create_checksum(b"shamir", data)
        )
        parsed = Share.parse(share)
        self.assertEqual(parsed.share_bit_length, 160)
        self.assertEqual(parsed.mnemonic(), share)
        self.assertEqual(Share.parse(parsed.mnemonic()).value, parsed.value)

    def test_repr_does_not_swallow_interrupts(self):
        """D9: bare except clauses also caught KeyboardInterrupt."""

        class Broken(EmbitBase):
            def __init__(self, exc):
                self.exc = exc

            def to_string(self):
                raise self.exc

        self.assertEqual(repr(Broken(ValueError("x"))), "Broken()")
        with self.assertRaises(KeyboardInterrupt):
            repr(Broken(KeyboardInterrupt()))

    def test_generate_privkey_uses_os_randomness(self):
        """D10: the pure-Python key generator drew keys from `random`."""
        from embit import misc
        from embit.util import key

        urandom = misc.urandom
        misc.urandom = lambda n: b"\x01" * n
        try:
            secret = key.generate_privkey()
        finally:
            misc.urandom = urandom
        self.assertEqual(secret, b"\x01" * 31 + b"\x02")
        self.assertTrue(key.generate_privkey() != key.generate_privkey())

    def test_miniscript_numbers(self):
        """An empty number was read as 0, so tr(K,older()) parsed as older(0);
        out-of-range numbers parsed and only some were rejected later."""
        key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        for ms in ("older()", "after()", "older(2147483648)", "older(1x)"):
            for desc in ("wsh(%s)" % ms, "tr(%s,%s)" % (key, ms)):
                with self.assertRaises(DescriptorError):
                    Descriptor.from_string(desc)
        desc = Descriptor.from_string("wsh(older(000002147483647))")
        self.assertEqual(str(desc), "wsh(older(2147483647))")

    def test_multisig_key_limits(self):
        """multi() and multi_a() took any number of keys. Bitcoin Core allows
        at most 20 (MAX_PUBKEYS_PER_MULTISIG) and 999 (MAX_PUBKEYS_PER_MULTI_A)."""

        def keys(n):
            return ",".join("%s/%d" % (XPUB, i) for i in range(n))

        for fn, limit, template in (
            ("multi", 20, "wsh(%s(1,%s))"),
            ("sortedmulti", 20, "sh(wsh(%s(1,%s)))"),
            ("multi_a", 999, "tr(%s,%%s(1,%%s))" % XPUB),
            ("sortedmulti_a", 999, "tr(%s,{pk(%s),%%s(1,%%s)})" % (XPUB, XPUB)),
        ):
            desc = Descriptor.from_string(template % (fn, keys(limit)))
            self.assertEqual(str(desc), template % (fn, keys(limit)))
            with self.assertRaises(DescriptorError):
                Descriptor.from_string(template % (fn, keys(limit + 1)))

    def test_taproot_leaves_are_type_checked(self):
        """Taproot leaves skipped the miniscript type checks that wsh() runs, so
        unsatisfiable or invalid leaves parsed into unspendable outputs, and
        multi_a(1) raised IndexError when the output script was computed."""
        k1 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        k2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        for leaf in (
            "multi_a(2,%s)" % k1,
            "multi_a(0,%s)" % k1,
            "multi_a(1)",
            "sortedmulti_a(1)",
            "and_v(pk(%s),pk(%s))" % (k1, k2),
            "or_b(pk(%s),pk(%s))" % (k1, k2),
            "thresh(3,pk(%s),s:pk(%s))" % (k1, k2),
            "v:pk(%s)" % k1,
        ):
            for tree in (leaf, "{pk(%s),%s}" % (k2, leaf)):
                with self.assertRaises(DescriptorError):
                    Descriptor.from_string("tr(%s,%s)" % (k1, tree))
        # d: is unit-producing only in tapscript, so this leaf is valid there
        leaf = "thresh(2,pk(%s),s:pk(%s),sdv:older(144))" % (k1, k2)
        desc = Descriptor.from_string(
            "tr(%s,{%s,multi_a(1,%s,%s)})" % (k1, leaf, k1, k2)
        )
        self.assertEqual(len(desc.script_pubkey().data), 34)
        with self.assertRaises(DescriptorError):
            Descriptor.from_string(
                "wsh(%s)" % leaf.replace(k1, "02" + k1).replace(k2, "02" + k2)
            )

    def test_taproot_multipath_lengths(self):
        """tr() accepted multipath keys with different numbers of branches,
        which BIP389 rejects, and failed only when the extra branch was used."""
        two, three = XPUB + "/<0;1>/*", XPUB + "/<2;3;4>/*"
        for desc in (
            "tr(%s,pk(%s))" % (two, three),
            "tr(%s,{pk(%s),pk(%s)})" % (XPUB, two, three),
        ):
            with self.assertRaises(DescriptorError):
                Descriptor.from_string(desc)
        # keys without a multipath specifier combine with any length
        desc = Descriptor.from_string(
            "tr(%s,{pk(%s),pk(%s/5/*)})" % (XPUB, three, XPUB)
        )
        self.assertEqual(desc.num_branches, 3)
        self.assertTrue(desc.branch(2).derive(7).address().startswith("bc1p"))

    def test_fixed_derivation_is_applied(self):
        """Scripts and addresses used an extended key itself and ignored a
        fixed derivation after it: wpkh(xpub/0/5) gave the xpub's address."""
        root = HDKey.from_base58(XPUB)
        a = hexlify(root.derive([0, 5]).key.sec()).decode()
        b = hexlify(root.derive([1]).key.sec()).decode()
        for template in (
            "wpkh(%s)",
            "sh(wpkh(%s))",
            "pkh(%s)",
            "wsh(multi(1,%s,%s))",
            "sh(wsh(sortedmulti(1,%s,%s)))",
            "tr(%s,pk(%s))",
        ):
            n = template.count("%s")
            fixed = Descriptor.from_string(
                template % ("%s/0/5" % XPUB, "%s/1" % XPUB)[:n]
            )
            plain = Descriptor.from_string(template % (a, b)[:n])
            self.assertFalse(fixed.is_wildcard)
            self.assertEqual(fixed.script_pubkey(), plain.script_pubkey())
            self.assertEqual(fixed.address(), plain.address())
            self.assertEqual(fixed.witness_script(), plain.witness_script())
            self.assertEqual(fixed.redeem_script(), plain.redeem_script())

    def test_derivation_indexes_are_decimal(self):
        """Indexes went through int(), which also takes signs, spaces,
        underscores and non-ASCII digits: BIP380's invalid [deadbeef/-0]
        parsed as index 0. Key origins also took a trailing slash."""
        for bad in ("-0", "+5", " 5", "5 ", "1_0", "\u0665", "0x5"):
            for path in ("m/%s" % bad, "m/%sh" % bad):
                with self.assertRaises(HDError):
                    parse_path(path)
            for desc in (
                "wpkh([deadbeef/%s]%s)" % (bad, XPUB),
                "wpkh(%s/%s/*)" % (XPUB, bad),
            ):
                with self.assertRaises(EmbitError):
                    Descriptor.from_string(desc)
        with self.assertRaises(DescriptorError):
            Descriptor.from_string("wpkh([deadbeef/0h/]%s)" % XPUB)
        # leading zeros and BIP32 paths with a trailing slash stay valid
        self.assertEqual(parse_path("m/007h/0/"), [HARDENED_INDEX + 7, 0])
        desc = Descriptor.from_string("wpkh([deadbeef/007h]%s/01/*)" % XPUB)
        self.assertEqual(str(desc), "wpkh([deadbeef/7h]%s/1/*)" % XPUB)

    def test_segwit_keys_are_compressed(self):
        """wpkh(), wsh() and tr() took uncompressed keys, which BIP382 and
        BIP386 reject: spending such a P2WPKH or P2WSH output is non-standard."""
        secret = b"\x11" * 32
        wif = ec.PrivateKey(secret, compressed=False).wif()
        loose = hexlify(ec.PrivateKey(secret, compressed=False).sec()).decode()
        tight = hexlify(ec.PrivateKey(secret).sec()).decode()
        for k in (loose, wif):
            for desc in (
                "wpkh(%s)" % k,
                "sh(wpkh(%s))" % k,
                "wsh(pk(%s))" % k,
                "sh(wsh(multi(1,%s,%s)))" % (tight, k),
                "tr(%s)" % k,
                "tr(%s,multi_a(1,%s))" % (tight[2:], k),
            ):
                with self.assertRaises(DescriptorError):
                    Descriptor.from_string(desc)
            # legacy scripts keep taking them
            for desc in ("pkh(%s)" % k, "sh(multi(1,%s,%s))" % (tight, k)):
                self.assertTrue(Descriptor.from_string(desc).address())

    def test_script_size_limits(self):
        """sh() took redeem scripts above the 520 bytes consensus lets a P2SH
        spend push, so its outputs could never be spent, and wsh() witness
        scripts above Bitcoin Core's 3600 bytes, which policy doesn't relay."""
        keys = ["%s/%d" % (XPUB, i) for i in range(98)]
        loose = [
            hexlify(ec.PrivateKey(bytes([i + 1]) * 32, compressed=False).sec())
            for i in range(8)
        ]
        loose = [k.decode() for k in loose]
        # 15 compressed keys take 513 bytes, 7 uncompressed ones 465
        for fit, extra in ((keys[:15], keys[15]), (loose[:7], loose[7])):
            for fn in ("multi", "sortedmulti"):
                desc = Descriptor.from_string("sh(%s(1,%s))" % (fn, ",".join(fit)))
                self.assertTrue(len(desc.redeem_script().data) <= 520)
                with self.assertRaises(DescriptorError):
                    Descriptor.from_string(
                        "sh(%s(1,%s))" % (fn, ",".join(fit + [extra]))
                    )

        def thresh(n):
            subs = ",".join("s:pk(%s)" % k for k in keys[1:n])
            return "thresh(1,pk(%s),%s)" % (keys[0], subs)

        for template in ("wsh(%s)", "sh(wsh(%s))"):
            desc = Descriptor.from_string(template % thresh(97))
            self.assertEqual(len(desc.witness_script().data), 3589)
            with self.assertRaises(DescriptorError):
                Descriptor.from_string(template % thresh(98))

    def test_descriptor_checksum(self):
        """BIP380: whatever followed '#' was ignored, so a descriptor changed
        after its checksum was computed still parsed."""
        desc = "wpkh(%s/0/*)" % XPUB
        good = add_checksum(desc)
        for s in (desc, good):
            self.assertEqual(str(Descriptor.from_string(s)), desc)
        payload, check = good.split("#")
        changed = payload.replace("/0/*", "/1/*")
        for bad in (
            changed + "#" + check,
            payload + "#" + checksum(changed),
            payload + "#" + check.upper(),
            payload + "#" + check[:7],
            payload + "#" + check + "q",
            payload + "#",
            good + "#" + check,
        ):
            with self.assertRaises(DescriptorError):
                Descriptor.from_string(bad)
