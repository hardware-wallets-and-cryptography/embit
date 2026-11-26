"""BIP380 to BIP390 descriptor test vectors, see data/vectors/README.md.
CPython only.

BIP380's key expressions go through Key.from_string(), the other BIPs'
descriptors through Descriptor.from_string(). A valid descriptor must give the
scripts listed under it, for indexes 0, 1 and 2 if it is ranged, and a BIP389
multipath descriptor the scripts of each descriptor it expands into. An
invalid one must raise; those of forms embit doesn't support pass because the
form is rejected.

A valid vector that embit rejects is skipped only for one of the reasons in
REJECTED, and an invalid one that it accepts only for an uppercase H.
"""

import os
import re
from unittest import TestCase

from embit.base import EmbitError
from embit.descriptor import Descriptor
from embit.descriptor.arguments import Key
from embit.descriptor.checksum import check_checksum
from embit.descriptor.errors import DescriptorError

VECTORS = os.path.join(os.path.dirname(__file__), "data", "vectors", "bitcoin-bips")
BIPS = ("380", "381", "382", "383", "384", "385", "386", "387", "389", "390")
TT = re.compile(r"<tt>(.*?)</tt>")


def mixes_multipath(desc):
    """Whether sh() or wsh() has extended keys with and without multipath."""
    keys = re.findall(r"[xt](?:pub|prv)\w+[^,)]*", desc)
    has_multipath = {"<" in key for key in keys}
    return desc.startswith(("sh(", "wsh(")) and has_multipath == {True, False}


# The reasons a valid vector may be rejected: forms embit doesn't support,
# and the BIP389 rule that sh() and wsh() apply more strictly
REJECTED = (
    (lambda d: d.startswith("pk("), "top-level pk() isn't supported"),
    (
        lambda d: d.startswith(("multi(", "sortedmulti(")),
        "top-level multi() and sortedmulti() aren't supported",
    ),
    (
        lambda d: d.startswith(("combo(", "raw(", "addr(")),
        "combo(), raw() and addr() aren't supported",
    ),
    (
        lambda d: "musig(" in d or d.startswith("rawtr("),
        "musig() and rawtr() aren't supported",
    ),
    (
        lambda d: re.search(r"pub\w+(/\d+)*/\d+[h']", d),
        "hardened steps after an extended public key aren't supported",
    ),
    (lambda d: re.search(r"\*[h']", d), "hardened wildcards aren't supported"),
    (mixes_multipath, "sh() and wsh() take multipath in all extended keys or none"),
)


def vector_section(name):
    """The test vectors section of a BIP's text."""
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        text = f.read()
    return re.split(r"\n==(?!=)", text.split("==Test Vectors==", 1)[1])[0]


def load_vectors(bip):
    """A BIP's vectors, as (list, label, descriptor, expected) items. The list
    is named by the last lead-in line: valid, invalid or checksum. "expected"
    holds the items under the descriptor: its scripts, or for BIP389 the
    descriptors it expands into."""
    items, kind = [], None
    for line in vector_section("bip-0%s.mediawiki" % bip).splitlines():
        line = line.strip()
        if not line.startswith("*"):
            lead = line.lower()
            for word in ("invalid", "valid", "checksum"):
                if word in lead:
                    kind = word
                    break
            continue
        tts = TT.findall(line)
        if not tts:
            continue
        if line.startswith("**"):
            items[-1][3].append(tts[-1])
        else:
            label = re.sub("</?tt>", "", line[1:].rsplit("<tt>", 1)[0]).strip(" :")
            items.append((kind, label, tts[-1], []))
    return items


VECTORS_BY_BIP = {bip: load_vectors(bip) for bip in BIPS}


def parse(bip, desc):
    return Key.from_string(desc) if bip == "380" else Descriptor.from_string(desc)


def script_pubkeys(desc, count):
    """The scripts of a descriptor, or of its first indexes if it is ranged."""
    if desc.is_wildcard:
        return [desc.derive(i).script_pubkey().data.hex() for i in range(count)]
    return [desc.script_pubkey().data.hex()]


def vectors(kind):
    for bip, items in VECTORS_BY_BIP.items():
        for n, (item_kind, label, desc, expected) in enumerate(items):
            if item_kind == kind:
                yield dict(bip=bip, n=n, label=label), desc, expected


class DescriptorVectorsTest(TestCase):
    def test_every_vector_is_read(self):
        counts = {}
        for items in VECTORS_BY_BIP.values():
            for kind, _, _, _ in items:
                counts[kind] = counts.get(kind, 0) + 1
        self.assertEqual(counts, {"checksum": 8, "valid": 91, "invalid": 77})

    def test_valid(self):
        for params, desc, expected in vectors("valid"):
            with self.subTest(**params):
                try:
                    parsed = parse(params["bip"], desc)
                except (EmbitError, ValueError):
                    reasons = [why for applies, why in REJECTED if applies(desc)]
                    self.assertTrue(reasons, "rejected for another reason")
                    self.skipTest(reasons[0])
                if params["bip"] == "389":
                    self.assertEqual(parsed.num_branches, len(expected))
                    for i, branch in enumerate(expected):
                        self.assertEqual(
                            script_pubkeys(parsed.branch(i), 3),
                            script_pubkeys(Descriptor.from_string(branch), 3),
                        )
                elif expected:
                    self.assertEqual(script_pubkeys(parsed, len(expected)), expected)

    def test_invalid(self):
        for params, desc, _ in vectors("invalid"):
            with self.subTest(**params):
                try:
                    parse(params["bip"], desc)
                except (EmbitError, ValueError):
                    continue
                self.assertRegex(desc, r"/\d+H", "accepted")
                self.skipTest("embit accepts H as a hardened indicator")

    def test_checksums(self):
        """BIP380's checksum vectors use raw(), which embit doesn't parse, so
        they go through check_checksum(), which Descriptor.from_string()
        calls."""
        for params, desc, _ in vectors("checksum"):
            with self.subTest(**params):
                if params["label"] in ("Valid checksum", "No checksum"):
                    self.assertEqual(check_checksum(desc), desc.split("#")[0])
                else:
                    with self.assertRaises(DescriptorError):
                        check_checksum(desc)
