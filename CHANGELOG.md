# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `compact.MAX_SIZE` (`0x02000000`, as in Bitcoin Core) and
  `compact.read_size()`, which reads a length or count and checks it against
  `MAX_SIZE`.
- `base58.MAX_DECODE_LENGTH` (1000 characters).
- `MAX_P2SH_SCRIPT_SIZE` (520) and `MAX_P2WSH_SCRIPT_SIZE` (3600) in
  `embit.descriptor.descriptor`, the largest `sh()` and `wsh()` scripts a
  descriptor may compile to.
- `descriptor.checksum.check_checksum()`, which checks a descriptor's BIP380
  checksum, if it has one, and returns the descriptor without it.

### Changed

- `base58.decode()` and everything decoding base58 (keys, WIF, addresses)
  raise `ValueError` for strings longer than `base58.MAX_DECODE_LENGTH`
  instead of decoding them in quadratic time: a 1 MB address took minutes.
- `HDKey.parse()`, `read_from()`, `from_base58()` and `from_string()` raise
  `HDError` for an extended key shorter than 78 bytes. They used to raise
  `IndexError`, or `ECError` when only part of the key was missing.
- `bip32.parse_path()` (and `HDKey.derive()` with a string path, descriptor
  key origins) raises `HDError` for an empty element such as `m//1`, which
  raised `IndexError`, and for indexes outside `[0, 2^32)` or hardened
  indexes outside `[0, 2^31)`. Those parsed before and failed on derivation
  with `OverflowError`; `-1h` was read as the non-hardened index `2^31 - 1`.
- `slip39.Share.parse()` raises `ValueError` instead of `SyntaxError` for
  non-zero padding bits, and `ValueError` for shares shorter than 20 words
  (which raised `IndexError`) or with more than 8 bits of padding (which were
  accepted), as SLIP-0039 requires.
- `slip39.ShareSet` and `ShareSet.recover_mnemonic()` raise `ValueError`
  instead of `TypeError` for shares with different identifiers or iteration
  exponents, and `ValueError` for an empty list of shares, which raised
  `IndexError`.
- `script.address_to_scriptpubkey()` and `Script.from_address()` raise
  `EmbitError` for a base58 address with an unknown version byte, which
  returned `None`, and for a payload that is not 20 bytes, which returned a
  malformed script.
- `script.address_to_scriptpubkey()` and `Script.from_address()` raise
  `EmbitError` for a bech32 or bech32m address whose human-readable part
  belongs to no network in `embit.networks.NETWORKS` (`bc`, `tb`, `bcrt`), as
  Bitcoin Core does. Such addresses, like the `tc1` ones that BIP173 and
  BIP350 list as invalid, returned a script. Liquid addresses are decoded by
  `embit.liquid.addresses.addr_decode()`.
- `ec.Signature.parse()` and `read_from()` raise `ECError` for input shorter
  than two bytes, which raised `IndexError`.
- `HDKey.child()` and `derive()` raise `HDError` before deriving past depth
  255, which raised `ValueError` from the depth byte after the child key was
  computed, and for a negative index, which raised `OverflowError`.
- Descriptors raise `DescriptorError` for an empty derivation index such as
  `xpub.../0//1` or `<0;;1>`, which raised `IndexError`.
- Derivation indexes must be ASCII decimal digits, as BIP32 paths and BIP380
  key expressions are written. `bip32.parse_path()` (and `HDKey.derive()`
  with a string path, descriptor key origins) raises `HDError`, and descriptor
  derivations after a key raise `ArgumentError`, for anything else. Python's
  `int()` let `-0`, `+5`, ` 5`, `1_0` and non-ASCII digits through (BIP380
  lists `[deadbeef/-0/-0/-0]` as invalid), and raised `ValueError` for other
  non-numbers such as `*h`. Descriptor key origins with a trailing `/`, also
  invalid in BIP380, raise `ArgumentError`.
- Miniscript numbers (thresholds and timelocks) must have at least one digit
  and be at most 2^31 - 1, or parsing raises `ArgumentError`, as in Bitcoin
  Core. An empty number such as `older()` was read as 0 and accepted in
  Taproot leaves, and a 1 MB number took minutes to parse.
- Miniscript nested deeper than `MAX_MINISCRIPT_DEPTH` (16 fragments and
  wrappers, `embit.descriptor.miniscript`) raises `MiniscriptError` while
  parsing. Deep nesting raised `RecursionError` (at about 1000 levels on
  CPython and below 20 on MicroPython with a 16 KB stack).
- Taproot trees in `tr()` descriptors deeper than BIP341's 128 levels
  (`MAX_TAPTREE_DEPTH`, `embit.descriptor.taptree`) raise `MiniscriptError`.
  They were accepted, and very deep ones raised `RecursionError`.
- `multi()` and `sortedmulti()` take at most 20 keys, and `multi_a()` and
  `sortedmulti_a()` at most 999, as in Bitcoin Core (`MAX_PUBKEYS_PER_MULTISIG`
  and `MAX_PUBKEYS_PER_MULTI_A`). Parsing raises `MiniscriptError` at the first
  extra key; any number of keys was accepted before.
- Taproot leaves in `tr()` descriptors get the miniscript type checks that
  `wsh()` already ran, and `TapLeaf` raises `MiniscriptError` for a leaf that
  fails them. Leaves such as `multi_a(2,K)`, `and_v(pk(A),pk(B))` or
  `v:pk(K)` were accepted and produced outputs whose script path can't be
  spent, and `multi_a(1)` raised `IndexError` when the output script was
  computed.
- `tr()` descriptors whose multipath keys have different numbers of branches,
  such as `<0;1>` and `<2;3;4>`, raise `DescriptorError`, as BIP389 requires.
  They parsed and failed only when the extra branch was derived. Keys without
  a multipath specifier still combine with any length.
- Segwit descriptors (`wpkh()`, `wsh()`, `tr()` and their Taproot leaves)
  raise `DescriptorError` for uncompressed public keys and uncompressed WIF
  private keys, as BIP382 and BIP386 require. They produced outputs that can't
  be spent under standard policy. `pkh()` and `sh()` still take them.
- `sh()` descriptors whose redeem script is larger than 520 bytes, such as
  `multi()` with more than 15 compressed keys, and `wsh()` miniscript larger
  than 3600 bytes raise `DescriptorError`, as in Bitcoin Core. Funds sent to
  such a P2SH output can never be spent, and spending such a P2WSH output is
  not relayed.
- `Descriptor.from_string()` checks the checksum after `#`, as BIP380 and
  Bitcoin Core's `CheckChecksum()` require, and raises `DescriptorError` when
  it does not match the descriptor, is not 8 characters long or follows a
  second `#`. Anything after `#` used to be ignored, so a descriptor changed
  after its checksum was computed still parsed. Descriptors without a
  checksum parse as before. The new `descriptor.checksum.check_checksum()`
  runs the check on its own.
- `compact.read_from()` and `compact.from_bytes()` raise `ValueError` instead
  of `RuntimeError` on truncated input, and reject integers that are not in
  their shortest encoding (for example `fd0100` for `1`), as Bitcoin Core's
  `ReadCompactSize()` does. Transactions, scripts, PSBTs and PSETs using such
  lengths or counts are now rejected.
- Lengths and counts above `compact.MAX_SIZE` in scripts, witnesses,
  transactions, PSBT and PSET keys and values, `PSBTView` and `PSETView` raise
  `ValueError` before anything is read for them. They used to raise
  `OverflowError` or request the declared length from the stream.
- PSBTv2 and PSET input and output counts (`PSBT_GLOBAL_INPUT_COUNT`,
  `PSBT_GLOBAL_OUTPUT_COUNT`) above `compact.MAX_SIZE` raise `PSBTError` in
  `PSBT.parse()` and `PSBTView.view()`. `PSBTView.fee()` and `verify()` raised
  `OverflowError` for counts of 2^63 and more.
- PSBTv2 and PSET inputs raise `PSBTError` in `PSBT.parse()` and
  `PSBTView.input()` unless `PSBT_IN_REQUIRED_TIME_LOCKTIME` is a 4-byte
  timestamp of at least 500000000 and `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME` a
  4-byte block height from 1 to 499999999, as BIP370 and Bitcoin Core require.
  Any value was kept as an unknown field before.
- PSBT and PSET inputs raise `PSBTError` in `PSBT.parse()` and
  `PSBTView.input()` for a `PSBT_IN_TAP_KEY_SIG` or `PSBT_IN_TAP_SCRIPT_SIG`
  signature that is not 64 or 65 bytes, and for a `PSBT_IN_TAP_LEAF_SCRIPT`
  whose control block is not 33 + 32m bytes with m at most 128 or whose value
  lacks the leaf version (BIP371, BIP341). Such fields were accepted. Malformed
  control blocks that used to fail later with another error, such as `ECError`,
  now raise `PSBTError`.

### Fixed

- Legacy `SIGHASH_SINGLE` sighashes (`Transaction.sighash_legacy()`,
  `PSBTView.sighash_legacy()`, and signing with `PSBT` and `PSBTView`) for any
  input but the first blanked the earlier outputs with the value `0xffffffff`
  where Bitcoin Core uses -1, so their signatures were invalid. The P2PKH, P2PK
  and P2WPKH signatures in Bitcoin Core's `tx_valid.json` verify now.
- Taproot sighashes with `SIGHASH_SINGLE` or `ANYONECANPAY`
  (`Transaction.sighash_taproot()`, `PSBTView.sighash_taproot()`, and signing
  with `PSBT` and `PSBTView`) didn't follow BIP341, so their signatures were
  invalid. An ANYONECANPAY input hashed its whole serialization, with scriptSig
  and sequence, where BIP341 hashes only the outpoint, and `SIGHASH_SINGLE`
  hashed its output where BIP341 hashes the output's SHA256. The BIP341 test
  vectors pass now. `Transaction.sighash_taproot()` also raises
  `TransactionError` instead of `IndexError` for `SIGHASH_SINGLE` without an
  output at the input's index.
- `PSBT` and `PSET` replaced an input's sequence of 0 with `0xffffffff` when
  they built the transaction (`PSBT.tx`, `PSET.tx`, `PSET.blinded_tx`). A
  PSBTv0 with such an input serialized to a different unsigned transaction,
  and `PSBT` computed sighashes and signatures for that transaction rather than
  the one in the PSBT, which `PSBTView` signs. When every input had sequence 0,
  the re-serialized transaction no longer enforced its nLockTime. A sequence of
  0 is kept now; only a missing PSBTv2 sequence defaults to `0xffffffff`.
- `embit.util.key.generate_privkey()` drew keys from the non-cryptographic
  `random` module. Nothing in embit calls it; it uses `misc.secure_randint()`
  (the OS random source) now.
- Bare `except:` clauses (backend detection, `repr()`, Liquid unblinding)
  also caught `KeyboardInterrupt` and `SystemExit`; they catch `ImportError` or
  `Exception` now.
- `slip39.Share.mnemonic()` padded 160- and 240-bit shares, whose value needs
  no padding, with an extra word, producing a mnemonic that does not parse.
  Shares of the 128 and 256 bits that `ShareSet.generate_shares()` creates are
  unchanged.
- Mutable default arguments were shared between instances: every
  `InputScope()`, `OutputScope()`, `PSBT()` and Liquid scope created without
  `unknown` used the same dict, so an unknown key parsed into one made the next
  report "Duplicated key", and `Transaction()` instances shared their `vin` and
  `vout` lists. Defaults are created per instance now.
- Liquid PSET issuance value, inflation keys amount and input value fields
  must be 8 bytes and the output blinder index 4 bytes; longer values parsed
  and then failed to serialize with `OverflowError`. They raise `PSBTError`.
- Liquid `LTransaction.parse()`, `read_from()` and `read_vout()` accepted
  truncated fixed-size fields and proofs, returning a transaction that does not
  serialize back to its input. They raise `TransactionError` now, also for a
  witness flag other than 0 or 1.
- `slip39.ShareSet.recover()` raised `IndexError` for a share whose group
  index is not below the group count. The group index is the share's x
  coordinate, which the SLIP-0039 reference implementation accepts.
- `script.address_to_scriptpubkey()` accepts all-uppercase bech32 and bech32m
  addresses, which BIP173 allows and which were rejected with `EmbitError`.
- A PSBTv2 output without `PSBT_OUT_AMOUNT` or `PSBT_OUT_SCRIPT` made
  `PSBTView.vout()`, `output()`, `fee()` and signing raise `TypeError`. Both
  `PSBT.parse()` and `PSBTView` now raise `PSBTError` for a missing,
  duplicated or non-8-byte amount and a missing or duplicated script; `PSBT`
  used the last of two amounts and `PSBTView` the first. `PSBT.parse()` also
  requires each PSBTv2 input's previous txid and output index, as `PSBTView`
  already did. Liquid `PSET` outputs may still omit both fields, as Elements
  allows for blinded and fee outputs.
- `PSBT.parse()` read the global unsigned transaction with segwit detection,
  so BIP174's valid PSBTs whose transaction has no inputs failed with
  `TransactionError` (the zero input count looked like a segwit marker), and a
  transaction serialized with witnesses, which BIP174 forbids, was accepted.
  It is read without witnesses now, as `PSBTView` already did; data after it
  raises `PSBTError` instead of `EmbitError`.
- A Taproot BIP32 derivation in a PSBT input or output could declare up to
  2^64 - 1 leaf hashes and keep parsing in a loop of empty reads. Parsing now
  stops with `PSBTError` at the first missing hash.
- `Descriptor.script_pubkey()`, `address()`, `witness_script()` and
  `redeem_script()` ignored a fixed derivation path after an extended key, so
  `wpkh(xpub/0/5)` gave the address of the xpub itself (BIP380 key
  expressions; the BIP381-387 test vectors with such keys failed). The path
  is applied now. Ranged descriptors (with `*` or `<a;b>`) are unchanged and
  still need `derive()`.
- `PSBT.parse()` created an input or output scope for every count a PSBTv2
  declared before reading any (about 1.5 KB each, so 100,000 inputs took
  156 MB), and `PSBTView.fee()` and `verify()` allocated a byte per declared
  input before reading them. Scopes are now created as they are read and the
  view reads every input first, so a count larger than the PSBT fails at the
  end of the stream.

## [0.8.2] - 2026-08-08

### Changed

- Align PSBT version parsing and serialization with BIP 174 and BIP 370 across
  `PSBT` and `PSBTView`.

## [0.8.1] - 2026-06-01

### Added

- Add support for Taproot key spend signature in PSBT - `PSBT_IN_TAP_KEY_SIG`.
- Add miniscript boolean literal support for `0` and `1`.
- Add GitHub Actions CI for Python 3.10, 3.11, 3.12, and 3.13.
- Add release hardening workflows for package verification, dependency review,
  CodeQL scanning, release SBOM generation, and PyPI Trusted Publisher
  publishing.
- Add package inspection and artifact verification tools.
- Add `SECURITY.md`, `RELEASING.md`, `CODEOWNERS`, and package content policy
  documentation.
- Add hashed development constraints, `poetry.lock`, Ruff configuration, and
  updated development tooling.

### Changed

- Declare CPython support as Python 3.10+ in package metadata.
- Update secp256k1 ctypes backend discovery to prefer repo-local build outputs,
  then system `libsecp256k1`, then system `secp256k1`, then the legacy in-tree
  `src/embit/util/prebuilt` path.
- Use pure-Python fallbacks for optional secp256k1 modules when the loaded
  ctypes library does not expose the required symbols.
- Make BIP39 mnemonic validation stricter by rejecting leading spaces, trailing
  spaces, double spaces, newline-separated words, phrases shorter than 12 words,
  and phrases longer than 24 words.
- Enforce BIP39 entropy length of 16 to 32 bytes, in multiples of 4.
- Change several invalid input paths from `assert` checks to explicit
  `ValueError` or `embit`-specific exceptions.
- Use deterministic insertion order when collecting PSBT signing derivations and
  derived keypairs, making signing output reproducible.
- Update README and docs to describe pure Python artifacts, optional ctypes
  backend lookup, package inspection, security reporting, and release process.

### Fixed

- Fix descriptor parser offset handling for `tr(...)`, `sh(wsh(...))`,
  `wsh(...)`, `sh(wpkh(...))`, `wpkh(...)`, `pkh(...)`, and `sh(...)`.
- Fix descriptor and miniscript branch counting.
- Fix miniscript `t:` wrapper validation so it only accepts `V` fragments.
- Fix MicroPython test source path precedence so local sources are preferred.
- Fix the MicroPython-style unittest shim so `assertRaises(...) as exc` stores
  the caught exception.
- Fix CPython import discrimination so the repo-local `secp256k1/` build
  directory is not accidentally treated as an empty module.

### Removed

- Remove bundled native `libsecp256k1` binaries from package artifacts.
- Remove native libraries, `.pth` files, startup hook files, nested
  distributions, and unexpected metadata payloads from allowed package contents.

### Security

- Harden release artifacts to verify that no native binaries, install-time
  hooks, `.pth` files, nested distributions, or unexpected metadata payloads are
  shipped.
- Add dependency review gating for newly added dependencies.
- Add CodeQL scanning for Python and GitHub Actions workflows.
- Add release checksums, SBOM generation, and build provenance attestations.

### Compatibility

- CPython users now need Python 3.10 or newer.
- Users who need the ctypes backend must provide a compatible system
  `libsecp256k1`; otherwise `embit` falls back to pure Python where possible.
- Liquid and ZKP operations still require a secp256k1 library exposing the
  required ZKP symbols.
- Applications that accepted BIP39 phrases with extra whitespace or newline
  separators should normalize input before passing it to `embit`.
- Some invalid inputs now raise `ValueError` or `embit`-specific errors instead
  of `AssertionError`.
