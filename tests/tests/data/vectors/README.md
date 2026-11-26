# Upstream test vectors

Each file here is a verbatim copy of an upstream test vector file, pinned to a
commit, so the tests that read it never need the network. To check a copy,
compare `shasum -a 256 <file>` with the table, or download the URL again.

The tests that use these files run on CPython only: `tests/tests/__init__.py`,
which the MicroPython runner imports, does not import them.

## bitcoin-bips

<https://github.com/bitcoin/bips> at commit
`9f3d3bc6a60db16efbdc71ac8f7ea30217fc0c39`. Each URL is
`https://raw.githubusercontent.com/bitcoin/bips/9f3d3bc6a60db16efbdc71ac8f7ea30217fc0c39/<file>`.

| File | SHA-256 | Used by |
|---|---|---|
| `bip-0173.mediawiki` | `b19eab06b264bbd15ad7f7d640fa34de8f4a8809fba8a6ecc3e165545b27a543` | `test_vectors_bech32.py` |
| `bip-0174.mediawiki` | `1c73b0d4afe3bf1805656968010261964a3657bf116aa371201dec6d0999047f` | `test_vectors_psbt.py` |
| `bip-0340/test-vectors.csv` | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` | `test_vectors_schnorr.py` |
| `bip-0341/wallet-test-vectors.json` | `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f` | `test_vectors_taproot.py` |
| `bip-0350.mediawiki` | `63634b06aa8bae88b31929674736e74964c4598684269ac2b0b140c43a7a0dec` | `test_vectors_bech32.py` |
| `bip-0370.mediawiki` | `b2b6e9099592fa04179383f9a1fd8b201fbeef4470f4c3f1c050d25589979c57` | `test_vectors_psbt.py` |
| `bip-0371.mediawiki` | `c2e8143a3c9aee0ee38d863cf40947ddf8ee67b4f40a748fb6925ccc5ad4b791` | `test_vectors_psbt.py` |
| `bip-0380.mediawiki` | `2abd2564a5a7f1905bc45d44255c39bdbae0cb1e7ad1c8b93a6e6c654eac0d2c` | `test_vectors_descriptor.py` |
| `bip-0381.mediawiki` | `f0f6060332f82454f61015815c824eea4b7b6684ce4892ef42d23e4e782fa817` | `test_vectors_descriptor.py` |
| `bip-0382.mediawiki` | `6cd2574998ca0d2141d1c487e70da2dfab47abd6a2dfcc3680af2c241f01fe9d` | `test_vectors_descriptor.py` |
| `bip-0383.mediawiki` | `c46f75e5869386c1852dd187725293822b9e3b761342a966fbcf99adaa112aa2` | `test_vectors_descriptor.py` |
| `bip-0384.mediawiki` | `9d6b32a619e021f50f4b1a07ed8f9d08cfea599c8f484e6b1360ada9aae8541c` | `test_vectors_descriptor.py` |
| `bip-0385.mediawiki` | `8c4963492f1d5b492808e5ece8be75f7f66def37f35d091074fdbfa98a6ddd08` | `test_vectors_descriptor.py` |
| `bip-0386.mediawiki` | `770121b4b33a50bfadfebcd94931dd0ad04159b9fbc1d3b3c3ae17fc0cc16de8` | `test_vectors_descriptor.py` |
| `bip-0387.mediawiki` | `92a1a95be774be27f3f373e15dcd8bf291f542cd62535dd1ccbd95bd1022464e` | `test_vectors_descriptor.py` |
| `bip-0389.mediawiki` | `dfe2d4673bb008565bbb5bcd01438de1c568ba0f46b1dd3bf09ee5df3bd29284` | `test_vectors_descriptor.py` |
| `bip-0390.mediawiki` | `9ec36e702689e8c910cc0d06d2950f32b6a6c66725af096a0731de465e3049af` | `test_vectors_descriptor.py` |

## bitcoin-core

<https://github.com/bitcoin/bitcoin> at commit
`4cf0f7c80cd4da7c7f79a958f7455c4bfd1f86aa`. Each URL is
`https://raw.githubusercontent.com/bitcoin/bitcoin/4cf0f7c80cd4da7c7f79a958f7455c4bfd1f86aa/src/test/data/<file>`.

| File | SHA-256 | Used by |
|---|---|---|
| `tx_valid.json` | `0abeb1a6e4b942e4e43ef8d49b7356c1f6204bcb14163f24153f4d0ec5418011` | `test_vectors_transaction.py` |

## python-shamir-mnemonic

<https://github.com/trezor/python-shamir-mnemonic>, the SLIP-0039 reference
implementation, at commit `4c63da0a50696e58b48f300737c4b540928d134c`. Each URL
is
`https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/4c63da0a50696e58b48f300737c4b540928d134c/<file>`.

| File | SHA-256 | Used by |
|---|---|---|
| `vectors.json` | `13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4` | `test_vectors_slip39.py` |

## Not stored: already copied into the tests

These upstream vectors are already in tests that MicroPython runs too, so
their files are not stored here. Each was checked against the upstream file
below.

| Upstream file | SHA-256 | Vectors | In |
|---|---|---|---|
| `bitcoin-bips` `bip-0032.mediawiki` at the commit above | `e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f` | Test vectors 1 to 5: the 4 seeds, the 34 extended keys of vectors 1 to 4 and the 16 invalid keys of vector 5 | `test_bip32.py`: `SEEDS`, `DERIVE_VECTORS`, `FROM_BASE58_ERROR_VECTORS` |
| `trezor/python-mnemonic` `vectors.json` at commit `b57a5ad77a981e743f4167ab2f7927a55c1e82a8` | `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8` | The 24 English vectors: entropy, mnemonic, seed with the passphrase `TREZOR` and xprv | `test_bip39.py`: `VECTORS` |
