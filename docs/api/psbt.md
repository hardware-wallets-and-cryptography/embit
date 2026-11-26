# PSBT transactions

## Signing is not fee approval

A Bitcoin **input** spends one output of a previous transaction. That previous
output, also called a **UTXO** (unspent transaction output), specifies an amount
and a script describing who can spend it. The new transaction identifies it by
the previous transaction's hash (**txid**) and an output index (**vout**).

The miner fee is:

```text
fee = sum(previous output amounts) - sum(new output amounts)
```

The new transaction does not contain its previous output amounts. A PSBT
(Partially Signed Bitcoin Transaction) supplies this extra information so a
wallet can sign offline. Host-supplied metadata is not automatically trustworthy.
All amounts below are in satoshis: 100,000,000 satoshis = 1 BTC.

### What the two UTXO fields prove

- `witness_utxo` contains just the previous output's amount and script. On its
  own, it does **not** authenticate either against the input's txid.
- `non_witness_utxo` contains the complete previous transaction. Strict
  `InputScope.verify()` checks its txid against the input and, if `witness_utxo`
  is also present, checks that it matches the referenced previous output.
  Compressed parsing retains the previous transaction's hash, selected output,
  and a commitment to that output and its index instead of the complete
  transaction. Verification rejects a changed cached amount, script, or index.
  Scope merging keeps this output proof and its transaction hash together.

Matching the txid authenticates the previous transaction's contents. It does not
prove that the transaction is confirmed or that its output is still unspent;
those are separate blockchain checks.

In PSBTv2 the outpoint lives in each input scope. `PSBT_IN_PREVIOUS_TXID`,
`PSBT_IN_OUTPUT_INDEX` and `PSBT_IN_SEQUENCE` may each appear only once, with
their fixed sizes (32, 4 and 4 bytes); otherwise parsing raises `PSBTError`. A
duplicate could name one outpoint for the proof check and another for signing.

BIP370's `PSBT_IN_REQUIRED_TIME_LOCKTIME` must be a 4-byte timestamp of at
least 500000000 and `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME` a 4-byte block height
from 1 to 499999999; other values raise `PSBTError`. Both are kept in the
input's `unknown` fields. The lock time that signatures commit to is
`PSBT_GLOBAL_FALLBACK_LOCKTIME`, or 0 without it; the required lock times are
not taken into account.

In PSBTv0 and PSBTv2 alike, BIP371's Taproot signatures (`PSBT_IN_TAP_KEY_SIG`,
`PSBT_IN_TAP_SCRIPT_SIG`) must be 64 or 65 bytes. A `PSBT_IN_TAP_LEAF_SCRIPT`
key must hold a BIP341 control block of 33 + 32m bytes with m at most 128, and
its value must end with a leaf version. Otherwise parsing raises `PSBTError`.

`InputScope.signing_script` checks redeem/witness-script commitments. These
checks prevent substituting a script inconsistent with the supplied UTXO, but
do not authenticate a witness-only amount.

Signing requires redeem/witness scripts for inputs with candidate signing keys,
not for unrelated inputs without matching derivations or an encoded signing key.
Previous-transaction proofs are still required for every input. Candidate inputs
must pass the script-commitment checks before a signature is generated.

The signing algorithm is selected from the committed scripts, not the presence
of `witness_utxo`. Even matching witness metadata on a legacy input does not
switch it to SegWit signing. Direct Taproot signing helpers raise `PSBTError`
when the input UTXO is missing, including on the explicitly unchecked path.

Non-Taproot derivation checks compare canonical compressed SEC public keys,
including parity. The original PSBT key encoding is preserved for script
membership and signature metadata, so valid uncompressed legacy keys remain
supported. Taproot derivation checks retain their x-only comparison.

### Why a valid signature does not protect the whole fee

For SegWit v0 inputs (such as P2WPKH and P2WSH), the
[BIP143 signature hash](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
includes the amount of the input being signed, **not the amounts of the other
inputs**. This is true even for `SIGHASH_ALL`: "ALL" does not mean all input
amounts.

An incorrect amount makes that input's signature unusable. However, a host can
request two signatures for the same unsigned transaction while alternating
which input amount is understated:

| Request | Input 0 metadata | Input 1 metadata | Apparent fee |
| ------- | ---------------: | ---------------: | -----------: |
| A       |      100,000,000 |           20,000 |       10,000 |
| B       |           20,000 |      100,000,000 |       10,000 |

In this example, both actual inputs are worth 100,000,000 and the new outputs
total 100,010,000. Each request understates one input and appears to pay a small
fee. Input 0's signature from A and input 1's signature from B both verify
against the actual amounts. Combining them authorizes the unchanged transaction
with a fee of **99,990,000**, not 10,000.

No script substitution or unusual sighash flag is required. Script commitment
checks and signing only keys belonging to the input do not stop this attack.
This explanation is specific to SegWit v0; other input types and sighash flags
have different commitment rules. Taproot signatures commit to every input amount;
see [Taproot-only transactions](#taproot-only-transactions).

## Recommended wallet policy

`PSBT.fee()` and `PSBT.sign_with()` check **every input** by default. A wrong
txid or conflicting witness/non-witness outputs raise `PSBTError`, and so does a
missing previous transaction, except for
[Taproot-only transactions](#taproot-only-transactions). Signing performs this
preflight before adding any signatures, even if the signing key controls only
one input. The direct `sign_input_with_tapkey()` helper also checks all inputs
by default.

Verification is repeated on each call; a previous successful `verify()` is not
permission to change input amounts afterward. These guards authenticate amounts,
but do not implement the wallet's approval UI or choose an appropriate sighash.

For an offline wallet authorizing Bitcoin fees, the conservative policy is:

1. Require previous-transaction proofs for **every input**, including inputs the
   wallet does not sign, unless the transaction is Taproot-only.
2. Get the fee from `psbt.fee()`, which performs these checks, before displaying
   it or releasing any signatures. Do not use `verify(ignore_missing=True)` as an
   approval check.
3. Review destinations, change, the authenticated fee, and the signing policy.
4. Sign only after approval, using exactly the verified transaction and metadata.

For example, given a parsed Bitcoin `psbt` and a private signing `root`:

```python
# Raises PSBTError if a required proof is missing, has the wrong txid,
# or conflicts.
fee = psbt.fee()

# The wallet must obtain approval of destinations, change, and this fee here.
# Keep the transaction and its metadata unchanged after verification.
psbt.sign_with(root)
```

On verification failure, abort approval/signing and surface the error to the
user. Do not continue using the unverified fee. Request a PSBT containing the
missing previous transactions instead.

A signer-only guard would be too late if an unauthenticated fee had already been
presented for approval. Wallet integrations must still implement the approval
boundary, using `fee()` or strict verification rather than summing unverified
host metadata themselves. See the [streaming equivalent](./psbtview.md).

## Compatibility and migration

Bitcoin fee/signing APIs now require previous-transaction proofs by default,
except for [Taproot-only transactions](#taproot-only-transactions). Otherwise ask
the PSBT producer to include the complete previous transactions; `witness_utxo`
alone is insufficient.
Retained and compressed proofs are both supported, but serializing a compressed
PSBT can omit its cached previous-transaction proofs. Retain the original
complete PSBT when passing it to another signer.

An explicit `verify_utxos=False` option preserves the old unchecked behavior.
Only boolean values are accepted; `None`, integers, and strings raise `PSBTError`
rather than accidentally disabling verification.

```python
# Unchecked compatibility/testing only: this fee is not authenticated.
unverified_fee = psbt.fee(verify_utxos=False)
psbt.sign_with(root, verify_utxos=False)
```

Do **not** use this option to approve fees from an untrusted host. It permits the
signature-mixing attack above. A caller bypassing the guard must provide its own
authentication and approval policy. The option does not disable script
commitment or derivation checks.

Liquid `PSET` fee calculation and `PSET`/`PSETView` signing retain their existing
defaults. Liquid has explicit fee outputs and different commitment rules; the
Bitcoin default-policy change is not a claim that Liquid signing has been
audited or secured here.

### Taproot-only transactions

A Taproot ([BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki))
signature without `SIGHASH_ANYONECANPAY` commits to the amount and script of
**every** input. If every input spends a P2TR output and no signature uses
ANYONECANPAY, a false `witness_utxo` makes every signature the wallet produces
invalid, so the two-request attack cannot change the fee. In that case `fee()`
and signing accept inputs that carry only `witness_utxo`. Bitcoin Core also
omits `non_witness_utxo` from such PSBTs.

- Every input must be P2TR (SegWit v1 with a 32-byte program) according to its
  UTXO. A transaction mixing Taproot with other input types needs proofs for all
  inputs.
- ANYONECANPAY disables the exception when it applies to the wallet's
  signatures: the requested sighash, or an input's PSBT sighash type in `fee()`
  and when signing with `sighash=None`.
- Previous transactions that are present are still checked.
- The fee is binding rather than verified: a false amount cannot make the
  wallet's signatures pay a different fee, but it can make them invalid.
- `PSBT.verify()` and `PSBTView.verify()` stay strict: they require every
  previous transaction.
- Liquid does not use this exception.

## Executable evidence and regression controls

The tests use deterministic publicly known test keys, synthetic previous
transactions, and real signature generation and verification. They do not mock
cryptography, access a network, broadcast transactions, or use real funds.

- [test_psbt.py](../../tests/tests/test_psbt.py):
  `test_segwit_v0_signature_mixing_evidence` reproduces the two-request attack
  for native P2WPKH, nested P2WPKH, and P2WSH. Other tests reject missing and
  conflicting proofs and verify the authenticated fee before signing.
- [test_psbtview.py](../../tests/tests/test_psbtview.py): the equivalent streaming
  evidence and an all-input preflight check before any signature output. Storage
  that changes outputs, outpoints or sequences after `fee()` cannot get a
  signature committing to the change, and a PSBTv2 input naming two previous
  txids is rejected.
- [test_psbt_versions.py](../../tests/tests/test_psbt_versions.py): PSBTv2
  outpoint fields must be unique, fixed-size and present, and required lock
  times must be in range.
- [test_taproot.py](../../tests/tests/test_taproot.py): Taproot-only PSBTs are
  accepted without previous transactions, mixed inputs and ANYONECANPAY still
  require them, present proofs are still checked, and a false amount or script
  invalidates every Taproot signature. Taproot signatures and control blocks
  must have valid sizes.

The evidence tests **pass when they demonstrate unsafe witness-only use through
the explicit unchecked option**. Separate default-API tests reject both attack
requests and verify that a missing/conflicting proof on a later input releases
no earlier signatures.

From the repository root, after installing the development dependencies:

```sh
python -m pytest tests/tests/test_psbt.py tests/tests/test_psbtview.py \
  tests/tests/test_taproot.py tests/tests/test_psbt_versions.py
```
