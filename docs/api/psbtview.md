# PSBTView - RAM-efficient PSBT class

## Verify all inputs before approving a fee or signing

`PSBTView` reads individual scopes from a stream rather than retaining the whole
PSBT in memory. Its `sign_input()` and `sign_with()` methods check **all
inputs** by default, before writing any signatures, with the same rules as
`PSBT`, including the
[Taproot-only exception](./psbt.md#taproot-only-transactions). The direct
`sign_input_with_tapkey()` helper has the same default. `view.fee()` applies the
same checks before returning the fee. `view.verify()` is the strict check that
every previous transaction is present.

Read [Signing is not fee approval](./psbt.md#signing-is-not-fee-approval) first.
In particular, a SegWit v0 signature commits to its own input amount, not every
input amount used in the fee calculation.

Given a Bitcoin `view`, private signing `root`, and an output `sig_stream`, a
conservative wallet preflight is:

```python
# Raises PSBTError if a required proof is missing, has the wrong txid,
# or conflicts.
fee = view.fee()

# Obtain approval of destinations, change, and the verified fee here.
# Keep the underlying PSBT stream and metadata unchanged.
view.sign_with(root, sig_stream)
```

Verify **all inputs first**. Do not verify input 0, sign it, then discover that
input 1 has an invalid or missing proof: signatures already released could be
combined with another request's signatures. Abort on any verification error
without approving the fee or releasing signatures.

The first check on a view (`fee()`, `verify()` or any signing call) parses every
input once and remembers the results for that view. Every signing call, batch
or standalone, then re-checks only the input it signs, including any
`extra_scope_data`, against those results. Signing input by input therefore
parses each input about twice instead of once per signed input. A new view, for
a new signing request, starts from scratch; `clear_cache()` forces a new scan.
Do not call `clear_cache()` between `fee()` and signing: the view then forgets
the inputs, outpoints and outputs `fee()` checked.

That scan releases each temporary input scope before parsing the next one,
rather than retaining the previous iteration's complete previous transaction.
`view.fee()` takes its amounts from the same scan that checks them. Liquid
`PSETView` has no `fee()`; use `PSET.fee()`.

Unrelated inputs without candidate signing keys need previous-transaction proofs
but not redeem/witness scripts. Batch signing skips generating signatures for
them and preserves their existing partial signatures in the signature stream.
Candidate inputs still require valid script commitments before signing.

The view remembers check results, not parsed scopes: signing re-reads the stream.
Each input it signs must match the scan `fee()` used. The unsigned transaction is
read once, on first use:

- Every input's outpoint and sequence, plus the transaction version and
  locktime, on the first `fee()`, `input()`, `vin()` or signature. `vin()` and
  the signature hashes use only these values. An input scope read later must
  carry the same outpoint and sequence, otherwise `PSBTError` is raised, so a
  checked previous transaction always belongs to the outpoint signed.
- Every output on the first `fee()`, `output()`, `vout()` or signature.
  Signatures commit to those outputs, and a later read that returns a different
  output raises `PSBTError`.

A PSBTv2 input scope must hold exactly one previous txid and one output index,
plus at most one sequence, each with its fixed size. A duplicate could otherwise
name one outpoint for the proof check and another for the signature.

Other input metadata, such as scripts and derivations, is read again when an
input is signed. Use trusted, immutable storage anyway: copy untrusted media
contents to trusted storage before creating the view.

`sign_input(..., extra_scope_data=...)` verifies the final merged target scope
and rejects an outpoint that differs from the unsigned transaction. Other inputs
still need proofs in the underlying stream. A merged UTXO that differs from the
one `fee()` used raises `PSBTError`. Any transaction or UTXO metadata change
requires verification and approval again.
Taproot amount and script hashes are recomputed for every signature from the
signed input's final merged scope and the scan's values for the other inputs, so
a hash calculated before merging metadata cannot override the verified data.

`verify_utxos=False` explicitly enables the old unchecked behavior on all three
signing methods. This is only for compatibility/testing or callers implementing
their own authenticated approval policy; it does **not** protect against the
two-request fee attack. It must not be used merely because another input's proof
is missing. See [compatibility and migration](./psbt.md#compatibility-and-migration).

[test_psbtview.py](../../tests/tests/test_psbtview.py) contains real cryptographic
evidence of signature mixing on the unchecked path and default rejection with
a missing or conflicting proof on the second input. Both retained and compressed
previous-transaction representations and merged target scopes are covered.
Storage-tampering tests change outputs, outpoints and sequences after `fee()`
and check that no released signature commits to the change. A PSBTv2 input scope
with two previous txids is rejected before any fee or signature;
[test_psbt_versions.py](../../tests/tests/test_psbt_versions.py) covers the
outpoint field rules.