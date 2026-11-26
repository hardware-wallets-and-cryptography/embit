"""
PSBTView class is RAM-friendly implementation of PSBT
that reads required data from a stream on request.

The PSBT transaction itself passed to the class
is a readable stream - it can be a file stream or a BytesIO object.
When using files make sure they are in trusted storage - when using SD card
or other untrusted source make sure to copy the file to a trusted media
(flash, QSPI or SPIRAM for example).

Otherwise you expose yourself to time-of-check-time-of-use style of attacks
where SD card MCU can trick you to sign a wrong transactions.

Makes sense to run gc.collect() after processing of each scope to free memory.
"""

# TODO: refactor, a lot of code is duplicated here from transaction.py
from collections import OrderedDict
import hashlib
from . import compact
from . import ec
from . import script
from .script import Script, Witness
from . import hashes
from .psbt import (
    PSBTError,
    CompressMode,
    InputScope,
    OutputScope,
    read_string,
    ser_string,
    skip_string,
    _GLOBAL_COUNT_FIELDS,
    _GLOBAL_FIXED_VALUE_LENGTHS,
    _GLOBAL_V2_FIELDS,
    _validate_global_fields,
    _validate_global_key,
    _validate_verify_utxos,
    _commits_to_all_amounts,
)
from .transaction import (
    TransactionError,
    _read_exact,
    TransactionOutput,
    TransactionInput,
    SIGHASH,
    hash_amounts,
    hash_script_pubkeys,
)


def _read_global_value(stream, key):
    value_len = compact.read_size(stream)
    if key in _GLOBAL_FIXED_VALUE_LENGTHS:
        if value_len != _GLOBAL_FIXED_VALUE_LENGTHS[key]:
            raise PSBTError("Invalid global field length")
    elif key in _GLOBAL_COUNT_FIELDS and value_len > 9:
        raise PSBTError("Invalid global count length")
    value = stream.read(value_len)
    if len(value) != value_len:
        raise PSBTError("Failed to read %d bytes" % value_len)
    return value, len(compact.to_bytes(value_len)) + value_len


def read_write(sin, sout, sz=None, chunk_size=32) -> int:
    """Reads l or all bytes from sin and writes to sout"""
    # number of bytes written
    res = 0
    barr = bytearray(chunk_size)
    while True:
        if sz == 0:  # nothing else to read
            return res
        elif sz and sz < chunk_size:  # read less than full chunk
            r = sin.read(sz)
            sout.write(r)
            return res + len(r)
        # reading full chunk
        r = sin.readinto(barr)
        if r == 0:
            return res
        res += r
        if r == chunk_size:
            sout.write(barr)
        else:
            sout.write(barr[:r])
        if sz:
            sz -= r


class _TransactionViewStream:
    """Seekable transaction reader with checked reads and bounded-size skips."""

    def __init__(self, stream, offset, length):
        self.stream = stream
        self.offset = offset
        self.end = None if length is None else offset + length
        self._validated_end = offset

    def tell(self):
        return self.stream.seek(0, 1)

    def _check_position(self, position):
        if position < self.offset or (self.end is not None and position > self.end):
            raise PSBTError("Read exceeds declared transaction length")

    def read(self, size):
        position = self.tell()
        self._check_position(position)
        self._check_position(position + size)
        data = self.stream.read(size)
        if len(data) != size:
            if self.end is not None:
                raise PSBTError("Incomplete transaction value")
            raise TransactionError("Incomplete transaction field")
        if position <= self._validated_end:
            self._validated_end = max(self._validated_end, position + size)
        return data

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.tell() + offset
        self._check_position(position)
        if position <= self._validated_end:
            self.stream.seek(position)
        else:
            # Only the contiguous prefix has been checked; the shared stream
            # may have been repositioned by another reader.
            current = self._validated_end
            self.stream.seek(current)
            while current < position:
                data = self.read(min(32, position - current))
                current += len(data)
        return position


class GlobalTransactionView:
    """
    Global transaction in PSBT is
    - unsigned (with empty scriptsigs)
    - doesn't have witness
    """

    LEN_VIN = 32 + 4 + 1 + 4  # txid, vout, scriptsig, sequence
    NUM_VIN_OFFSET = 4  # version

    def __init__(self, stream, offset, length=None):
        self.stream = _TransactionViewStream(stream, offset, length)
        self.offset = offset
        self._num_vin = None
        self._vin0_offset = None
        self._num_vout = None
        self._vout0_offset = None
        self._inputs_checked = False
        self._locktime = None
        self._version = None

    @property
    def version(self):
        if self._version is None:
            self.stream.seek(self.offset)
            self._version = int.from_bytes(_read_exact(self.stream, 4), "little")
        return self._version

    @property
    def num_vin(self):
        if self._num_vin is None:
            self.stream.seek(self.offset + self.NUM_VIN_OFFSET)
            self._num_vin = compact.read_size(self.stream)
            self._vin0_offset = self.stream.tell()
        return self._num_vin

    @property
    def num_vout(self):
        if self._num_vout is None:
            self._check_inputs()
            # version, n_vin, n_vin * len(vin)
            self.stream.seek(self.vin0_offset + self.LEN_VIN * self.num_vin)
            self._num_vout = compact.read_size(self.stream)
            self._vout0_offset = self.stream.tell()
        return self._num_vout

    @property
    def vin0_offset(self):
        if self._vin0_offset is None:
            _ = self.num_vin
        return self._vin0_offset

    @property
    def vout0_offset(self):
        if self._vout0_offset is None:
            _ = self.num_vout
        return self._vout0_offset

    @property
    def locktime(self):
        if self._locktime is None:
            self.stream.seek(self.vout0_offset)
            n = self.num_vout
            while n:
                self._skip_output()
                n -= 1
            locktime = int.from_bytes(_read_exact(self.stream, 4), "little")
            if self.stream.end is not None and self.stream.tell() != self.stream.end:
                raise PSBTError("Trailing bytes in transaction value")
            self._locktime = locktime
        return self._locktime

    def _check_inputs(self):
        """LEN_VIN only holds for unsigned inputs, so every scriptSig must be
        empty before anything is located by striding over the inputs."""
        if self._inputs_checked:
            return
        for i in range(self.num_vin):
            self.stream.seek(self.vin0_offset + self.LEN_VIN * i + 36)
            if _read_exact(self.stream, 1) != b"\x00":
                raise PSBTError("Global transaction input has a non-empty scriptSig")
        self._inputs_checked = True

    def vin(self, i):
        if i < 0 or i >= self.num_vin:
            raise PSBTError("Invalid input index")
        self._check_inputs()
        self.stream.seek(self.vin0_offset + self.LEN_VIN * i)
        return TransactionInput.read_from(self.stream)

    def _skip_output(self):
        """Seeks over one output"""
        self.stream.seek(8, 1)
        l = compact.read_size(self.stream)
        self.stream.seek(l, 1)

    def vout(self, i):
        if i < 0 or i >= self.num_vout:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vout0_offset)
        n = i
        while n:
            self._skip_output()
            n -= 1
        return TransactionOutput.read_from(self.stream)


class PSBTView:
    """
    Constructor shouldn't be used directly. PSBTView.view(stream) should be used instead.
    Either version should be 2 or tx_offset should be int, otherwise you get an error
    """

    # for subclasses like PSET
    MAGIC = b"psbt\xff"
    PSBTIN_CLS = InputScope
    PSBTOUT_CLS = OutputScope
    TX_CLS = GlobalTransactionView
    # Accept witness-only UTXOs when every signature commits to all amounts
    _WITNESS_ONLY_TAPROOT = True

    def __init__(
        self,
        stream,
        num_inputs,
        num_outputs,
        offset,
        first_scope,
        version=None,
        tx_offset=None,
        compress=CompressMode.KEEP_ALL,
        tx_length=None,
    ):
        if version != 2 and tx_offset is None:
            raise PSBTError("Global tx is not found, but PSBT version is %d" % version)
        self.version = version
        self.stream = stream
        # by default we use provided offset, tell() or 0 as default value
        self.offset = offset or 0
        self.num_inputs = num_inputs
        self.num_outputs = num_outputs
        self.tx_offset = tx_offset
        # tx class
        self.tx = self.TX_CLS(stream, tx_offset, tx_length) if self.tx_offset else None
        self.first_scope = first_scope
        self.compress = compress
        self._tx_version = self.tx.version if self.tx else None
        self._locktime = self.tx.locktime if self.tx else None
        self.clear_cache()

    def clear_cache(self):
        # cache for digests
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
        # per-input results of _scan_inputs()
        self._input_utxos = None
        self._input_facts = None
        # results of _pin_outputs()
        self._output_digests = None
        self._output_total = None
        # result of _pin_inputs(), with _hash_prevouts and _hash_sequence
        self._input_pins = None

    @classmethod
    def view(cls, stream, offset=None, compress=CompressMode.KEEP_ALL):
        if offset is None and hasattr(stream, "tell"):
            offset = stream.tell()
        offset = offset or 0
        # current offset
        cur = offset
        # check magic
        if stream.read(len(cls.MAGIC)) != cls.MAGIC:
            raise PSBTError("Invalid PSBT magic")
        cur += len(cls.MAGIC)
        # first we parse the global scope and see if we have tx there
        version = None
        num_inputs = None
        num_outputs = None
        tx_offset = None
        tx_len = None
        global_fields = {}
        while True:
            # read key and update cursor
            key = read_string(stream)
            cur += len(key) + len(compact.to_bytes(len(key)))
            # separator
            if len(key) == 0:
                break
            _validate_global_key(key)
            if key == b"\xfb" or key in _GLOBAL_V2_FIELDS:
                value, value_size = _read_global_value(stream, key)
                cur += value_size
                if key == b"\xfb":
                    if version is not None:
                        raise PSBTError("Duplicated global version")
                    if len(value) != 4:
                        raise PSBTError("Global version must be 4 bytes")
                    version = int.from_bytes(value, "little")
                    if version not in [0, 2]:
                        raise PSBTError("Unsupported PSBT version %d" % version)
                else:
                    if key in global_fields:
                        raise PSBTError("Duplicated global field")
                    global_fields[key] = value
            elif key == b"\x00":
                # we found global transaction
                if tx_offset is not None:
                    raise PSBTError("Duplicated global transaction")
                if version == 2:
                    raise PSBTError("Global transaction with version 2 PSBT")
                if b"\x04" in global_fields or b"\x05" in global_fields:
                    raise PSBTError("Invalid global transaction")
                tx_len = compact.read_size(stream)
                cur += len(compact.to_bytes(tx_len))
                tx_offset = cur
                tx = cls.TX_CLS(stream, tx_offset, tx_len)
                num_inputs = tx.num_vin
                num_outputs = tx.num_vout
                # seek to the end of transaction
                stream.seek(tx_offset + tx_len)
                cur += tx_len
            else:
                cur += skip_string(stream)
        first_scope = cur
        # the check inside the loop only fires if 0xfb was seen before 0x00,
        # so repeat it here to stay independent of the global map key order
        if tx_offset is not None and version == 2:
            raise PSBTError("Global transaction with version 2 PSBT")
        _validate_global_fields(version, tx_offset is not None, global_fields)
        if tx_offset is None:
            num_inputs = compact.from_bytes(global_fields[b"\x04"])
            num_outputs = compact.from_bytes(global_fields[b"\x05"])
        if None in [version or tx_offset, num_inputs, num_outputs]:
            raise PSBTError("Missing something important in PSBT")
        return cls(
            stream,
            num_inputs,
            num_outputs,
            offset,
            first_scope,
            version,
            tx_offset,
            compress,
            tx_len,
        )

    def _skip_scope(self):
        off = 0
        while True:
            # read key and update cursor
            keylen = skip_string(self.stream)
            off += keylen
            # separator: zero-length key, has actual len of 1
            if keylen == 1:
                break
            # not separator - skip value as well
            off += skip_string(self.stream)
        return off

    def seek_to_scope(self, n):
        """
        Moves the stream cursor to n'th scope.
        n can be from 0 to num_inputs+num_outputs or None.
        If n = None it seeks to global scope.
        If n = num_inputs + num_outputs it seeks to the end of PSBT.
        This can be useful to check that nothing is left in the stream (i.e. for tests).
        Returns an offset at this scope.
        """
        if n is None:
            off = self.offset + len(self.MAGIC)
            self.stream.seek(off)
            return off
        if n > self.num_inputs + self.num_outputs:
            raise PSBTError("Invalid scope number")
        # seek to first scope
        self.stream.seek(self.first_scope)
        off = self.first_scope
        while n:
            off += self._skip_scope()
            n -= 1
        return off

    def input(self, i, compress=None):
        """Reads, parses and returns PSBT InputScope #i.

        Its outpoint and sequence are checked against the ones signatures use.
        """
        if compress is None:
            compress = self.compress
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input index")
        self._pin_inputs()
        vin = self._scope_vin(i)
        self.seek_to_scope(i)
        scope = self.PSBTIN_CLS.read_from(
            self.stream, vin=vin, compress=compress, version=self.version
        )
        self._check_input(i, scope)
        return scope

    def output(self, i, compress=None):
        """Reads, parses and returns PSBT OutputScope #i.

        Its amount and script are checked against the outputs fee() summed.
        """
        if compress is None:
            compress = self.compress
        if i < 0 or i >= self.num_outputs:
            raise PSBTError("Invalid output index")
        self._pin_outputs()
        vout = self.tx.vout(i) if self.tx else None
        self.seek_to_scope(self.num_inputs + i)
        scope = self.PSBTOUT_CLS.read_from(
            self.stream, vout=vout, compress=compress, version=self.version
        )
        self._check_output(i, scope.vout)
        return scope

    # Bits recorded per stream input by _scan_inputs(verify=True)
    _FACT_VERIFIED = 1  # previous transaction present and verified
    _FACT_INVALID = 2  # previous transaction present but does not match
    _FACT_P2TR = 4  # commits to all amounts unless ANYONECANPAY is requested
    _FACT_P2TR_OWN = 8  # commits to all amounts with its own PSBT sighash type

    def _scan_inputs(self, verify=True):
        """Parse every input of the stream once per view and cache the results.

        Records each input's (amount, scriptPubKey) for fee() and Taproot
        sighashes. With verify=True it also verifies every previous transaction
        that is present and records the facts _verify_inputs() needs. Like
        signing, this relies on the stream not changing afterwards;
        clear_cache() forces a new scan.
        """
        if self._input_utxos is not None and (
            not verify or self._input_facts is not None
        ):
            return
        utxos = []
        # every scope is read before anything is allocated per declared input
        self._pin_inputs()
        facts = bytearray(self.num_inputs) if verify else None
        for i in range(self.num_inputs):
            inp = self.input(i)
            if verify:
                try:
                    if inp.verify(ignore_missing=True):
                        facts[i] |= self._FACT_VERIFIED
                except PSBTError:
                    # Raised by _verify_inputs() unless a merged scope replaces it
                    facts[i] |= self._FACT_INVALID
                if not facts[i] & self._FACT_INVALID:
                    if _commits_to_all_amounts(inp, SIGHASH.DEFAULT):
                        facts[i] |= self._FACT_P2TR
                    if _commits_to_all_amounts(inp, None):
                        facts[i] |= self._FACT_P2TR_OWN
            try:
                utxo = inp.utxo
            except IndexError:  # output index beyond an unverified transaction
                utxo = None
            utxos.append(None if utxo is None else (utxo.value, utxo.script_pubkey))
            # Release the previous transaction before parsing the next scope.
            del inp, utxo
        self._input_utxos = utxos
        if verify:
            self._input_facts = facts

    def _verify_inputs(
        self, input_index=None, input_scope=None, sighash=None, strict=False
    ):
        """Apply the PSBT._verify_utxos() policy to every input.

        Stream inputs come from the per-view scan, so this parses nothing after
        the first call. input_scope replaces the stream's scope at input_index
        and is checked on every call. Its UTXO must match the scanned one, which
        fee() reported, unless the scan found that input invalid. With
        strict=True every previous transaction must be present.
        """
        self._scan_inputs(verify=True)
        if sighash is None:
            need = self._FACT_P2TR_OWN
        elif sighash & SIGHASH.ANYONECANPAY:
            need = 0
        else:
            need = self._FACT_P2TR
        missing = False
        committed = self._WITNESS_ONLY_TAPROOT and not strict
        for i, fact in enumerate(self._input_facts):
            if input_scope is not None and i == input_index:
                vin = self.vin(i)
                if input_scope.txid != vin.txid or input_scope.vout != vin.vout:
                    raise PSBTError("Input outpoint does not match transaction")
                verified = input_scope.verify(ignore_missing=True)
                commits = _commits_to_all_amounts(input_scope, sighash)
                # Unverified Taproot amounts are only bound by the signature,
                # so a re-read or merged UTXO must equal the one fee() used.
                scanned = self._input_utxos[i]
                if scanned is not None and not (fact & self._FACT_INVALID):
                    utxo = input_scope.utxo
                    if (
                        utxo is None
                        or utxo.value != scanned[0]
                        or utxo.script_pubkey != scanned[1]
                    ):
                        raise PSBTError("Input %d changed after it was checked" % i)
            else:
                if fact & self._FACT_INVALID:
                    # Parse it again to raise the original error.
                    self.input(i).verify(ignore_missing=True)
                    raise PSBTError("Input %d changed after it was checked" % i)
                verified = fact & self._FACT_VERIFIED
                commits = fact & need
            missing = missing or not verified
            committed = committed and bool(commits)
        if missing and not committed:
            raise PSBTError("Missing non_witness_utxo")

    def verify(self) -> bool:
        """Strictly verify every previous transaction in the stream.

        The stream is checked once per view; clear_cache() forces a new check.
        """
        self._verify_inputs(strict=True)
        return True

    def fee(self, verify_utxos: bool = True) -> int:
        """Input amounts minus output amounts, after the same checks as signing.

        See PSBT.fee(). The amounts come from the same pass that checks them,
        and signatures commit to the outputs summed here.
        """
        _validate_verify_utxos(verify_utxos)
        if verify_utxos:
            self._verify_inputs()
        else:
            self._scan_inputs(verify=False)
        total = 0
        for i, utxo in enumerate(self._input_utxos):
            if utxo is None:
                raise PSBTError("Missing previous utxo on input %d" % i)
            total += utxo[0]
        self._pin_outputs()
        return total - self._output_total

    def _pin_outputs(self):
        """Read every output once; later output reads must return the same.

        fee(), hash_outputs(), output() and vout() all use this pass, so the
        fee, the outputs shown and the outputs signed cannot differ even if
        the stream changes. clear_cache() forces a new pass.
        """
        if self._output_digests is not None:
            return
        digests = bytearray()
        h = hashlib.sha256()
        total = 0
        for i in range(self.num_outputs):
            out = self._read_vout(i)
            data = out.serialize()
            h.update(data)
            digests += hashlib.sha256(data).digest()
            total += out.value
        self._hash_outputs = h.digest()
        self._output_total = total
        # 32 bytes per output; set last, it marks the pass as complete
        self._output_digests = bytes(digests)

    def _check_output(self, i, out):
        """Raise if output i differs from the one _pin_outputs() read."""
        if self._output_digests is None:
            return
        expected = self._output_digests[32 * i : 32 * i + 32]
        if hashlib.sha256(out.serialize()).digest() != expected:
            raise PSBTError("Output %d changed after it was checked" % i)

    # bytes per pinned input: txid, output index, sequence, as serialized
    _PIN_SIZE = 32 + 4 + 4

    def _pin_inputs(self):
        """Read every input's outpoint and sequence once; later reads use these.

        vin(), hash_prevouts(), hash_sequence() and therefore every sighash use
        this pass, and input() rejects a scope that disagrees with it, so the
        proofs _scan_inputs() checks belong to the outpoints signed, even if
        the stream changes. Transaction version and locktime are read here
        too: the whole unsigned transaction is read before fee() returns.
        clear_cache() forces a new pass.
        """
        if self._input_pins is not None:
            return
        # grown per input: num_inputs is not trusted until every scope is read
        pins = bytearray()
        prevouts = hashlib.sha256()
        sequences = hashlib.sha256()
        if self.tx is None:
            self.stream.seek(self.first_scope)
        for i in range(self.num_inputs):
            if self.tx is None:
                outpoint, sequence = self._read_scope_outpoint(i)
            else:
                vin = self.tx.vin(i)
                outpoint = bytes(reversed(vin.txid)) + vin.vout.to_bytes(4, "little")
                sequence = vin.sequence.to_bytes(4, "little")
            prevouts.update(outpoint)
            sequences.update(sequence)
            pins.extend(outpoint)
            pins.extend(sequence)
        _ = self.tx_version
        _ = self.locktime
        self._hash_prevouts = prevouts.digest()
        self._hash_sequence = sequences.digest()
        # set last, it marks the pass as complete
        self._input_pins = pins

    def _read_scope_outpoint(self, i):
        """Read the PSBTv2 input scope at the stream position.

        Returns its serialized outpoint and sequence. Keys must match exactly
        and appear once with a fixed-size value, as InputScope requires: a
        prefix match or a duplicate could select a different value than the
        one whose proof is checked. Other keys and values are skipped unread.
        """
        sizes = self.PSBTIN_CLS.OUTPOINT_FIELD_SIZES
        fields = {}
        while True:
            key_len = compact.read_size(self.stream)
            if key_len == 0:  # separator
                break
            if key_len != 1:
                self.stream.seek(key_len, 1)
                skip_string(self.stream)
                continue
            key = self.stream.read(1)
            if key not in sizes:
                if len(key) != 1:
                    raise PSBTError("Truncated input %d" % i)
                skip_string(self.stream)
                continue
            if key in fields:
                raise PSBTError("Duplicated previous outpoint field in input %d" % i)
            if compact.read_from(self.stream) != sizes[key]:
                raise PSBTError("Invalid previous outpoint field in input %d" % i)
            value = self.stream.read(sizes[key])
            if len(value) != sizes[key]:
                raise PSBTError("Truncated input %d" % i)
            fields[key] = value
        if b"\x0e" not in fields or b"\x0f" not in fields:
            raise PSBTError("Missing previous outpoint in input %d" % i)
        sequence = fields.get(b"\x10", b"\xff\xff\xff\xff")
        return fields[b"\x0e"] + fields[b"\x0f"], sequence

    def _pinned_vin(self, i):
        """TransactionInput for input i from _pin_inputs(); reads no stream."""
        self._pin_inputs()
        pin = self._input_pins[self._PIN_SIZE * i : self._PIN_SIZE * (i + 1)]
        return TransactionInput(
            bytes(reversed(pin[:32])),
            int.from_bytes(pin[32:36], "little"),
            sequence=int.from_bytes(pin[36:40], "little"),
        )

    def _scope_vin(self, i):
        """The vin a PSBTv0 input scope is parsed with: the pinned one."""
        return self._pinned_vin(i) if self.tx else None

    def _check_input(self, i, scope):
        """Raise if input scope i's outpoint or sequence differs from the pin.

        PSBTv0 scopes are parsed with the pinned vin. PSBTv2 scopes carry their
        own fields, read again from the stream.
        """
        vin = self._pinned_vin(i)
        sequence = 0xFFFFFFFF if scope.sequence is None else scope.sequence
        if scope.txid != vin.txid or scope.vout != vin.vout or sequence != vin.sequence:
            raise PSBTError("Input %d changed after it was checked" % i)

    # compress is not used here, but may be used by subclasses (liquid)
    def vin(self, i, compress=None):
        """Input i's outpoint and sequence, as read by _pin_inputs()."""
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input index")
        return self._pinned_vin(i)

    # compress is not used here, but may be used by subclasses (liquid)
    def vout(self, i, compress=None):
        """Output i, checked against the outputs fee() summed."""
        if i < 0 or i >= self.num_outputs:
            raise PSBTError("Invalid output index")
        self._pin_outputs()
        out = self._read_vout(i)
        self._check_output(i, out)
        return out

    def _read_vout(self, i):
        """Read output i from the stream without checking it."""
        if self.tx:
            return self.tx.vout(i)
        self.seek_to_scope(self.num_inputs + i)
        return self._read_scope_output(i)

    # PSBT_OUT_AMOUNT and PSBT_OUT_SCRIPT
    _OUTPUT_FIELDS = (b"\x03", b"\x04")

    def _read_scope_output(self, i):
        """Read the amount and script of the PSBTv2 output scope at the stream
        position. As in OutputScope, each key must match exactly and appear
        once, and the amount is 8 bytes: a prefix match or a duplicate could
        select another value than the one PSBT.parse() reads.
        """
        fields = {}
        while True:
            key_len = compact.read_size(self.stream)
            if key_len == 0:  # separator
                break
            key = self.stream.read(1)
            if len(key) != 1:
                raise PSBTError("Truncated output %d" % i)
            if key not in self._OUTPUT_FIELDS:
                self.stream.seek(key_len - 1, 1)
                skip_string(self.stream)
                continue
            if key_len != 1:
                raise PSBTError("Invalid PSBTv2 field key in output %d" % i)
            if key in fields:
                raise PSBTError("Duplicated amount or script in output %d" % i)
            fields[key] = read_string(self.stream)
        if len(fields) != len(self._OUTPUT_FIELDS):
            raise PSBTError("Missing amount or script in output %d" % i)
        if len(fields[b"\x03"]) != 8:
            raise PSBTError("Invalid amount in output %d" % i)
        value = int.from_bytes(fields[b"\x03"], "little")
        return TransactionOutput(value, Script(fields[b"\x04"]))

    @property
    def locktime(self):
        if self._locktime is None:
            v = self.get_value(b"\x03")
            self._locktime = int.from_bytes(v, "little") if v is not None else 0
        return self._locktime

    @property
    def tx_version(self):
        if self._tx_version is None:
            v = self.get_value(b"\x02")
            self._tx_version = int.from_bytes(v, "little") if v is not None else 0
        return self._tx_version

    def seek_to_value(self, key_start, from_current=False):
        """
        Seeks to value with key starting with key_start.
        Returns offset - relative if from_current=True, absolute otherwise.
        If key is not found - returns None.
        """
        off = 0
        if not from_current:
            # go to the start
            self.stream.seek(self.offset + len(self.MAGIC))
            off = self.offset + len(self.MAGIC)
        while True:
            key = read_string(self.stream)
            off += len(key) + len(compact.to_bytes(len(key)))
            # separator - not found
            if len(key) == 0:
                return None
            # matches
            if key.startswith(key_start):
                return off
            # continue to the next key
            off += skip_string(self.stream)

    def get_value(self, key_start, from_current=False):
        off = self.seek_to_value(key_start, from_current)
        if off:
            return read_string(self.stream)

    def hash_prevouts(self):
        # computed in the same pass that pins every outpoint
        self._pin_inputs()
        return self._hash_prevouts

    def hash_sequence(self):
        # computed in the same pass that pins every sequence
        self._pin_inputs()
        return self._hash_sequence

    def hash_outputs(self):
        # computed in the same pass as fee()'s output total
        self._pin_outputs()
        return self._hash_outputs

    def hash_amounts(self, amounts):
        return hash_amounts(amounts)

    def hash_script_pubkeys(self, script_pubkeys):
        return hash_script_pubkeys(script_pubkeys)

    def sighash_taproot(
        self,
        input_index,
        script_pubkeys,
        values,
        sighash=SIGHASH.DEFAULT,
        ext_flag=0,
        annex=None,
        script=None,
        leaf_version=0xC0,
        codeseparator_pos=None,
    ):
        """check out bip-341"""
        # TODO: refactor, it's almost a complete copy of tx.sighash_taproot
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        if len(values) != self.num_inputs:
            raise PSBTError("All spent amounts are required")
        sh, anyonecanpay = SIGHASH.check(sighash)
        h = hashes.tagged_hash_init("TapSighash", b"\x00")
        h.update(bytes([sighash]))
        h.update(self.tx_version.to_bytes(4, "little"))
        h.update(self.locktime.to_bytes(4, "little"))
        if not anyonecanpay:
            h.update(self.hash_prevouts())
            h.update(self.hash_amounts(values))
            h.update(self.hash_script_pubkeys(script_pubkeys))
            h.update(self.hash_sequence())
        if sh not in [SIGHASH.SINGLE, SIGHASH.NONE]:
            h.update(self.hash_outputs())
        # data about this input
        h.update(bytes([2 * ext_flag + int(annex is not None)]))
        if anyonecanpay:
            vin = self.vin(input_index)
            # the outpoint only: BIP341 adds amount, script and sequence below
            h.update(bytes(reversed(vin.txid)))
            h.update(vin.vout.to_bytes(4, "little"))
            h.update(values[input_index].to_bytes(8, "little"))
            h.update(script_pubkeys[input_index].serialize())
            h.update(vin.sequence.to_bytes(4, "little"))
        else:
            h.update(input_index.to_bytes(4, "little"))
        if annex is not None:
            h.update(hashes.sha256(compact.to_bytes(len(annex)) + annex))
        if sh == SIGHASH.SINGLE:
            h.update(hashes.sha256(self.vout(input_index).serialize()))
        if script is not None:
            h.update(
                hashes.tagged_hash(
                    "TapLeaf", bytes([leaf_version]) + script.serialize()
                )
            )
            h.update(b"\x00")
            h.update(
                b"\xff\xff\xff\xff"
                if codeseparator_pos is None
                else codeseparator_pos.to_bytes(4, "little")
            )
        return h.digest()

    def sighash_segwit(self, input_index, script_pubkey, value, sighash=SIGHASH.ALL):
        """check out bip-143"""
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        # default sighash is used only in taproot
        if sh == SIGHASH.DEFAULT:
            sh = SIGHASH.ALL
        inp = self.vin(input_index)
        zero = b"\x00" * 32  # for sighashes
        h = hashlib.sha256()
        h.update(self.tx_version.to_bytes(4, "little"))
        if anyonecanpay:
            h.update(zero)
        else:
            h.update(hashlib.sha256(self.hash_prevouts()).digest())
        if anyonecanpay or sh in [SIGHASH.NONE, SIGHASH.SINGLE]:
            h.update(zero)
        else:
            h.update(hashlib.sha256(self.hash_sequence()).digest())
        h.update(bytes(reversed(inp.txid)))
        h.update(inp.vout.to_bytes(4, "little"))
        h.update(script_pubkey.serialize())
        h.update(int(value).to_bytes(8, "little"))
        h.update(inp.sequence.to_bytes(4, "little"))
        if sh not in {SIGHASH.NONE, SIGHASH.SINGLE}:
            h.update(hashlib.sha256(self.hash_outputs()).digest())
        elif sh == SIGHASH.SINGLE and input_index < self.num_outputs:
            h.update(
                hashlib.sha256(
                    hashlib.sha256(self.vout(input_index).serialize()).digest()
                ).digest()
            )
        else:
            h.update(zero)
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash_legacy(self, input_index, script_pubkey, sighash=SIGHASH.ALL):
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        # default sighash is used only in taproot
        if sh == SIGHASH.DEFAULT:
            sh = SIGHASH.ALL
        # no corresponding output for this input, we sign 00...01
        if sh == SIGHASH.SINGLE and input_index >= self.num_outputs:
            return b"\x00" * 31 + b"\x01"

        h = hashlib.sha256()
        h.update(self.tx_version.to_bytes(4, "little"))
        # ANYONECANPAY - only one input is serialized
        if anyonecanpay:
            h.update(compact.to_bytes(1))
            h.update(self.vin(input_index).serialize(script_pubkey))
        else:
            h.update(compact.to_bytes(self.num_inputs))
            for i in range(self.num_inputs):
                inp = self.vin(i)
                if input_index == i:
                    h.update(inp.serialize(script_pubkey))
                else:
                    h.update(inp.serialize(Script(b""), sighash))
        # no outputs
        if sh == SIGHASH.NONE:
            h.update(compact.to_bytes(0))
        # one output on the same index, others are empty
        elif sh == SIGHASH.SINGLE:
            h.update(compact.to_bytes(input_index + 1))
            # Bitcoin Core blanks them as CTxOut(): value -1, empty script
            empty = TransactionOutput(0xFFFFFFFFFFFFFFFF, Script(b"")).serialize()
            # this way we commit to input index
            for i in range(input_index):
                h.update(empty)
            # last is ours
            h.update(self.vout(input_index).serialize())
        elif sh == SIGHASH.ALL:
            h.update(compact.to_bytes(self.num_outputs))
            for i in range(self.num_outputs):
                out = self.vout(i)
                h.update(out.serialize())
        else:
            # shouldn't happen
            raise PSBTError("Invalid sighash")
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash(self, i, sighash=SIGHASH.ALL, input_scope=None, **kwargs):
        inp = self.input(i) if input_scope is None else input_scope

        if inp.is_taproot:
            # Other inputs come from the per-view scan; this input from its scope
            self._scan_inputs(verify=False)
            values = []
            scripts = []
            for idx, utxo in enumerate(self._input_utxos):
                if idx == i:
                    utxo = (inp.utxo.value, inp.utxo.script_pubkey)
                elif utxo is None:
                    raise PSBTError("Missing input UTXO")
                values.append(utxo[0])
                scripts.append(utxo[1])
            return self.sighash_taproot(
                i,
                script_pubkeys=scripts,
                values=values,
                sighash=sighash,
                **kwargs,
            )

        value = inp.utxo.value
        sc = inp.signing_script

        # detect if it is a segwit input
        is_segwit = (
            inp.witness_script
            or inp.utxo.script_pubkey.script_type() in {"p2wpkh", "p2wsh"}
            or (
                inp.redeem_script
                and inp.redeem_script.script_type() in {"p2wpkh", "p2wsh"}
            )
        )
        # convert to p2pkh according to bip143
        if sc.script_type() == "p2wpkh":
            sc = script.p2pkh_from_p2wpkh(sc)

        if is_segwit:
            h = self.sighash_segwit(i, sc, value, sighash=sighash)
        else:
            h = self.sighash_legacy(i, sc, sighash=sighash)
        return h

    def sign_input_with_tapkey(
        self,
        key: ec.PrivateKey,
        input_index: int,
        inp=None,
        sighash=SIGHASH.DEFAULT,
        verify_utxos: bool = True,
    ) -> int:
        """Sign a taproot input after checking every input's UTXO, as in fee()."""
        _validate_verify_utxos(verify_utxos)
        # get input ourselves if not provided
        inp = inp or self.input(input_index)
        if verify_utxos:
            self._verify_inputs(input_index, inp, sighash)
        if not inp.is_taproot:
            return 0
        # check if key is internal key
        pk = key.taproot_tweak(inp.taproot_merkle_root or b"")
        if pk.xonly() in inp.utxo.script_pubkey.data:
            h = self.sighash(
                input_index,
                sighash=sighash,
                input_scope=inp,
            )
            sig = pk.schnorr_sign(h)
            wit = sig.serialize()
            if sighash != SIGHASH.DEFAULT:
                wit += bytes([sighash])
            # TODO: maybe better to put into internal key sig field
            inp.final_scriptwitness = Witness([wit])
            # no need to sign anything else
            return 1
        counter = 0
        # negate if necessary
        pub = ec.PublicKey.from_xonly(key.xonly())
        # iterate over leafs and sign
        for ctrl, sc in inp.taproot_scripts.items():
            if pub.xonly() not in sc:
                continue
            leaf_version = sc[-1]
            script = Script(sc[:-1])
            h = self.sighash(
                input_index,
                sighash=sighash,
                input_scope=inp,
                ext_flag=1,
                script=script,
                leaf_version=leaf_version,
            )
            sig = key.schnorr_sign(h)
            leaf = hashes.tagged_hash(
                "TapLeaf", bytes([leaf_version]) + script.serialize()
            )
            sigdata = sig.serialize()
            # append sighash if necessary
            if sighash != SIGHASH.DEFAULT:
                sigdata += bytes([sighash])
            inp.taproot_sigs[(pub, leaf)] = sigdata
            counter += 1
        return counter

    def sign_input(
        self,
        i,
        root,
        sig_stream,
        sighash=SIGHASH.DEFAULT,
        extra_scope_data=None,
        verify_utxos: bool = True,
    ) -> int:
        """
        Signs input taking into account additional
        derivation information for this input.

        It's helpful if your wallet knows more than provided in PSBT.
        As PSBTView is read-only it can't change anything in PSBT,
        that's why you may need extra_scope_data.
        Every input's UTXO is verified before any signature is written, including
        the merged scope. verify_utxos=False is an unchecked compatibility path.
        """
        _validate_verify_utxos(verify_utxos)
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input number")

        # if WIF - fingerprint is None
        fingerprint = None
        # if descriptor key
        if hasattr(root, "origin"):
            if not root.is_private:  # pubkey can't sign
                return 0
            if root.is_extended:  # use fingerprint only for HDKey
                fingerprint = root.fingerprint
            else:
                root = root.key  # WIF key
        # if HDKey
        if not fingerprint and hasattr(root, "my_fingerprint"):
            fingerprint = root.my_fingerprint

        rootpub = root.get_public_key()
        sec = rootpub.sec()
        pkh = hashes.hash160(sec)

        inp = self.input(i)
        if extra_scope_data is not None:
            inp.update(extra_scope_data)
        if verify_utxos:
            self._verify_inputs(i, inp, sighash)

        # SIGHASH.DEFAULT is only for taproot, fallback to SIGHASH.ALL for other inputs
        required_sighash = sighash
        if not inp.is_taproot and required_sighash == SIGHASH.DEFAULT:
            required_sighash = SIGHASH.ALL

        # check which sighash to use
        inp_sighash = inp.sighash_type
        if inp_sighash is None:
            inp_sighash = required_sighash or SIGHASH.DEFAULT
        if not inp.is_taproot and inp_sighash == SIGHASH.DEFAULT:
            inp_sighash = SIGHASH.ALL

        # if input sighash is set and is different from required sighash
        # we don't sign this input
        # except DEFAULT is functionally the same as ALL
        if required_sighash is not None and inp_sighash != required_sighash:
            if inp_sighash not in {
                SIGHASH.DEFAULT,
                SIGHASH.ALL,
            } or required_sighash not in {SIGHASH.DEFAULT, SIGHASH.ALL}:
                return 0

        # get all possible derivations with matching fingerprint
        bip32_derivations = OrderedDict()
        if fingerprint:
            # if taproot derivations are present add them
            for pub in inp.taproot_bip32_derivations:
                _leafs, derivation = inp.taproot_bip32_derivations[pub]
                if derivation.fingerprint == fingerprint:
                    # Add only if not already present
                    if (pub, derivation) not in bip32_derivations:
                        bip32_derivations[(pub, derivation)] = True

            # segwit and legacy derivations
            for pub in inp.bip32_derivations:
                derivation = inp.bip32_derivations[pub]
                if derivation.fingerprint == fingerprint:
                    if (pub, derivation) not in bip32_derivations:
                        bip32_derivations[(pub, derivation)] = True

        # get derived keys for signing
        derived_keypairs = OrderedDict()  # (prv, pub)
        for pub, derivation in bip32_derivations:
            der = derivation.derivation
            # descriptor key has origin derivation that we take into account
            if hasattr(root, "origin"):
                if root.origin:
                    if root.origin.derivation != der[: len(root.origin.derivation)]:
                        # derivation doesn't match - go to next input
                        continue
                    der = der[len(root.origin.derivation) :]
                hdkey = root.key.derive(der)
            else:
                hdkey = root.derive(der)

            if (
                hdkey.xonly() != pub.xonly()
                if inp.is_taproot
                else (
                    hdkey.get_public_key().sec(compressed=True)
                    != pub.sec(compressed=True)
                )
            ):
                raise PSBTError("Derivation path doesn't look right")
            # Insert into derived_keypairs if not present
            if (hdkey.key, pub) not in derived_keypairs:
                derived_keypairs[(hdkey.key, pub)] = True

        counter = 0
        # sign with taproot key
        if inp.is_taproot:
            # try to sign with individual private key (WIF)
            # or with root without derivations
            counter += self.sign_input_with_tapkey(
                root,
                i,
                inp,
                sighash=inp_sighash,
                verify_utxos=False,
            )
            # sign with all derived keys
            for prv, pub in derived_keypairs:
                counter += self.sign_input_with_tapkey(
                    prv,
                    i,
                    inp,
                    sighash=inp_sighash,
                    verify_utxos=False,
                )
            if inp.final_scriptwitness:
                ser_string(sig_stream, b"\x08")
                ser_string(sig_stream, inp.final_scriptwitness.serialize())

            for pub, leaf in inp.taproot_sigs:
                ser_string(sig_stream, b"\x14" + pub.xonly() + leaf)
                ser_string(sig_stream, inp.taproot_sigs[(pub, leaf)])
            return counter

        if derived_keypairs or inp._has_signing_key(sec, pkh):
            h = self.sighash(i, sighash=inp_sighash, input_scope=inp)
            sc = inp.signing_script

            # check if root is included in the script
            if sec in sc.data or pkh in sc.data:
                sig = root.sign(h)
                # sig plus sighash flag
                inp.partial_sigs[rootpub] = sig.serialize() + bytes([inp_sighash])
                counter += 1
            for prv, pub in derived_keypairs:
                der_sec = pub.sec()
                der_pkh = hashes.hash160(der_sec)
                # same script-membership check as for the root key above -
                # a matching fingerprint alone doesn't prove this key is
                # actually part of the input's script
                if der_sec not in sc.data and der_pkh not in sc.data:
                    continue
                sig = prv.sign(h)
                # sig plus sighash flag
                inp.partial_sigs[pub] = sig.serialize() + bytes([inp_sighash])
                counter += 1
        for pub in inp.partial_sigs:
            ser_string(sig_stream, b"\x02" + pub.serialize())
            ser_string(sig_stream, inp.partial_sigs[pub])
        return counter

    def sign_with(
        self, root, sig_stream, sighash=SIGHASH.DEFAULT, verify_utxos: bool = True
    ) -> int:
        """
        Signs psbtview with root key (HDKey or similar) and writes per-input signatures to the sig_stream.
        It can be either a simple BytesIO object or a file stream open for writing.
        Returns number of signatures added to PSBT.
        Sighash kwarg is set to SIGHASH.DEFAULT, for segwit and legacy it's replaced to SIGHASH.ALL
        so if PSBT is asking to sign with a different sighash this function won't sign.
        If you want to sign with sighashes provided in the PSBT - set sighash=None.
        All input UTXOs are checked before the first signature is written, as in
        fee(), and each input is checked again as it is signed.
        verify_utxos=False explicitly permits unchecked metadata.
        """
        _validate_verify_utxos(verify_utxos)
        if verify_utxos:
            self._verify_inputs(sighash=sighash)
        counter = 0
        for i in range(self.num_inputs):
            # check if it's a descriptor, and sign with
            # all private keys in this descriptor
            if hasattr(root, "keys"):
                for k in root.keys:
                    if hasattr(k, "is_private") and k.is_private:
                        counter += self.sign_input(
                            i, k, sig_stream, sighash=sighash, verify_utxos=verify_utxos
                        )
            else:
                # just sign with the key
                counter += self.sign_input(
                    i, root, sig_stream, sighash=sighash, verify_utxos=verify_utxos
                )
            # add separator
            sig_stream.write(b"\x00")
        return counter

    def write_to(
        self,
        writable_stream,
        compress=None,
        extra_input_streams=(),
        extra_output_streams=(),
    ):
        """
        Writes PSBTView to stream.
        extra_input_streams and extra_output_streams
        are streams with extra per-input and per-output data that should be written to stream as well.
        For example they can contain signatures or extra derivations.

        If compressed flag is used then only minimal number of fields will be writen:
        For psbtv0 it will have global tx and partial sigs for all inputs
        For psbtv2 it will have version, tx_version, locktime, per-vin data, per-vout data and partial sigs
        """
        if compress is None:
            compress = self.compress

        # first we write global scope
        self.stream.seek(self.offset)
        res = read_write(self.stream, writable_stream, self.first_scope - self.offset)

        # write all inputs
        for i in range(self.num_inputs):
            inp = self.input(i)
            # add extra data from extra input streams
            for s in extra_input_streams:
                extra = InputScope.read_from(s)
                inp.update(extra)
            if compress:
                inp.clear_metadata(compress=compress)
            res += inp.write_to(writable_stream, version=self.version)

        # write all outputs
        for i in range(self.num_outputs):
            out = self.output(i)
            # add extra data from extra input streams
            for s in extra_output_streams:
                extra = OutputScope.read_from(s)
                out.update(extra)
            if compress:
                out.clear_metadata(compress=compress)
            res += out.write_to(writable_stream, version=self.version)

        return res
