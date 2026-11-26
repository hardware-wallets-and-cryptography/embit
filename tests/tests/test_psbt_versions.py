from io import BytesIO
from unittest import TestCase

from embit import compact
from embit.base import EmbitError
from embit.psbt import InputScope, OutputScope, PSBT, PSBTError
from embit.psbtview import PSBTView
from embit.script import Script, Witness
from embit.transaction import Transaction, TransactionInput, TransactionOutput


def key_value(key, value):
    return compact.to_bytes(len(key)) + key + compact.to_bytes(len(value)) + value


def unsigned_tx(value=1000):
    return Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(value, Script(b"\x51"))],
    )


def psbt_v0():
    return PSBT(unsigned_tx()).serialize()


def psbt_v0_globals(extra=b"", tx_first=True):
    """A minimal PSBTv0 with `extra` key-values added to the global map."""
    tx_kv = key_value(b"\x00", unsigned_tx().serialize())
    globals_ = tx_kv + extra if tx_first else extra + tx_kv
    # global separator, then one empty input scope and one empty output scope
    return PSBT.MAGIC + globals_ + b"\x00" + b"\x00" + b"\x00"


V2_GLOBAL_FIELDS = (
    (b"\x02", (2).to_bytes(4, "little")),
    (b"\x04", compact.to_bytes(0)),
    (b"\x05", compact.to_bytes(0)),
    (b"\xfb", (2).to_bytes(4, "little")),
)


def psbt_v2_globals(fields=V2_GLOBAL_FIELDS):
    globals_ = b"".join(key_value(key, value) for key, value in fields)
    return PSBT.MAGIC + globals_ + b"\x00"


class LimitedReadStream:
    def __init__(self, data):
        self.stream = BytesIO(data)

    def read(self, size=-1):
        if size > 9:
            raise AssertionError("Oversized payload read")
        return self.stream.read(size)

    def seek(self, *args):
        return self.stream.seek(*args)


class PSBTVersionTest(TestCase):
    def test_v0_excludes_v2_input_fields(self):
        raw = psbt_v0()
        fields = [
            (b"\x0e", bytes(32)),
            (b"\x0f", bytes(4)),
            (b"\x10", bytes(4)),
            (b"\x11", bytes(4)),
            (b"\x12", bytes(4)),
        ]
        for key, value in fields:
            invalid = raw[:-2] + key_value(key, value) + raw[-2:]
            with self.assertRaises(PSBTError):
                PSBT.parse(invalid)
            view = PSBTView.view(BytesIO(invalid))
            with self.assertRaises(PSBTError):
                view.input(0)

    def test_v0_excludes_v2_output_fields(self):
        raw = psbt_v0()
        fields = [
            (b"\x03", (1000).to_bytes(8, "little")),
            (b"\x04", b"\x51"),
        ]
        for key, value in fields:
            invalid = raw[:-1] + key_value(key, value) + raw[-1:]
            with self.assertRaises(PSBTError):
                PSBT.parse(invalid)
            view = PSBTView.view(BytesIO(invalid))
            with self.assertRaises(PSBTError):
                view.output(0)

    def test_v0_excludes_v2_fields_with_key_data(self):
        raw = psbt_v0()
        fields = [
            (b"\x0e\x00", bytes(32), -2, "input"),
            (b"\x03\x00", (1000).to_bytes(8, "little"), -1, "output"),
        ]
        for key, value, offset, scope in fields:
            invalid = raw[:offset] + key_value(key, value) + raw[offset:]
            with self.assertRaises(PSBTError):
                PSBT.parse(invalid)
            view = PSBTView.view(BytesIO(invalid))
            with self.assertRaises(PSBTError):
                getattr(view, scope)(0)

    def assertRejected(self, raw):
        with self.assertRaises(PSBTError):
            PSBT.parse(raw)
        with self.assertRaises(PSBTError):
            PSBTView.view(BytesIO(raw))

    def test_global_version_2_rejected_with_unsigned_tx_in_any_order(self):
        version_kv = key_value(b"\xfb", (2).to_bytes(4, "little"))
        # the global map is unordered, so both orderings must be rejected
        self.assertRejected(psbt_v0_globals(version_kv))
        self.assertRejected(psbt_v0_globals(version_kv, tx_first=False))

    def test_explicit_global_version_0_accepted(self):
        raw = psbt_v0_globals(key_value(b"\xfb", (0).to_bytes(4, "little")))
        self.assertEqual(len(PSBT.parse(raw).inputs), 1)
        self.assertEqual(PSBTView.view(BytesIO(raw)).num_inputs, 1)

    def test_rejects_unsupported_global_version(self):
        for version in [1, 3, 0xFFFFFFFF]:
            self.assertRejected(
                psbt_v0_globals(key_value(b"\xfb", version.to_bytes(4, "little")))
            )

    def test_rejects_malformed_global_version(self):
        for value in [b"", b"\x00", b"\x00" * 8]:
            self.assertRejected(psbt_v0_globals(key_value(b"\xfb", value)))

    def test_rejects_duplicated_global_version(self):
        version_kv = key_value(b"\xfb", (0).to_bytes(4, "little"))
        self.assertRejected(psbt_v0_globals(version_kv + version_kv))

    def test_rejects_duplicated_global_tx(self):
        # a second global tx must not silently override the first
        self.assertRejected(
            psbt_v0_globals(key_value(b"\x00", unsigned_tx(999).serialize()))
        )

    def test_v0_rejects_v2_global_fields(self):
        fields = [
            (b"\x02", (3).to_bytes(4, "little")),
            (b"\x03", (42).to_bytes(4, "little")),
            (b"\x04", compact.to_bytes(1)),
            (b"\x05", compact.to_bytes(1)),
            (b"\x06", b"\x01"),
        ]
        for key, value in fields:
            kv = key_value(key, value)
            for raw in (psbt_v0_globals(kv), psbt_v0_globals(kv, tx_first=False)):
                self.assertRejected(raw)

    def test_rejects_key_data_on_global_singleton_fields(self):
        fields = [
            (b"\x00\x00", unsigned_tx().serialize()),
            (b"\x02\x00", (2).to_bytes(4, "little")),
            (b"\x03\x00", bytes(4)),
            (b"\x04\x00", compact.to_bytes(1)),
            (b"\x05\x00", compact.to_bytes(1)),
            (b"\x06\x00", b"\x00"),
            (b"\xfb\x00", (2).to_bytes(4, "little")),
        ]
        for key, value in fields:
            self.assertRejected(psbt_v0_globals(key_value(key, value)))

    def test_v0_requires_unsigned_transaction(self):
        self.assertRejected(PSBT.MAGIC + b"\x00")
        version = key_value(b"\xfb", (0).to_bytes(4, "little"))
        self.assertRejected(PSBT.MAGIC + version + b"\x00")

    def test_global_tx_is_read_without_witnesses(self):
        """PSBT.parse() took a zero input count in the global transaction for
        the segwit marker, so BIP174's valid PSBTs without inputs failed, and
        accepted a transaction serialized with witnesses, which BIP174
        forbids. PSBTView already read it without witnesses."""
        for tx in (Transaction(), Transaction(vout=unsigned_tx().vout)):
            raw = PSBT.MAGIC + key_value(b"\x00", tx.serialize()) + b"\x00"
            raw += b"\x00" * len(tx.vout)
            self.assertEqual(PSBT.parse(raw).serialize(), raw)
            self.assertEqual(PSBTView.view(BytesIO(raw)).num_inputs, 0)
        tx = unsigned_tx()
        tx.vin[0].witness = Witness([b"\x01"])
        raw = PSBT.MAGIC + key_value(b"\x00", tx.serialize()) + b"\x00\x00\x00"
        with self.assertRaises((EmbitError, ValueError)):
            PSBT.parse(raw)
        with self.assertRaises((EmbitError, ValueError)):
            PSBTView.view(BytesIO(raw))

    def test_v2_requires_global_transaction_fields(self):
        for required_key in [b"\x02", b"\x04", b"\x05"]:
            fields = tuple(
                field for field in V2_GLOBAL_FIELDS if field[0] != required_key
            )
            self.assertRejected(psbt_v2_globals(fields))

    def test_v2_rejects_malformed_global_fields(self):
        malformed = [
            (b"\x02", b"\x02"),
            (b"\x03", b"\x00"),
            (b"\x04", b""),
            (b"\x04", b"\xfd"),
            (b"\x04", b"\xfd\x00\x00"),
            (b"\x05", b"\x00\x00"),
            (b"\x06", b""),
        ]
        for key, value in malformed:
            fields = tuple(field for field in V2_GLOBAL_FIELDS if field[0] != key)
            self.assertRejected(psbt_v2_globals(fields + ((key, value),)))

    def test_v2_rejects_duplicated_global_fields(self):
        values = dict(V2_GLOBAL_FIELDS)
        values.update({b"\x03": bytes(4), b"\x06": b"\x00"})
        for key in [b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"]:
            fields = V2_GLOBAL_FIELDS
            if key not in dict(fields):
                fields += ((key, values[key]),)
            self.assertRejected(psbt_v2_globals(fields + ((key, values[key]),)))

    def test_valid_v2_global_fields_remain_compatible(self):
        raw = psbt_v2_globals()
        psbt = PSBT.parse(raw)
        view = PSBTView.view(BytesIO(raw))
        self.assertEqual(psbt.version, 2)
        self.assertEqual(psbt.tx_version, 2)
        self.assertEqual(view.version, 2)
        self.assertEqual(view.tx_version, 2)

    def test_empty_v2_serialization_round_trip(self):
        raw = PSBT(version=2).serialize()
        psbt = PSBT.parse(raw)
        view = PSBTView.view(BytesIO(raw))
        self.assertEqual(psbt.tx_version, 2)
        self.assertEqual(len(psbt.inputs), 0)
        self.assertEqual(len(psbt.outputs), 0)
        self.assertEqual(view.tx_version, 2)
        self.assertEqual(view.num_inputs, 0)
        self.assertEqual(view.num_outputs, 0)

    def test_view_rejects_oversized_global_values_before_reading(self):
        for key in [b"\x02", b"\x03", b"\x04", b"\x05", b"\x06", b"\xfb"]:
            raw = PSBT.MAGIC + key_value(key, bytes(10))
            with self.assertRaises(PSBTError):
                PSBTView.view(LimitedReadStream(raw))

    def test_v2_preserves_zero_transaction_version(self):
        fields = tuple(
            (key, bytes(4)) if key == b"\x02" else (key, value)
            for key, value in V2_GLOBAL_FIELDS
        )
        raw = psbt_v2_globals(fields)
        psbt = PSBT.parse(raw)
        view = PSBTView.view(BytesIO(raw))
        self.assertEqual(psbt.tx_version, 0)
        self.assertEqual(psbt.tx.version, 0)
        self.assertEqual(view.tx_version, 0)

    def test_unknown_global_field_with_key_data_remains_compatible(self):
        key = b"\xf0\x00"
        value = b"unknown"
        raw = psbt_v0_globals(key_value(key, value))
        self.assertEqual(PSBT.parse(raw).unknown[key], value)
        self.assertEqual(PSBTView.view(BytesIO(raw)).version, None)

    def test_v0_rejects_v2_output_scope(self):
        raw = psbt_v0()
        output_data = key_value(b"\x03", (1000).to_bytes(8, "little")) + key_value(
            b"\x04", b"\x52"
        )
        invalid = raw[:-1] + output_data + raw[-1:]

        with self.assertRaises(PSBTError):
            PSBT.parse(invalid)
        view = PSBTView.view(BytesIO(invalid))
        with self.assertRaises(PSBTError):
            view.output(0)

    def test_v0_rejects_v2_prevout_metadata(self):
        raw = psbt_v0()
        previous_tx = Transaction(
            vin=[TransactionInput(bytes([1]) * 32, 0)],
            vout=[TransactionOutput(2000, Script(b"\x51"))],
        )
        input_data = key_value(b"\x00", previous_tx.serialize()) + key_value(
            b"\x0e", bytes(reversed(previous_tx.txid()))
        )
        invalid = raw[:-2] + input_data + raw[-2:]

        with self.assertRaises(PSBTError):
            PSBT.parse(invalid)
        view = PSBTView.view(BytesIO(invalid))
        with self.assertRaises(PSBTError):
            view.input(0)

    def test_v2_scope_fields_remain_compatible(self):
        input_data = (
            key_value(b"\x0e", bytes(range(32)))
            + key_value(b"\x0f", (3).to_bytes(4, "little"))
            + key_value(b"\x10", (4).to_bytes(4, "little"))
            + b"\x00"
        )
        inp = InputScope.read_from(BytesIO(input_data), version=2)
        self.assertEqual(inp.txid, bytes(reversed(range(32))))
        self.assertEqual(inp.vout, 3)
        self.assertEqual(inp.sequence, 4)

        output_data = (
            key_value(b"\x03", (1000).to_bytes(8, "little"))
            + key_value(b"\x04", b"\x51")
            + b"\x00"
        )
        out = OutputScope.read_from(BytesIO(output_data), version=2)
        self.assertEqual(out.value, 1000)
        self.assertEqual(out.script_pubkey, Script(b"\x51"))

    def test_v2_outpoint_fields_are_unique_and_fixed_size(self):
        """One fixed-size value per outpoint key, as PSBTView pins them."""
        fields = [
            (b"\x0e", bytes(range(32))),
            (b"\x0f", (3).to_bytes(4, "little")),
            (b"\x10", (4).to_bytes(4, "little")),
        ]
        for key, value in fields:
            valid = b"".join(key_value(k, v) for k, v in fields)
            cases = [(valid + key_value(key, value), "Duplicated")]
            for bad in (value[:-1], value + b"\x00"):
                data = b"".join(key_value(k, bad if k == key else v) for k, v in fields)
                cases.append((data, "Invalid"))
            for data, kind in cases:
                expected = (
                    "Duplicated previous outpoint field"
                    if kind == "Duplicated"
                    else "Invalid previous outpoint field length"
                )
                with self.assertRaises(PSBTError) as error:
                    InputScope.read_from(BytesIO(data + b"\x00"), version=2)
                self.assertEqual(str(error.exception), expected)

    def test_zero_sequence_is_kept(self):
        """nSequence 0 is valid. PSBT used to replace it with 0xffffffff, so
        a PSBTv0 didn't serialize back to itself and PSBT computed sighashes
        for a different transaction than the PSBT's and PSBTView's."""
        tx = unsigned_tx()
        tx.vin[0].sequence = 0
        utxo = TransactionOutput(2000, Script(b"\x00\x14" + bytes(20)))
        script_code = Script(b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")
        expected = tx.sighash_segwit(0, script_code, 2000)
        for version in (0, 2):
            psbt = PSBT(tx)
            psbt.version = version
            psbt.inputs[0].witness_utxo = utxo
            raw = psbt.serialize()
            parsed = PSBT.parse(raw)
            self.assertEqual(parsed.tx.vin[0].sequence, 0)
            self.assertEqual(parsed.serialize(), raw)
            self.assertEqual(parsed.sighash_segwit(0, script_code, 2000), expected)
            view = PSBTView.view(BytesIO(raw))
            self.assertEqual(view.sighash_segwit(0, script_code, 2000), expected)

    def v2_with_input_field(self, key, value):
        """A PSBTv2 whose only input scope also holds key: value."""
        psbt = PSBT(unsigned_tx())
        psbt.version = 2
        raw = psbt.serialize()
        outputs = key_value(b"\x03", (1000).to_bytes(8, "little"))
        outputs += key_value(b"\x04", b"\x51") + b"\x00"
        self.assertTrue(raw.endswith(b"\x00" + outputs))
        end = len(raw) - len(outputs) - 1
        return raw[:end] + key_value(key, value) + raw[end:]

    def test_v2_required_locktimes_are_in_range(self):
        """BIP370: a 4-byte time of at least 500000000, or a height below it
        and above 0. Any value used to be accepted as an unknown field."""
        time, height = b"\x11", b"\x12"
        for key, locktime in (
            (time, 500000000),
            (time, 0xFFFFFFFF),
            (height, 1),
            (height, 499999999),
        ):
            raw = self.v2_with_input_field(key, locktime.to_bytes(4, "little"))
            self.assertEqual(PSBT.parse(raw).serialize(), raw)
            PSBTView.view(BytesIO(raw)).input(0)
        for key, value in (
            (time, (499999999).to_bytes(4, "little")),
            (time, bytes(4)),
            (height, bytes(4)),
            (height, (500000000).to_bytes(4, "little")),
            (height, b"\xff" * 4),
            (time, (500000000).to_bytes(5, "little")),
            (height, b"\x01\x00\x00"),
        ):
            raw = self.v2_with_input_field(key, value)
            with self.assertRaises(PSBTError):
                PSBT.parse(raw)
            view = PSBTView.view(BytesIO(raw))
            with self.assertRaises(PSBTError):
                view.input(0)

    def test_view_requires_v2_previous_outpoint(self):
        tx = unsigned_tx()
        for missing in (b"\x0e", b"\x0f"):
            psbt = PSBT(tx)
            psbt.version = 2
            raw = psbt.serialize()
            field = (
                key_value(b"\x0e", bytes(reversed(tx.vin[0].txid)))
                if missing == b"\x0e"
                else key_value(b"\x0f", tx.vin[0].vout.to_bytes(4, "little"))
            )
            self.assertEqual(raw.count(field), 1)
            view = PSBTView.view(BytesIO(raw.replace(field, b"")))
            for operation in (lambda: view.vin(0), lambda: view.input(0)):
                with self.assertRaises(PSBTError) as error:
                    operation()
                self.assertEqual(
                    str(error.exception), "Missing previous outpoint in input 0"
                )

    def v2_with_output(self, output_fields):
        """A PSBTv2 whose only output scope holds output_fields."""
        psbt = PSBT(unsigned_tx())
        psbt.version = 2
        # an input amount lets fee() reach the outputs
        psbt.inputs[0].witness_utxo = TransactionOutput(1500, Script(b"\x51"))
        raw = psbt.serialize()
        scope = key_value(b"\x03", (1000).to_bytes(8, "little"))
        scope += key_value(b"\x04", b"\x51")
        self.assertTrue(raw.endswith(scope + b"\x00"))
        return raw[: -len(scope) - 1] + output_fields + b"\x00"

    def test_v2_output_amount_and_script_are_required_and_unique(self):
        amount = key_value(b"\x03", (1000).to_bytes(8, "little"))
        script = key_value(b"\x04", b"\x51")
        for fields in (
            script,
            amount,
            b"",
            amount + amount + script,
            amount + script + key_value(b"\x03", (5).to_bytes(8, "little")),
            amount + script + script,
            key_value(b"\x03", (1000).to_bytes(7, "little")) + script,
            key_value(b"\x03", (1000).to_bytes(9, "little")) + script,
            amount + script + key_value(b"\x03\x00", (5).to_bytes(8, "little")),
        ):
            raw = self.v2_with_output(fields)
            with self.assertRaises(PSBTError):
                PSBT.parse(raw)
            # used to raise TypeError for a missing field and to read the
            # first of two amounts where PSBT.parse() used the last one
            for operation in (
                lambda v: v.vout(0),
                lambda v: v.output(0),
                lambda v: v.fee(verify_utxos=False),
            ):
                with self.assertRaises(PSBTError):
                    operation(PSBTView.view(BytesIO(raw)))
        raw = self.v2_with_output(amount + key_value(b"\xfc\x00", b"x") + script)
        self.assertEqual(PSBT.parse(raw).outputs[0].value, 1000)
        self.assertEqual(PSBTView.view(BytesIO(raw)).vout(0).value, 1000)
        self.assertEqual(PSBTView.view(BytesIO(raw)).fee(verify_utxos=False), 500)

    def test_v2_requires_previous_outpoint(self):
        # PSBTView already required both fields; PSBT.parse() accepted the
        # scope and its tx property failed later
        tx = unsigned_tx()
        for field in (
            key_value(b"\x0e", bytes(reversed(tx.vin[0].txid))),
            key_value(b"\x0f", tx.vin[0].vout.to_bytes(4, "little")),
        ):
            psbt = PSBT(tx)
            psbt.version = 2
            raw = psbt.serialize()
            with self.assertRaises(PSBTError) as error:
                PSBT.parse(raw.replace(field, b""))
            self.assertEqual(
                str(error.exception), "Missing previous outpoint in input 0"
            )

    def test_v2_fields_reject_key_data(self):
        fields = [
            (InputScope, b"\x0e\x00", bytes(32)),
            (OutputScope, b"\x03\x00", (1000).to_bytes(8, "little")),
        ]
        for scope_cls, key, value in fields:
            data = key_value(key, value) + b"\x00"
            with self.assertRaises(PSBTError):
                scope_cls.read_from(BytesIO(data), version=2)

    def test_unknown_fields_with_key_data_remain_compatible(self):
        key = b"\xf0\x00"
        value = b"unknown"
        data = key_value(key, value) + b"\x00"

        inp = InputScope.read_from(BytesIO(data), version=0)
        self.assertEqual(inp.unknown[key], value)

        out = OutputScope.read_from(BytesIO(data), version=2)
        self.assertEqual(out.unknown[key], value)
