import sys
from unittest import TestCase, skipUnless
from embit.psbtview import PSBTView
from embit.psbt import PSBT, InputScope, CompressMode, DerivationPath, PSBTError
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput
from embit import bip32, bip39, ec, script
from binascii import a2b_base64, b2a_base64
from io import BytesIO
from .test_psbt import (
    _fee_attack_fixture,
    _assert_signature_mixing,
    _uncompressed_legacy_fixture,
)

if sys.implementation.name == "cpython":
    import weakref

ROOT = bip32.HDKey.from_seed(
    bip39.mnemonic_to_seed(
        "toy fault beef holiday later unit boring merge shield detail scrap negative"
    )
)
# tprv8ZgxMBicQKsPeDhmZay7WoN2W9gkmZNv4bkPRgCsaqKAnafo2YkpmJFQUAv34PTdYciNteTu8A1tvDUBsusThseGfiPkdFAniazFzxRd8xv

PSBTS = [
    # native segwit single key, 3 inputs 4 outputs, version is None
    "cHNidP8BAP0NAQIAAAADzs+bdp5MDPJOynM/GVqxv0TxNfN65lYTcGjA8cD2NQABAAAAAP3////1a2FpOvW/FfVn5ct5op0HWQPcF4A4CiD1PuhzM0hvrQAAAAAA/f///2MhMb9J3pwquctpXFlr8LsbwD92XoSKkuwvoNt5prEyAQAAAAD9////BJ5YYgIAAAAAFgAUVE9NQrxzbpzaj8DvSA4+Vfb3S8+Aw8kBAAAAACIAILUTol87mgHQEKeZJcuNUJjXFfUupwaSGuS7QTdBQ1TW5pWYAAAAAAAWABSyijJ33ycsST0veZC7xCcjMLvGnoCWmAAAAAAAFgAUfwP8SJ6OrkWYgi79Rmtboh4vb6AAAAAAAAEAcQIAAAABuN9N7UQtW4/kL7p6GZ+7mJBDtdrC/DLvjimTOlG61vwAAAAAAP7///8CZnl3IwEAAAAWABTW7Yti5UnKO3zm7e0HWxgroI9k8YCWmAAAAAAAFgAUCCFopyBBzsmGQ+okmceR7NCUMRkAAAAAAQEfgJaYAAAAAAAWABQIIWinIEHOyYZD6iSZx5Hs0JQxGSIGAqmBsz9+uSoKzzc3UJKj73Z/nJbAJO8qGivBThNWuQtcGCYUvcRUAACAAQAAgAAAAIAAAAAAAgAAAAABAH0CAAAAAWMhMb9J3pwquctpXFlr8LsbwD92XoSKkuwvoNt5prEyAAAAAAD9////AoCWmAAAAAAAFgAUmt3MvhOm8evmqSbslu0VMw4ajTRcLDEBAAAAACIAIAzATi9Gij9I+WDMngJmvUJUfdBpvUc5SHXeB2kErkrHAAAAAAEBH4CWmAAAAAAAFgAUmt3MvhOm8evmqSbslu0VMw4ajTQiBgOBjOkF2dUPQVfZDgvAq1AJnIyXnxIndmAv9CatqeHP9hgmFL3EVAAAgAEAAIAAAACAAAAAAAEAAAAAAQB9AgAAAAG4303tRC1bj+QvunoZn7uYkEO12sL8Mu+OKZM6UbrW/AEAAAAA/f///wKAw8kBAAAAACIAIFwqEzbsUSf+/PC7SPfqGuy75tAydrgFkmv8DAEW6eNi5hwsBAAAAAAWABT9hflT6IkrLKaHS+x3zqee7ExP/AAAAAABAR/mHCwEAAAAABYAFP2F+VPoiSsspodL7HfOp57sTE/8IgYC420o3I+pkBOSVZyER/NTtZTLtP1iIKPdZK99ilI9UDoYJhS9xFQAAIABAACAAAAAgAEAAAAAAAAAAAAAIgICfM8IJ5ATUtpeuQOLpQbXkqvhs5mriKEpWLHod5vWAo4YJhS9xFQAAIABAACAAAAAgAEAAAACAAAAACICAujQqWO9vOEDwyUZqbeseGADN99ME/YWtJJTjW9/ag25GCYUvcRUAACAAQAAgAAAAIAAAAAAAwAAAAA=",
    # same transaction, version = 2
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQMBBQEEAfsEAgAAAAABAHECAAAAAbjfTe1ELVuP5C+6ehmfu5iQQ7Xawvwy744pkzpRutb8AAAAAAD+////AmZ5dyMBAAAAFgAU1u2LYuVJyjt85u3tB1sYK6CPZPGAlpgAAAAAABYAFAghaKcgQc7JhkPqJJnHkezQlDEZAAAAAAEBH4CWmAAAAAAAFgAUCCFopyBBzsmGQ+okmceR7NCUMRkiBgKpgbM/frkqCs83N1CSo+92f5yWwCTvKhorwU4TVrkLXBgmFL3EVAAAgAEAAIAAAACAAAAAAAIAAAABDiDOz5t2nkwM8k7Kcz8ZWrG/RPE183rmVhNwaMDxwPY1AAEPBAEAAAABEAT9////AAEAfQIAAAABYyExv0nenCq5y2lcWWvwuxvAP3ZehIqS7C+g23mmsTIAAAAAAP3///8CgJaYAAAAAAAWABSa3cy+E6bx6+apJuyW7RUzDhqNNFwsMQEAAAAAIgAgDMBOL0aKP0j5YMyeAma9QlR90Gm9RzlIdd4HaQSuSscAAAAAAQEfgJaYAAAAAAAWABSa3cy+E6bx6+apJuyW7RUzDhqNNCIGA4GM6QXZ1Q9BV9kOC8CrUAmcjJefEid2YC/0Jq2p4c/2GCYUvcRUAACAAQAAgAAAAIAAAAAAAQAAAAEOIPVrYWk69b8V9Wfly3minQdZA9wXgDgKIPU+6HMzSG+tAQ8EAAAAAAEQBP3///8AAQB9AgAAAAG4303tRC1bj+QvunoZn7uYkEO12sL8Mu+OKZM6UbrW/AEAAAAA/f///wKAw8kBAAAAACIAIFwqEzbsUSf+/PC7SPfqGuy75tAydrgFkmv8DAEW6eNi5hwsBAAAAAAWABT9hflT6IkrLKaHS+x3zqee7ExP/AAAAAABAR/mHCwEAAAAABYAFP2F+VPoiSsspodL7HfOp57sTE/8IgYC420o3I+pkBOSVZyER/NTtZTLtP1iIKPdZK99ilI9UDoYJhS9xFQAAIABAACAAAAAgAEAAAAAAAAAAQ4gYyExv0nenCq5y2lcWWvwuxvAP3ZehIqS7C+g23mmsTIBDwQBAAAAARAE/f///wABAwieWGICAAAAAAEEFgAUVE9NQrxzbpzaj8DvSA4+Vfb3S88AAQMIgMPJAQAAAAABBCIAILUTol87mgHQEKeZJcuNUJjXFfUupwaSGuS7QTdBQ1TWACICAnzPCCeQE1LaXrkDi6UG15Kr4bOZq4ihKVix6Heb1gKOGCYUvcRUAACAAQAAgAAAAIABAAAAAgAAAAEDCOaVmAAAAAAAAQQWABSyijJ33ycsST0veZC7xCcjMLvGngAiAgLo0KljvbzhA8MlGam3rHhgAzffTBP2FrSSU41vf2oNuRgmFL3EVAAAgAEAAIAAAACAAAAAAAMAAAABAwiAlpgAAAAAAAEEFgAUfwP8SJ6OrkWYgi79Rmtboh4vb6AA",
    # nested segwit, 3 inp 3 outs
    "cHNidP8BAOMCAAAAAxTKkAuekd781k0dtVGHQB6rfsnXbOoRI8nCZaODOTuKAQAAAAD9////GzrJPRcrKOpTM/UuJtU9BHoPOauuwOwTbze8A98e9jkAAAAAAP3///8zUYet5YsLr1JURBtw6y1J+aOIFUYppSUF98NMQ0SGqAEAAAAA/f///wPA4eQAAAAAABYAFDi4Qvb/any4sD/j++An4QeQyZ8ZABu3AAAAAAAWABSZhIQZ8nU642HEO2Ad58HNlLuNX0LFLQAAAAAAF6kUmyPIidm0uYu4R4cd4G/ePLv/KL6HAAAAAAABAHICAAAAAc7Pm3aeTAzyTspzPxlasb9E8TXzeuZWE3BowPHA9jUAAAAAAAD+////Alji3iIBAAAAFgAUhtwMeBRjJ59uRi16BF//sCuKaQ+AlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwAAAAABASCAlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwEEFgAUlGEc5+39qmo7NT7GrA6unMA28sciBgObyQ41qMrOxju4XxzMINIB1ZGui3QjZEVfIZ7WGJnS2xgmFL3EMQAAgAEAAIAAAACAAAAAAAAAAAAAAQByAgAAAAGhyWgevahbYnWS3rmRhpZign4sGaq4mOdM4D8UKs2q1AAAAAAA/v///wKAlpgAAAAAABepFPAAkmx/dRJAKf+Lw49LAzeIh975h/JabSkBAAAAFgAUfWxZ1njvA0Yr7QVYEme4CDHh7qMAAAAAAQEggJaYAAAAAAAXqRTwAJJsf3USQCn/i8OPSwM3iIfe+YcBBBYAFM6hs2GlOxZSDUae67LI3aiHb3G/IgYCtyN18tSmyoFClQl6Fa87TtEnrMZH6NJoRooWChmuHd0YJhS9xDEAAIABAACAAAAAgAAAAAABAAAAAAEAcgIAAAABV2MIaeVqMWANJDD2CUpsLwzV+Kbyg5cpQYob80WZZSMAAAAAAP7///8C8lptKQEAAAAWABTXvwQx1pNX7/TEGt2BYOIovqhL4ICWmAAAAAAAF6kU9x5iJ+lOE1CyDvzfZ+6pFjHKnviHAAAAAAEBIICWmAAAAAAAF6kU9x5iJ+lOE1CyDvzfZ+6pFjHKnviHAQQWABQ5QbIFFdKLyxFSNm1hZ8S/28cjGSIGAz0meCzo95/qUlBrj9hp+T8hPjVPMIsYK7uTj4iq+Wl6GCYUvcQxAACAAQAAgAAAAIAAAAAAAgAAAAAAAAEAFgAUvQVfGjGkvg8XROgHZhlqhzm/ZOkiAgJXWxh/KFZ6O5bcwrw6M8BwIWtYoHYbrU7JqNOgbTtwxBgmFL3EMQAAgAEAAIAAAACAAQAAAAAAAAAA",
    # same psbt, version = 2
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQMBBQEDAfsEAgAAAAABAHICAAAAAc7Pm3aeTAzyTspzPxlasb9E8TXzeuZWE3BowPHA9jUAAAAAAAD+////Alji3iIBAAAAFgAUhtwMeBRjJ59uRi16BF//sCuKaQ+AlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwAAAAABASCAlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwEEFgAUlGEc5+39qmo7NT7GrA6unMA28sciBgObyQ41qMrOxju4XxzMINIB1ZGui3QjZEVfIZ7WGJnS2xgmFL3EMQAAgAEAAIAAAACAAAAAAAAAAAABDiAUypALnpHe/NZNHbVRh0Aeq37J12zqESPJwmWjgzk7igEPBAEAAAABEAT9////AAEAcgIAAAABocloHr2oW2J1kt65kYaWYoJ+LBmquJjnTOA/FCrNqtQAAAAAAP7///8CgJaYAAAAAAAXqRTwAJJsf3USQCn/i8OPSwM3iIfe+YfyWm0pAQAAABYAFH1sWdZ47wNGK+0FWBJnuAgx4e6jAAAAAAEBIICWmAAAAAAAF6kU8ACSbH91EkAp/4vDj0sDN4iH3vmHAQQWABTOobNhpTsWUg1GnuuyyN2oh29xvyIGArcjdfLUpsqBQpUJehWvO07RJ6zGR+jSaEaKFgoZrh3dGCYUvcQxAACAAQAAgAAAAIAAAAAAAQAAAAEOIBs6yT0XKyjqUzP1LibVPQR6DzmrrsDsE283vAPfHvY5AQ8EAAAAAAEQBP3///8AAQByAgAAAAFXYwhp5WoxYA0kMPYJSmwvDNX4pvKDlylBihvzRZllIwAAAAAA/v///wLyWm0pAQAAABYAFNe/BDHWk1fv9MQa3YFg4ii+qEvggJaYAAAAAAAXqRT3HmIn6U4TULIO/N9n7qkWMcqe+IcAAAAAAQEggJaYAAAAAAAXqRT3HmIn6U4TULIO/N9n7qkWMcqe+IcBBBYAFDlBsgUV0ovLEVI2bWFnxL/bxyMZIgYDPSZ4LOj3n+pSUGuP2Gn5PyE+NU8wixgru5OPiKr5aXoYJhS9xDEAAIABAACAAAAAgAAAAAACAAAAAQ4gM1GHreWLC69SVEQbcOstSfmjiBVGKaUlBffDTENEhqgBDwQBAAAAARAE/f///wABAwjA4eQAAAAAAAEEFgAUOLhC9v9qfLiwP+P74CfhB5DJnxkAAQMIABu3AAAAAAABBBYAFJmEhBnydTrjYcQ7YB3nwc2Uu41fAAEAFgAUvQVfGjGkvg8XROgHZhlqhzm/ZOkiAgJXWxh/KFZ6O5bcwrw6M8BwIWtYoHYbrU7JqNOgbTtwxBgmFL3EMQAAgAEAAIAAAACAAQAAAAAAAAABAwhCxS0AAAAAAAEEF6kUmyPIidm0uYu4R4cd4G/ePLv/KL6HAA==",
    # nested segwit multisig
    "cHNidP8BAKYCAAAAAqwnavvdHI4NbOBtVh9gwDMaEihEEDHZGQvtIuDQwsX/AAAAAAD9////YfVl48Yz2drXieVIad5Y7Wi0tSRJtFHrQlEnngrZ3QkBAAAAAP3///8CrMUtAAAAAAAiACDft7hY/3mCaVbzx5iozo/WnZfPkjYLO05Pfhth1z9oFAAbtwAAAAAAFgAU0MSj7wnpl7bpnjl+UY/j5BoRjKFoAAAAAAEAiQIAAAABm3GgisgrZVavQX37IlZb67iWsnsm3xru9yrJN6GOceEBAAAAAP7///8CQEtMAAAAAAAiACASZsoYpJ92dFQsvD9fYXe+wJfyQJTVDkwezKqd6aKnYhpYbSkBAAAAIlEg7/mnoO8sZbhtLWsZcQ33T8XhZi9ewBnqVwM67uve8ywAAAAAAQErQEtMAAAAAAAiACASZsoYpJ92dFQsvD9fYXe+wJfyQJTVDkwezKqd6aKnYgEFR1EhAjR311GagxyF6Y5tm5yzde5b630HlzMMPbp6M+lenp17IQNolXLiiw/tqdaYHAI32eXe2/7BbecUP2gKAu1dFZ91h1KuIgYCNHfXUZqDHIXpjm2bnLN17lvrfQeXMww9unoz6V6enXscJhS9xDAAAIABAACAAAAAgAIAAIAAAAAAAQAAACIGA2iVcuKLD+2p1pgcAjfZ5d7b/sFt5xQ/aAoC7V0Vn3WHHHPF2gowAACAAQAAgAAAAIACAACAAAAAAAEAAAAAAQCJAgAAAAGWtQHBrqExP4b8sds+ifJwkF8f8PeTWCwyc//OqHyfJwEAAAAA/v///wJNQobtAAAAACJRINvp7v+XERaEfoeg9R6/tig4uAF4UqswwDnD/lO97Jt8gJaYAAAAAAAiACBRRsM1i5rrMvkZ0kMKCm3N7ABg5Fon/ogKbtGwQhjU7gAAAAABASuAlpgAAAAAACIAIFFGwzWLmusy+RnSQwoKbc3sAGDkWif+iApu0bBCGNTuAQVHUSEDC5DtLoa61/Kk/pdpu0F9e6nKoRJIB9v7Ni377rZefgEhA/uxUExKakOxWqckxLG/LGuNFSBA/paURtQVNHSEcvIJUq4iBgMLkO0uhrrX8qT+l2m7QX17qcqhEkgH2/s2Lfvutl5+ARxzxdoKMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIgYD+7FQTEpqQ7FapyTEsb8sa40VIED+lpRG1BU0dIRy8gkcJhS9xDAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAABAUdRIQOgfTvgutY8gDXSHJe0EIkNPToZ0uQDr7P8/GgmqiY8diED41V+tIWahSqtEAq6IPVKeX7RITmu5WdtwNFRHa8RujRSriICA6B9O+C61jyANdIcl7QQiQ09OhnS5AOvs/z8aCaqJjx2HHPF2gowAACAAQAAgAAAAIACAACAAQAAAAAAAAAiAgPjVX60hZqFKq0QCrog9Up5ftEhOa7lZ23A0VEdrxG6NBwmFL3EMAAAgAEAAIAAAACAAgAAgAEAAAAAAAAAAAA=",
    # same, version 2
    "cHNidP8BAgQCAAAAAQMEaAAAAAEEAQIBBQECAfsEAgAAAAABAIkCAAAAAZtxoIrIK2VWr0F9+yJWW+u4lrJ7Jt8a7vcqyTehjnHhAQAAAAD+////AkBLTAAAAAAAIgAgEmbKGKSfdnRULLw/X2F3vsCX8kCU1Q5MHsyqnemip2IaWG0pAQAAACJRIO/5p6DvLGW4bS1rGXEN90/F4WYvXsAZ6lcDOu7r3vMsAAAAAAEBK0BLTAAAAAAAIgAgEmbKGKSfdnRULLw/X2F3vsCX8kCU1Q5MHsyqnemip2IBBUdRIQI0d9dRmoMchemObZucs3XuW+t9B5czDD26ejPpXp6deyEDaJVy4osP7anWmBwCN9nl3tv+wW3nFD9oCgLtXRWfdYdSriIGAjR311GagxyF6Y5tm5yzde5b630HlzMMPbp6M+lenp17HCYUvcQwAACAAQAAgAAAAIACAACAAAAAAAEAAAAiBgNolXLiiw/tqdaYHAI32eXe2/7BbecUP2gKAu1dFZ91hxxzxdoKMAAAgAEAAIAAAACAAgAAgAAAAAABAAAAAQ4grCdq+90cjg1s4G1WH2DAMxoSKEQQMdkZC+0i4NDCxf8BDwQAAAAAARAE/f///wABAIkCAAAAAZa1AcGuoTE/hvyx2z6J8nCQXx/w95NYLDJz/86ofJ8nAQAAAAD+////Ak1Chu0AAAAAIlEg2+nu/5cRFoR+h6D1Hr+2KDi4AXhSqzDAOcP+U73sm3yAlpgAAAAAACIAIFFGwzWLmusy+RnSQwoKbc3sAGDkWif+iApu0bBCGNTuAAAAAAEBK4CWmAAAAAAAIgAgUUbDNYua6zL5GdJDCgptzewAYORaJ/6ICm7RsEIY1O4BBUdRIQMLkO0uhrrX8qT+l2m7QX17qcqhEkgH2/s2Lfvutl5+ASED+7FQTEpqQ7FapyTEsb8sa40VIED+lpRG1BU0dIRy8glSriIGAwuQ7S6GutfypP6XabtBfXupyqESSAfb+zYt++62Xn4BHHPF2gowAACAAQAAgAAAAIACAACAAAAAAAAAAAAiBgP7sVBMSmpDsVqnJMSxvyxrjRUgQP6WlEbUFTR0hHLyCRwmFL3EMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAAQ4gYfVl48Yz2drXieVIad5Y7Wi0tSRJtFHrQlEnngrZ3QkBDwQBAAAAARAE/f///wABAUdRIQOgfTvgutY8gDXSHJe0EIkNPToZ0uQDr7P8/GgmqiY8diED41V+tIWahSqtEAq6IPVKeX7RITmu5WdtwNFRHa8RujRSriICA6B9O+C61jyANdIcl7QQiQ09OhnS5AOvs/z8aCaqJjx2HHPF2gowAACAAQAAgAAAAIACAACAAQAAAAAAAAAiAgPjVX60hZqFKq0QCrog9Up5ftEhOa7lZ23A0VEdrxG6NBwmFL3EMAAAgAEAAIAAAACAAgAAgAEAAAAAAAAAAQMIrMUtAAAAAAABBCIAIN+3uFj/eYJpVvPHmKjOj9adl8+SNgs7Tk9+G2HXP2gUAAEDCAAbtwAAAAAAAQQWABTQxKPvCemXtumeOX5Rj+PkGhGMoQA=",
]


def _previous_transaction_retention_fixture():
    key = ec.PrivateKey(b"\x02" * 32)
    spk = script.p2wpkh(key.get_public_key())
    previous = [
        Transaction(
            vin=[TransactionInput(bytes([i + 1]) * 32, 0)],
            vout=[TransactionOutput(10_000, spk)]
            + [TransactionOutput(1, script.Script(b"\x51")) for _ in range(1000)],
        )
        for i in range(3)
    ]
    psbt = PSBT(
        Transaction(
            vin=[TransactionInput(tx.txid(), 0) for tx in previous],
            vout=[TransactionOutput(29_000, spk)],
        )
    )
    for inp, tx in zip(psbt.inputs, previous):
        inp.non_witness_utxo = tx
        inp.witness_utxo = tx.vout[0]
    return key, psbt.serialize()


class _PreviousTransactionTrackingView(PSBTView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._previous_transaction_refs = []
        self.peak_live_previous_transactions = 0

    def input(self, i, compress=None):
        inp = super().input(i, compress=compress)
        if inp.non_witness_utxo is not None:
            self._previous_transaction_refs.append(weakref.ref(inp.non_witness_utxo))
            live = sum(ref() is not None for ref in self._previous_transaction_refs)
            self.peak_live_previous_transactions = max(
                self.peak_live_previous_transactions, live
            )
        return inp


def _signing_fixture(n, kind="p2wpkh"):
    """n synthetic inputs with previous transactions, all spendable by one key."""
    key = ec.PrivateKey(b"\x03" * 32)
    pub = key.get_public_key()
    spk = script.p2tr(pub) if kind == "p2tr" else script.p2wpkh(pub)
    previous = [
        Transaction(
            vin=[TransactionInput(bytes([i + 1]) * 32, 0)],
            vout=[TransactionOutput(10_000, spk)],
        )
        for i in range(n)
    ]
    psbt = PSBT(
        Transaction(
            vin=[TransactionInput(tx.txid(), 0) for tx in previous],
            vout=[TransactionOutput(n * 10_000 - 1_000, spk)],
        )
    )
    for inp, tx in zip(psbt.inputs, previous):
        inp.non_witness_utxo = tx
        inp.witness_utxo = tx.vout[0]
    return key, psbt


class _ParseCountingView(PSBTView):
    """Counts input scopes parsed from the stream."""

    parses = 0

    def input(self, i, compress=None):
        self.parses += 1
        return super().input(i, compress=compress)


class _TamperedRereadView(PSBTView):
    """Serves a false amount for input 1 after its first read (mutable storage)."""

    reads = 0

    def input(self, i, compress=None):
        inp = super().input(i, compress=compress)
        if i == 1:
            self.reads += 1
            if self.reads > 1:
                inp.witness_utxo.value = 1
        return inp


def _signature_valid(honest, i, signed):
    """Whether a signature PSBTView released for input i fits the honest PSBT."""
    if signed.final_scriptwitness is not None:  # Taproot key path
        pub = ec.PublicKey.from_xonly(honest.inputs[i].utxo.script_pubkey.data[2:])
        sig = ec.SchnorrSig.parse(signed.final_scriptwitness.items[0])
        return pub.schnorr_verify(sig, honest.sighash(i, sighash=SIGHASH.DEFAULT))
    return any(
        pub.verify(ec.Signature.parse(sig[:-1]), honest.sighash(i))
        for pub, sig in signed.partial_sigs.items()
    )


def _storage_overstating_output(honest, delta):
    """A stream serving `honest` with output 0 raised by `delta`, and the honest bytes.

    Only the amount differs, so the honest bytes can overwrite the stream in
    place, as tampered storage would.
    """
    shown = PSBT.parse(honest.serialize())
    shown.outputs[0].value += delta
    honest_raw, shown_raw = honest.serialize(), shown.serialize()
    assert len(shown_raw) == len(honest_raw)
    return BytesIO(shown_raw), honest_raw


def _storage_swapping_prevout(root, honest, signed):
    """Storage contents for one request of the prevout-swapping attack.

    Returns (shown, real). `shown` replaces input `1 - signed` with a fabricated
    20,000 sat previous transaction that has no derivations, so the wallet treats
    it as a foreign input and signs only input `signed`. Every proof in `shown`
    is valid. `real` is the same bytes with that input's honest outpoint, so the
    two differ only in one previous txid.
    """
    other = 1 - signed
    shown = PSBT.parse(honest.serialize())
    fake = Transaction(
        vin=[TransactionInput(b"\x09" * 32, 0)],
        vout=[
            TransactionOutput(20_000, script.p2wpkh(root.derive([7]).get_public_key()))
        ],
    )
    inp = shown.inputs[other]
    inp.txid, inp.vout = fake.txid(), 0
    inp.non_witness_utxo = fake
    inp.witness_utxo = fake.vout[0]
    inp.witness_script = inp.redeem_script = None
    inp.bip32_derivations = {}
    shown_raw = shown.serialize()
    inp.txid, inp.vout = honest.inputs[other].txid, honest.inputs[other].vout
    real_raw = shown.serialize()
    assert len(shown_raw) == len(real_raw)
    return shown_raw, real_raw


class _PrevoutSwappingView(PSBTView):
    """Mutable storage that serves the real outpoints while hash_prevouts() runs.

    Hostile storage sees reads, not code. The hook stands in for a controller
    that recognises the signer walking every outpoint in turn. A view that read
    the outpoints there would hash the real ones; one that pinned them when
    fee() read them returns that earlier digest.
    """

    shown_raw = None
    real_raw = None

    def _serve(self, raw):
        self.stream.seek(0)
        self.stream.write(raw)

    def hash_prevouts(self):
        self._serve(self.real_raw)
        try:
            return super().hash_prevouts()
        finally:
            self._serve(self.shown_raw)


def _released_scopes(sigs):
    """Per-input scopes written to a signature stream, including before an error."""
    data = sigs.getvalue()
    stream = BytesIO(data)
    scopes = []
    while stream.tell() < len(data):
        scopes.append(InputScope.read_from(stream))
    return scopes


class PSBTViewTest(TestCase):

    def test_signing_input_by_input_parses_each_input_twice(self):
        """One scan per view; each signature re-parses only its own input."""
        n = 8
        for kind in ("p2wpkh", "p2tr"):
            key, psbt = _signing_fixture(n, kind)
            raw = psbt.serialize()
            view = _ParseCountingView.view(BytesIO(raw))
            for i in range(n):
                extra = InputScope(vin=psbt.inputs[i].vin)
                count = view.sign_input(i, key, BytesIO(), extra_scope_data=extra)
                self.assertEqual(count, 1)
            self.assertEqual(view.parses, 2 * n)
            view.clear_cache()
            self.assertTrue(view.verify())
            self.assertEqual(view.parses, 3 * n)

            view = _ParseCountingView.view(BytesIO(raw))
            self.assertEqual(view.fee(), 1_000)
            self.assertEqual(view.sign_with(key, BytesIO()), n)
            self.assertEqual(view.parses, 2 * n)

    def test_cached_scan_still_checks_the_signed_input(self):
        root, honest, requests = _fee_attack_fixture()
        view = PSBTView.view(BytesIO(honest.serialize()))
        self.assertEqual(view.fee(), 99_990_000)  # scans and caches the stream
        # A merged scope with a false amount is still rejected after the scan.
        extra = InputScope(vin=honest.inputs[0].vin)
        extra.witness_utxo = requests[1].inputs[0].witness_utxo
        sigs = BytesIO()
        with self.assertRaises(PSBTError) as error:
            view.sign_input(0, root, sigs, extra_scope_data=extra)
        self.assertEqual(
            str(error.exception), "Witness UTXO does not match previous transaction"
        )
        self.assertEqual(sigs.getvalue(), b"")

        # A merged scope may supply the signed input's previous transaction,
        # but every other input still needs its own.
        request = PSBT.parse(honest.serialize())
        request.inputs[0].non_witness_utxo = None
        view = PSBTView.view(BytesIO(request.serialize()))
        extra = InputScope(vin=honest.inputs[0].vin)
        extra.non_witness_utxo = honest.inputs[0].non_witness_utxo
        self.assertEqual(view.sign_input(0, root, BytesIO(), extra_scope_data=extra), 1)
        with self.assertRaises(PSBTError) as error:
            view.sign_input(1, root, BytesIO())
        self.assertEqual(str(error.exception), "Missing non_witness_utxo")

    def test_sign_with_rechecks_each_input_it_signs(self):
        """Data re-read for signing is checked again, not trusted from the scan."""
        root, honest, _ = _fee_attack_fixture()
        view = _TamperedRereadView.view(BytesIO(honest.serialize()))
        with self.assertRaises(PSBTError) as error:
            view.sign_with(root, BytesIO())
        self.assertEqual(
            str(error.exception), "Witness UTXO does not match previous transaction"
        )

    def test_signatures_commit_to_outputs_fee_reported(self):
        """Outputs re-read for signing must be the ones fee() summed.

        Storage overstates the output until fee() returns, so the wallet shows
        a 100 sat fee. If signing hashes the honest outputs it re-reads, every
        signature is valid for the honest transaction, which pays 1,000 sat.
        One request is enough: no signature mixing is needed.
        """
        for kind in ("p2wpkh", "p2tr"):
            key, honest = _signing_fixture(2, kind)
            stream, honest_raw = _storage_overstating_output(honest, 900)
            view = PSBTView.view(stream)
            self.assertEqual(view.fee(), 100)
            stream.seek(0)
            stream.write(honest_raw)  # storage now serves the honest outputs
            sigs = BytesIO()
            try:
                view.sign_with(key, sigs)
            except PSBTError:
                continue  # refusing to sign is safe
            sigs.seek(0)
            for i in range(view.num_inputs):
                self.assertFalse(
                    _signature_valid(honest, i, InputScope.read_from(sigs)),
                    "%s input %d: signature valid for a %d sat fee; fee() showed 100"
                    % (kind, i, honest.fee()),
                )

    def test_output_reads_after_fee_must_match_it(self):
        """Every later read of an output must return what fee() summed.

        Covers the reads that do not use the cached outputs hash: showing
        outputs, legacy signing and SIGHASH_SINGLE signing.
        """
        root, legacy = _uncompressed_legacy_fixture()
        key, segwit = _signing_fixture(2)
        for honest, operation in (
            (segwit, lambda view, sigs: view.output(0)),
            (segwit, lambda view, sigs: view.vout(0)),
            (legacy, lambda view, sigs: view.sign_with(root, sigs)),
            (
                segwit,
                lambda view, sigs: view.sign_with(key, sigs, sighash=SIGHASH.SINGLE),
            ),
        ):
            stream, honest_raw = _storage_overstating_output(honest, 900)
            view = PSBTView.view(stream)
            self.assertEqual(view.fee(), 100)
            stream.seek(0)
            stream.write(honest_raw)  # storage now serves the honest outputs
            sigs = BytesIO()
            with self.assertRaises(PSBTError) as error:
                operation(view, sigs)
            self.assertEqual(
                str(error.exception), "Output 0 changed after it was checked"
            )
            self.assertEqual(sigs.getvalue(), b"")

    def test_signatures_commit_to_prevouts_fee_reported(self):
        """Outpoints re-read for signing must be the ones fee() checked.

        Real transaction: two wallet inputs of 100,000,000 sat, one output of
        100,010,000 sat, fee 99,990,000 sat. Two requests, each:

        1. Storage shows the other input as a fabricated 20,000 sat previous
           transaction without derivations. Every proof is valid, so fee()
           returns 10,000 and the wallet signs only its own input.
        2. While signing calls hash_prevouts(), storage serves the real outpoint.
        3. A signature hashed over those bytes commits to the real transaction.

        Request A would release input 0's signature and request B input 1's.
        Together they would authorize the real transaction. Refusing to sign is
        safe, and so are signatures that do not fit the real transaction.
        """
        for script_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh"):
            root, honest, _ = _fee_attack_fixture(script_type)
            self.assertEqual(honest.fee(), 99_990_000)
            released = []
            for signed in range(2):
                shown_raw, real_raw = _storage_swapping_prevout(root, honest, signed)
                differing = sum(a != b for a, b in zip(shown_raw, real_raw))
                self.assertTrue(0 < differing <= 32, "only one txid may differ")

                view = _PrevoutSwappingView.view(BytesIO(shown_raw))
                view.shown_raw, view.real_raw = shown_raw, real_raw
                # Shown for approval: the real outputs and a 10,000 sat fee.
                self.assertEqual(view.fee(), 10_000)
                for i in range(view.num_outputs):
                    self.assertEqual(
                        view.vout(i).serialize(), honest.outputs[i].vout.serialize()
                    )

                sigs = BytesIO()
                try:
                    view.sign_with(root, sigs)
                except PSBTError:
                    pass  # refusing is safe; still check what was written
                released.append(
                    [
                        _signature_valid(honest, i, scope)
                        for i, scope in enumerate(_released_scopes(sigs))
                    ]
                )
            self.assertFalse(
                any(any(valid) for valid in released),
                "%s: fee() showed 10,000 sat in both requests, but released "
                "signatures fit the real transaction paying %d sat "
                "(per request, per input: %s)" % (script_type, honest.fee(), released),
            )

    def test_inputs_read_after_fee_must_match_it(self):
        """Outpoints and sequences are read once; later reads return the same.

        After fee(), storage changes input 0's sequence and input 1's txid.
        vin() keeps returning what fee() checked. PSBTv0 scopes take their
        outpoint from that pass; PSBTv2 scopes carry their own fields, so
        re-reading one raises. Either way no signature commits to the change.
        """
        for version in (None, 2):
            key, honest = _signing_fixture(2)
            honest.version = version
            changed = PSBT.parse(honest.serialize())
            changed.inputs[0].sequence = 0xFFFFFFFD
            changed.inputs[1].txid = bytes(32)
            honest_raw, changed_raw = honest.serialize(), changed.serialize()
            self.assertEqual(len(honest_raw), len(changed_raw))

            stream = BytesIO(honest_raw)
            view = PSBTView.view(stream)
            self.assertEqual(view.fee(), 1_000)
            stream.seek(0)
            stream.write(changed_raw)  # storage now serves the changed inputs
            for i in range(view.num_inputs):
                self.assertEqual(
                    view.vin(i).serialize(), honest.inputs[i].vin.serialize()
                )

            sigs = BytesIO()
            if version == 2:
                for operation in (
                    lambda: view.input(0),
                    lambda: view.sign_with(key, sigs),
                ):
                    with self.assertRaises(PSBTError) as error:
                        operation()
                    self.assertEqual(
                        str(error.exception), "Input 0 changed after it was checked"
                    )
                self.assertEqual(sigs.getvalue(), b"")
                continue
            self.assertEqual(view.input(0).sequence, 0xFFFFFFFF)
            self.assertEqual(view.sign_with(key, sigs), 2)
            sigs.seek(0)
            for i in range(view.num_inputs):
                signed = InputScope.read_from(sigs)
                self.assertTrue(_signature_valid(honest, i, signed))
                self.assertFalse(_signature_valid(changed, i, signed))

    def test_v2_duplicate_outpoint_field_is_rejected(self):
        """A PSBTv2 input scope must not name two previous outpoints.

        Static bytes, no storage tampering. Input `other` carries two
        PSBT_IN_PREVIOUS_TXID values: the real txid and the txid of a
        fabricated 20,000 sat transaction whose proof is valid. When the proof
        check took the last value and the signature hash the first, fee()
        showed 10,000 sat and sign_input() released signatures valid for the
        real transaction paying 99,990,000 sat.
        """
        root, honest, _ = _fee_attack_fixture()
        for signed in range(2):
            other = 1 - signed
            shown_raw, _ = _storage_swapping_prevout(root, honest, signed)
            shown = PSBT.parse(shown_raw)
            shown.version = 2
            raw = shown.serialize()
            fake = b"\x01\x0e\x20" + bytes(reversed(shown.inputs[other].txid))
            real = b"\x01\x0e\x20" + bytes(reversed(honest.inputs[other].txid))
            self.assertEqual(raw.count(fake), 1)
            for duplicated in (real + fake, fake + real):
                invalid = raw.replace(fake, duplicated)
                with self.assertRaises(PSBTError) as error:
                    PSBT.parse(invalid)
                self.assertEqual(
                    str(error.exception), "Duplicated previous outpoint field"
                )
                for operation in (
                    lambda view, sigs: view.fee(),
                    lambda view, sigs: view.sign_input(signed, root, sigs),
                    lambda view, sigs: view.sign_with(root, sigs),
                ):
                    view = PSBTView.view(BytesIO(invalid))
                    sigs = BytesIO()
                    with self.assertRaises(PSBTError) as error:
                        operation(view, sigs)
                    self.assertEqual(
                        str(error.exception),
                        "Duplicated previous outpoint field in input %d" % other,
                    )
                    self.assertEqual(sigs.getvalue(), b"")

    @skipUnless(
        sys.implementation.name == "cpython",
        "Transaction-lifetime assertions require CPython reference counting",
    )
    def test_verify_releases_previous_transactions_between_inputs(self):
        _, raw = _previous_transaction_retention_fixture()
        view = _PreviousTransactionTrackingView.view(BytesIO(raw))
        for i in range(view.num_inputs):
            self.assertTrue(view.input(i).verify())
        self.assertEqual(view.peak_live_previous_transactions, 1)

        view.peak_live_previous_transactions = 0
        self.assertTrue(view.verify())
        # The shim lacks assertLessEqual. Check an upper bound, not an exact count:
        # only the current previous transaction may be live.
        self.assertTrue(
            view.peak_live_previous_transactions <= 1,
            "Verification retains the previous proof while parsing the next one",
        )

    @skipUnless(
        sys.implementation.name == "cpython",
        "Transaction-lifetime assertions require CPython reference counting",
    )
    def test_sign_input_releases_previous_transactions_between_inputs(self):
        key, raw = _previous_transaction_retention_fixture()
        view = _PreviousTransactionTrackingView.view(BytesIO(raw))
        self.assertEqual(view.sign_input(0, key, BytesIO()), 1)
        # The shim lacks assertLessEqual. Check an upper bound, not an exact count:
        # the target previous transaction may stay live alongside the current one.
        self.assertTrue(
            view.peak_live_previous_transactions <= 2,
            "Signing should retain only its target proof and the current proof",
        )

    def test_unchecked_option_requires_an_explicit_boolean(self):
        root, _, requests = _fee_attack_fixture()
        view = PSBTView.view(BytesIO(requests[0].serialize()))
        for value in (None, 0, "False"):
            sigs = BytesIO()
            for operation in (
                lambda: view.sign_input(0, root, sigs, verify_utxos=value),
                lambda: view.sign_with(root, sigs, verify_utxos=value),
            ):
                with self.assertRaises(PSBTError) as error:
                    operation()
                self.assertEqual(str(error.exception), "verify_utxos must be a boolean")
            self.assertEqual(sigs.getvalue(), b"")

    def test_default_signing_preflights_every_input(self):
        root, honest, requests = _fee_attack_fixture()
        for conflict in ("missing", "amount", "txid"):
            request = PSBT.parse(honest.serialize())
            if conflict == "missing":
                request.inputs[1].non_witness_utxo = None
                expected = "Missing non_witness_utxo"
            elif conflict == "amount":
                request.inputs[1].witness_utxo = requests[0].inputs[1].witness_utxo
                expected = "Witness UTXO does not match previous transaction"
            else:
                request.inputs[1].non_witness_utxo = honest.inputs[0].non_witness_utxo
                expected = "Previous txid doesn't match non_witness_utxo txid"
            for compress in (CompressMode.KEEP_ALL, CompressMode.PARTIAL):
                view = PSBTView.view(BytesIO(request.serialize()), compress=compress)
                for single_input in (False, True):
                    sigs = BytesIO()
                    with self.assertRaises(PSBTError) as error:
                        if single_input:
                            view.sign_input(0, root.derive([0]).key, sigs)
                        else:
                            view.sign_with(root, sigs)
                    self.assertEqual(str(error.exception), expected)
                    self.assertEqual(sigs.getvalue(), b"")

    def test_batch_signing_skips_foreign_input_without_signing_script(self):
        for script_type in ("p2wsh", "p2sh-p2wpkh"):
            root, honest, _ = _fee_attack_fixture(script_type)
            key = root.derive([0]).key
            honest.inputs[1].witness_script = None
            honest.inputs[1].redeem_script = None
            honest.inputs[1].bip32_derivations = {}
            sc = honest.inputs[0].signing_script
            if sc.script_type() == "p2wpkh":
                sc = script.p2pkh_from_p2wpkh(sc)
            expected = honest.tx.sighash_segwit(0, sc, honest.inputs[0].utxo.value)
            for compress in (CompressMode.KEEP_ALL, CompressMode.PARTIAL):
                for signer in (key, root):
                    view = PSBTView.view(BytesIO(honest.serialize()), compress=compress)
                    self.assertEqual(self._verified_fee(view), 99_990_000)
                    self.assertEqual(view.sign_input(0, signer, BytesIO()), 1)
                    sigs = BytesIO()
                    self.assertEqual(view.sign_with(signer, sigs), 1)
                    sigs.seek(0)
                    signed = InputScope.read_from(sigs)
                    pub = key.get_public_key()
                    sig = signed.partial_sigs[pub]
                    self.assertTrue(pub.verify(ec.Signature.parse(sig[:-1]), expected))
                    self.assertFalse(InputScope.read_from(sigs).partial_sigs)

    def test_batch_signing_preserves_foreign_partial_signature_without_script(self):
        root, honest, _ = _fee_attack_fixture("p2wsh")
        foreign_key = root.derive([1]).key
        self.assertEqual(honest.sign_with(foreign_key), 1)
        foreign_sigs = dict(honest.inputs[1].partial_sigs)
        honest.inputs[1].witness_script = None
        honest.inputs[1].bip32_derivations = {}
        view = PSBTView.view(BytesIO(honest.serialize()))
        sigs = BytesIO()
        self.assertEqual(view.sign_with(root.derive([0]).key, sigs), 1)
        sigs.seek(0)
        self.assertEqual(len(InputScope.read_from(sigs).partial_sigs), 1)
        self.assertEqual(InputScope.read_from(sigs).partial_sigs, foreign_sigs)

    def test_default_signing_verifies_merged_scope(self):
        root, honest, requests = _fee_attack_fixture()
        view = PSBTView.view(BytesIO(honest.serialize()))
        extra = InputScope(vin=honest.inputs[0].vin)
        extra.witness_utxo = requests[1].inputs[0].witness_utxo
        sigs = BytesIO()
        with self.assertRaises(PSBTError) as error:
            view.sign_input(0, root, sigs, extra_scope_data=extra)
        self.assertEqual(
            str(error.exception), "Witness UTXO does not match previous transaction"
        )
        self.assertEqual(sigs.getvalue(), b"")

    def test_default_signing_rejects_substituted_outpoint(self):
        root, honest, _ = _fee_attack_fixture()
        view = PSBTView.view(BytesIO(honest.serialize()))
        sigs = BytesIO()
        with self.assertRaises(PSBTError) as error:
            view.sign_input(0, root, sigs, extra_scope_data=honest.inputs[1])
        self.assertEqual(
            str(error.exception), "Input outpoint does not match transaction"
        )
        self.assertEqual(sigs.getvalue(), b"")

    def test_merged_cached_output_keeps_its_transaction_hash(self):
        root, honest, _ = _fee_attack_fixture()
        forged = PSBT.parse(honest.serialize())
        forged.inputs[0].non_witness_utxo.vout[0].value = 20_000
        forged.inputs[0].witness_utxo.value = 20_000
        for compress in (CompressMode.PARTIAL, CompressMode.KEEP_ALL):
            extra = PSBT.parse(forged.serialize(), compress=compress).inputs[0]
            view = PSBTView.view(
                BytesIO(honest.serialize()), compress=CompressMode.PARTIAL
            )
            sigs = BytesIO()
            with self.assertRaises(PSBTError) as error:
                view.sign_input(0, root, sigs, extra_scope_data=extra)
            self.assertEqual(
                str(error.exception),
                "Previous txid doesn't match non_witness_utxo txid",
            )
            self.assertEqual(sigs.getvalue(), b"")

    def _verified_fee(self, view):
        """Preflight every input before fee approval or any signature output."""
        view.verify()
        input_total = 0
        for i in range(view.num_inputs):
            inp = view.input(i)
            input_total += inp.utxo.value
            del inp
        return input_total - sum(view.vout(i).value for i in range(view.num_outputs))

    def test_segwit_v0_signature_mixing_evidence(self):
        """The streaming signer has the same witness-only trust boundary."""
        for script_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh"):
            root, honest, requests = _fee_attack_fixture(script_type)
            signed_inputs = []
            for request in requests:
                view = PSBTView.view(BytesIO(request.serialize()))
                sigs = BytesIO()
                for i in range(view.num_inputs):
                    self.assertFalse(view.input(i).verify(ignore_missing=True))
                    self.assertEqual(
                        view.sign_input(i, root, sigs, verify_utxos=False), 1
                    )
                    sigs.write(b"\x00")
                sigs.seek(0)
                signed_inputs.append(
                    [InputScope.read_from(sigs) for _ in range(view.num_inputs)]
                )
            _assert_signature_mixing(self, honest, requests, signed_inputs)

    def test_default_signing_blocks_both_attack_requests(self):
        for script_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh"):
            root, _, requests = _fee_attack_fixture(script_type)
            for request in requests:
                view = PSBTView.view(BytesIO(request.serialize()))
                sigs = BytesIO()
                with self.assertRaises(PSBTError) as error:
                    view.sign_with(root, sigs)
                self.assertEqual(str(error.exception), "Missing non_witness_utxo")
                self.assertEqual(sigs.getvalue(), b"")

    def test_script_commitments_before_signing(self):
        for script_type, field, label in (
            ("p2sh-p2wpkh", "redeem_script", "Redeem"),
            ("p2wsh", "witness_script", "Witness"),
        ):
            for missing in (False, True):
                root, honest, _ = _fee_attack_fixture(script_type)
                setattr(
                    honest.inputs[0],
                    field,
                    None if missing else getattr(honest.inputs[1], field),
                )
                view = PSBTView.view(BytesIO(honest.serialize()))
                sigs = BytesIO()
                with self.assertRaises(PSBTError) as error:
                    view.sign_input(0, root, sigs)
                expected = (
                    "Missing " + field.replace("_", " ")
                    if missing
                    else label + " script does not match input UTXO"
                )
                self.assertEqual(str(error.exception), expected)
                self.assertEqual(sigs.getvalue(), b"")

    def test_derived_key_must_belong_to_script(self):
        root, honest, _ = _fee_attack_fixture()
        foreign = root.derive([2]).get_public_key()
        honest.inputs[0].bip32_derivations = {
            foreign: DerivationPath(root.my_fingerprint, [2])
        }
        view = PSBTView.view(BytesIO(honest.serialize()))
        sigs = BytesIO()
        self.assertEqual(view.sign_input(0, root, sigs), 0)
        self.assertEqual(sigs.getvalue(), b"")

    def test_derived_key_requires_full_sec_match(self):
        for compressed in (True, False):
            root, honest, _ = _fee_attack_fixture()
            pub = root.derive([0]).get_public_key()
            negated = ec.PublicKey.parse(bytes([5 - pub.sec()[0]]) + pub.sec()[1:])
            negated.compressed = compressed
            honest.inputs[0].bip32_derivations = {
                negated: DerivationPath(root.my_fingerprint, [0])
            }
            view = PSBTView.view(BytesIO(honest.serialize()))
            sigs = BytesIO()
            with self.assertRaises(PSBTError) as error:
                view.sign_input(0, root, sigs)
            self.assertEqual(str(error.exception), "Derivation path doesn't look right")
            self.assertEqual(sigs.getvalue(), b"")

    def test_sign_uncompressed_legacy_derivation(self):
        root, psbt = _uncompressed_legacy_fixture()
        view = PSBTView.view(BytesIO(psbt.serialize()))
        self.assertTrue(view.verify())
        sigs = BytesIO()
        # The streaming signer must also match the full key point, not reject
        # an uncompressed legacy key because BIP32 uses compressed SEC encoding.
        self.assertEqual(view.sign_input(0, root, sigs), 1)
        sigs.write(b"\x00")
        sigs.seek(0)
        signed = InputScope.read_from(sigs)
        pub = next(iter(psbt.inputs[0].bip32_derivations))
        sig = signed.partial_sigs[pub]
        self.assertEqual(sig[-1], SIGHASH.ALL)
        self.assertTrue(pub.verify(ec.Signature.parse(sig[:-1]), psbt.sighash(0)))

    def test_legacy_witness_utxo_cannot_produce_invalid_signature(self):
        """Reject misplaced witness metadata or sign with the legacy algorithm."""
        root, psbt = _uncompressed_legacy_fixture()
        inp = psbt.inputs[0]
        inp.witness_utxo = inp.non_witness_utxo.vout[inp.vout]
        expected = psbt.tx.sighash_legacy(
            0, inp.non_witness_utxo.vout[inp.vout].script_pubkey, SIGHASH.ALL
        )
        view = PSBTView.view(BytesIO(psbt.serialize()))
        sigs = BytesIO()
        try:
            count = view.sign_with(root, sigs)
        except PSBTError:
            self.assertEqual(sigs.getvalue(), b"")
        else:
            self.assertEqual(count, 1)
            sigs.seek(0)
            signed = InputScope.read_from(sigs)
            pub = next(iter(inp.bip32_derivations))
            sig = signed.partial_sigs[pub]
            self.assertEqual(sig[-1], SIGHASH.ALL)
            self.assertTrue(
                pub.verify(ec.Signature.parse(sig[:-1]), expected),
                "P2PKH signature does not verify against the legacy sighash",
            )

    def test_verify_all_inputs_before_releasing_signatures(self):
        """A bad second input must be found before signing the valid first one."""
        root, honest, requests = _fee_attack_fixture()
        for conflict in ("missing", "amount"):
            request = PSBT.parse(honest.serialize())
            if conflict == "missing":
                request.inputs[1].non_witness_utxo = None
                expected = "Missing non_witness_utxo"
            else:
                request.inputs[1].witness_utxo = requests[0].inputs[1].witness_utxo
                expected = "Witness UTXO does not match previous transaction"
            for compress in (CompressMode.KEEP_ALL, CompressMode.PARTIAL):
                view = PSBTView.view(BytesIO(request.serialize()), compress=compress)
                sigs = BytesIO()
                for operation in (
                    lambda: self._verified_fee(view),
                    lambda: view.sign_with(root, sigs),
                ):
                    with self.assertRaises(PSBTError) as error:
                        operation()
                    self.assertEqual(str(error.exception), expected)
                    self.assertEqual(sigs.getvalue(), b"")

    def test_verified_fee_before_signing(self):
        root, honest, _ = _fee_attack_fixture()
        for compress in (CompressMode.KEEP_ALL, CompressMode.PARTIAL):
            view = PSBTView.view(BytesIO(honest.serialize()), compress=compress)
            self.assertEqual(self._verified_fee(view), 99_990_000)
            sigs = BytesIO()
            self.assertEqual(view.sign_with(root, sigs), 2)
            sigs.seek(0)
            for i in range(view.num_inputs):
                inp = InputScope.read_from(sigs)
                pub = next(iter(honest.inputs[i].bip32_derivations))
                sig = inp.partial_sigs[pub]
                self.assertTrue(
                    pub.verify(ec.Signature.parse(sig[:-1]), honest.sighash(i))
                )

    def test_scopes(self):
        """Tests that PSBT and PSBTView result in the same scopes and other constants"""
        for compress in [
            CompressMode.KEEP_ALL,
            CompressMode.CLEAR_ALL,
            CompressMode.PARTIAL,
        ]:
            for b64 in PSBTS:
                psbt = PSBT.from_string(b64, compress=compress)
                stream = BytesIO(a2b_base64(b64))
                psbtv = PSBTView.view(stream, compress=compress)
                self.assertEqual(len(psbt.inputs), psbtv.num_inputs)
                self.assertEqual(len(psbt.outputs), psbtv.num_outputs)
                self.assertEqual(psbt.version, psbtv.version)
                if psbt.version != 2:
                    self.assertTrue(psbtv.tx_offset > 0)
                # check something left when seek to n-1
                psbtv.seek_to_scope(psbtv.num_inputs + psbtv.num_outputs - 1)
                self.assertEqual(len(stream.read(1)), 1)
                # check nothing left in the stream when seeking to the end
                psbtv.seek_to_scope(psbtv.num_inputs + psbtv.num_outputs)
                self.assertEqual(stream.read(1), b"")
                # check that all scopes are the same in psbt and psbtv
                # check random input scope first
                idx = len(psbt.inputs) // 2
                self.assertEqual(
                    psbt.inputs[idx].serialize(), psbtv.input(idx).serialize()
                )
                # check input scopes sequentially
                for i, inp in enumerate(psbt.inputs):
                    self.assertEqual(inp.serialize(), psbtv.input(i).serialize())
                    self.assertEqual(inp.vin.serialize(), psbtv.vin(i).serialize())
                # check random output scope
                idx = len(psbt.outputs) // 2
                self.assertEqual(
                    psbt.outputs[idx].serialize(), psbtv.output(idx).serialize()
                )
                # check input scopes sequentially
                for i, out in enumerate(psbt.outputs):
                    self.assertEqual(out.serialize(), psbtv.output(i).serialize())
                    self.assertEqual(out.vout.serialize(), psbtv.vout(i).serialize())
                self.assertEqual(psbt.tx_version, psbtv.tx_version)
                self.assertEqual(psbt.locktime, psbtv.locktime)

    def test_sign(self):
        """Test if we can sign psbtview and get the same as from signing psbt"""
        for compress in [
            CompressMode.KEEP_ALL,
            CompressMode.CLEAR_ALL,
            CompressMode.PARTIAL,
        ]:
            for i, b64 in enumerate(PSBTS):
                psbt = PSBT.from_string(b64, compress=compress)
                stream = BytesIO(a2b_base64(b64))
                psbtv = PSBTView.view(stream, compress=compress)

                # incomplete psbtview
                xpsbt = PSBT.from_string(b64, compress=compress)
                # remove derivations and other important data from original
                for sc in xpsbt.inputs:
                    sc.bip32_derivations = {}
                    sc.witness_script = None
                    sc.redeem_script = None

                xstream = BytesIO(xpsbt.serialize())
                xpsbtv = PSBTView.view(xstream, compress=compress)

                csigs1 = psbt.sign_with(ROOT)
                sigs_stream2 = BytesIO()
                csigs2 = psbtv.sign_with(ROOT, sigs_stream2)
                # signing incomplete psbtview
                sigs_stream3 = BytesIO()
                csigs3 = 0
                for i in range(xpsbtv.num_inputs):
                    csigs3 += xpsbtv.sign_input(
                        i,
                        ROOT,
                        sigs_stream3,
                        extra_scope_data=psbt.inputs[i],
                        # Compressed round-trips omit other inputs' previous proofs.
                        verify_utxos=compress == CompressMode.KEEP_ALL,
                    )
                    # add separator
                    sigs_stream3.write(b"\x00")

                self.assertEqual(csigs1, csigs2)
                self.assertEqual(csigs1, csigs3)
                for sigs_stream in [sigs_stream2, sigs_stream3]:
                    sigs_stream.seek(0)
                    # check all sigs
                    signed_inputs = [
                        InputScope.read_from(sigs_stream)
                        for i in range(len(psbt.inputs))
                    ]
                    self.assertEqual(len(signed_inputs), len(psbt.inputs))
                    for i, inp in enumerate(signed_inputs):
                        inp2 = psbt.inputs[i]
                        if inp.partial_sigs != inp2.partial_sigs:
                            print(compress)
                            print(i)
                            print(inp.partial_sigs, inp2.partial_sigs)
                        self.assertEqual(inp.partial_sigs, inp2.partial_sigs)
                    # check serialization with signatures
                    sigs_stream.seek(0)
                ser = BytesIO()
                psbtv.write_to(ser, extra_input_streams=[sigs_stream2])
                for sc in psbt.inputs + psbt.outputs:
                    sc.clear_metadata(compress=compress)
                self.assertEqual(len(ser.getvalue()), len(psbt.serialize()))
                # check compress reduces the size of psbt
                if compress != CompressMode.CLEAR_ALL:
                    sigs_stream2.seek(0)
                    ser2 = BytesIO()
                    psbtv.write_to(
                        ser2,
                        extra_input_streams=[sigs_stream2],
                        compress=CompressMode.CLEAR_ALL,
                    )
                    self.assertTrue(len(ser2.getvalue()) < len(ser.getvalue()))
