"""Order-bound Testnet fee and inventory claims in the shared protocol funding journal."""

from contextlib import contextmanager
import json
import re
import time

from chia_rs import Coin

ROLES = ("receipt_parent", "receipt_fee", "delivery_fee", "return_0", "return_1")
TRANSITIONS = {
    "ALLOCATED": {"UNPAID_RETURNING"},
    "PAID": {"RETURNING", "DELIVERED"},
    "RETURNING": {"RETURNED", "DELIVERED"},
    "RETURNED": {"REFUNDED"},
    "UNPAID_RETURNING": {"ABANDONED"},
}
TERMINAL = {"DELIVERED", "REFUNDED", "ABANDONED"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_card_funding (
    purchase TEXT PRIMARY KEY, binding TEXT NOT NULL, cap INTEGER NOT NULL, till TEXT NOT NULL,
    state TEXT NOT NULL, payment TEXT UNIQUE, outcome TEXT, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS vault_card_inputs (
    purchase TEXT NOT NULL, role TEXT NOT NULL, id TEXT NOT NULL, coin TEXT NOT NULL, locked INTEGER NOT NULL,
    PRIMARY KEY(purchase,role));
CREATE UNIQUE INDEX IF NOT EXISTS one_vault_card_input ON vault_card_inputs(id) WHERE locked=1;
CREATE TABLE IF NOT EXISTS vault_card_funded_stages (
    purchase TEXT NOT NULL, role TEXT NOT NULL, original TEXT NOT NULL, prepared TEXT NOT NULL,
    PRIMARY KEY(purchase,role));
"""


def canonical(data):
    return json.dumps(data, sort_keys=True, allow_nan=False, separators=(",", ":"))


def hx(value):
    return "0x" + value.hex()


class CardFundingJournal:
    """One connection and one writer lock also protect ordinary till reservations."""

    def __init__(self, funding):
        self.funding = funding
        self.db = funding.db

    @contextmanager
    def writing(self):
        with self.funding.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def get(self, purchase):
        with self.funding.lock:
            record = self.db.execute(
                "SELECT * FROM vault_card_funding WHERE purchase=?", (purchase,)
            ).fetchone()
            if not record:
                return None
            coins = {
                r["role"]: Coin.from_json_dict(json.loads(r["coin"]))
                for r in self.db.execute(
                    "SELECT role,coin FROM vault_card_inputs WHERE purchase=?",
                    (purchase,),
                )
            }
            return {
                **dict(record),
                "binding": json.loads(record["binding"]),
                "coins": coins,
            }

    def protected_input(self, inputs):
        with self.funding.lock:
            return any(
                self.db.execute(
                    "SELECT 1 FROM vault_card_inputs WHERE id=? AND locked=1", (hx(i),)
                ).fetchone()
                for i in inputs
            )

    def allocate(self, binding, till, cap, coins, reservations):
        purchase = binding["purchase_id"]
        if (
            set(coins) != set(ROLES)
            or len(reservations) != 2
            or type(cap) != int
            or cap <= 0
            or len({c.name() for c in (*coins.values(), *reservations)}) != 7
            or any(
                hx(c.puzzle_hash) != till
                or c.amount < (2 if r == "receipt_parent" else cap)
                for r, c in coins.items()
            )
            or [hx(c.name()) for c in reservations] != binding["reserved_coin_ids"]
        ):
            raise ValueError("Card allocation inputs differ")
        with self.writing():
            previous = self.get(purchase)
            if previous:
                if (
                    previous["binding"] != binding
                    or previous["cap"] != cap
                    or previous["till"] != till
                    or previous["state"] != "ALLOCATED"
                ):
                    raise ValueError("Card allocation already bound")
                return previous
            occupied = self.funding.reserved_coin_ids()
            self.db.execute(
                "INSERT INTO vault_card_funding VALUES(?,?,?,?,'ALLOCATED',NULL,NULL,?)",
                (purchase, canonical(binding), cap, till, int(time.time())),
            )
            for role, coin in dict(
                coins, deed_0=reservations[0], deed_1=reservations[1]
            ).items():
                if hx(coin.name()) in occupied:
                    raise ValueError("Card input is assigned to another operation")
                self.db.execute(
                    "INSERT INTO vault_card_inputs VALUES(?,?,?,?,1)",
                    (purchase, role, hx(coin.name()), canonical(coin.to_json_dict())),
                )
            return self.get(purchase)

    def payment(self, binding, payment):
        if not re.fullmatch(r"pi_[A-Za-z0-9]{6,128}", payment):
            raise ValueError("Invalid Stripe payment reference")
        purchase = binding["purchase_id"]
        with self.writing():
            row = self.get(purchase)
            if (
                not row
                or row["binding"] != binding
                or row["payment"] not in (None, payment)
            ):
                raise ValueError("Card payment does not match funding")
            if row["payment"] == payment:
                return
            if row["state"] != "ALLOCATED":
                raise ValueError("Card allocation is already closed")
            self.db.execute(
                "UPDATE vault_card_funding SET payment=?,state='PAID',updated=? WHERE purchase=?",
                (payment, int(time.time()), purchase),
            )

    def transition(self, purchase, payment, from_states, state, outcome=None):
        with self.writing():
            row = self.get(purchase)
            if (
                not row
                or row["payment"] != payment
                or (not payment and state not in ("UNPAID_RETURNING", "ABANDONED"))
            ):
                raise ValueError("Card payment binding changed")
            encoded = canonical(outcome) if outcome is not None else None
            if row["state"] == state:
                if encoded != row["outcome"]:
                    raise ValueError("Card outcome is immutable")
                return
            if row["state"] not in from_states or state not in TRANSITIONS.get(
                row["state"], ()
            ):
                raise ValueError("Competing card outcome")
            self.db.execute(
                "UPDATE vault_card_funding SET state=?,outcome=?,updated=? WHERE purchase=?",
                (state, encoded, int(time.time()), purchase),
            )
            if state in TERMINAL:
                # Confirmed inputs cannot be reused. Release the *unused* fee coins after finality.
                self.db.execute(
                    "UPDATE vault_card_inputs SET locked=0 WHERE purchase=?",
                    (purchase,),
                )

    def saved_stage(self, purchase, role, original):
        with self.funding.lock:
            row = self.db.execute(
                "SELECT original,prepared FROM vault_card_funded_stages WHERE purchase=? AND role=?",
                (purchase, role),
            ).fetchone()
            if not row:
                return None
            if row["original"] != original:
                raise ValueError("Card stage already has different original bytes")
            return json.loads(row["prepared"])

    def save_stage(self, purchase, role, bundle, prepared):
        original = hx(bundle.name())
        with self.writing():
            row = self.get(purchase)
            expected = (
                {"RETURNING", "UNPAID_RETURNING"}
                if role.startswith("return_")
                else {"PAID"}
            )
            if (
                not row
                or row["state"] not in expected
                or prepared.fee_coin_id != hx(row["coins"][role].name())
            ):
                raise ValueError("Card stage is no longer authorized")
            net = row["binding"]["network"]
            saved = self.saved_stage(purchase, role, original)
            if saved:
                if saved != prepared.to_json():
                    raise ValueError("Card funded bytes already fixed")
                return
            self.db.execute(
                "INSERT INTO vault_card_funded_stages VALUES(?,?,?,?)",
                (purchase, role, original, canonical(prepared.to_json())),
            )
            # Keep all spent inputs quarantined across terminal release and general funding restarts.
            for c in prepared.bundle.removals():
                cid = hx(c.name())
                other = self.db.execute(
                    """SELECT original_id FROM funded_protocol_input_history h WHERE network=? AND coin_id=?
                    AND NOT EXISTS(SELECT 1 FROM funded_protocol_releases r WHERE r.network=h.network AND r.original_id=h.original_id)""",
                    (net, cid),
                ).fetchone()
                # A deterministically rebuilt timeout may conflict with our own earlier
                # delivery attempt. Canonical expiry and both actual spends arbitrate.
                if other and other[0] != original:
                    prior = self.db.execute(
                        "SELECT original FROM vault_card_funded_stages WHERE purchase=? AND role='delivery_fee'",
                        (purchase,),
                    ).fetchone()
                    if not (
                        role.startswith("return_")
                        and cid in row["binding"]["reserved_coin_ids"]
                        and prior
                        and prior[0] == other[0]
                    ):
                        raise ValueError("Conflicting funded input")
                self.db.execute(
                    "INSERT OR IGNORE INTO funded_protocol_input_history VALUES(?,?,?)",
                    (net, cid, original),
                )
