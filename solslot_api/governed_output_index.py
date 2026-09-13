"""Chain-authoritative index for governed purchase delivery outputs.

The purchase artifact and protocol spend authorize delivery.  This index is a
durable read model: it records the exact outputs before submission and marks
them confirmed only after the local Chia node proves the complete atomic set.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator, Mapping, Sequence
from types import MappingProxyType

from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64


PREPARED = "PREPARED"
MEMPOOL = "MEMPOOL"
CONFIRMED = "CONFIRMED"
BLOCKED = "BLOCKED"
SMARTDEED = "smartdeed"
SGT = "sgt"
DELIVERY_KINDS = frozenset({SMARTDEED, SGT})


class GovernedOutputNotFound(LookupError):
    pass


class GovernedOutputConflict(RuntimeError):
    pass


@dataclass(frozen=True, init=False)
class EvaluatedBundleOutputs:
    """One immutable evaluation of one exact local transaction bundle.

    Construct this only after the complete bundle is built. It is request-local:
    no caller-supplied additions and no cache shared with a later or fee-funded
    bundle. Each lookup retains the original exact ancestry checks.
    """

    additions: tuple[Coin, ...]
    _additions_by_id: Mapping[bytes32, Coin]
    _removals_by_id: Mapping[bytes32, Coin]
    _destinations: Mapping[tuple[bytes32, int], tuple[Coin, ...]]

    def __init__(self, bundle: Any) -> None:
        additions = tuple(bundle.additions())
        removals = tuple(bundle.removals())
        object.__setattr__(self, "additions", additions)
        object.__setattr__(self, "_additions_by_id", MappingProxyType(
            {coin.name(): coin for coin in additions}))
        object.__setattr__(self, "_removals_by_id", MappingProxyType(
            {coin.name(): coin for coin in removals}))
        destinations: dict[tuple[bytes32, int], list[Coin]] = {}
        for coin in additions:
            destinations.setdefault((coin.puzzle_hash, int(coin.amount)), []).append(coin)
        object.__setattr__(self, "_destinations", MappingProxyType(
            {key: tuple(coins) for key, coins in destinations.items()}))

    def find_exact_descendant(
        self, *, ancestor_coin_id: bytes32, puzzle_hash: bytes32, amount: int, label: str,
    ) -> Coin:
        """Require one destination reached through created-and-spent parents."""
        matches = self._destinations.get((puzzle_hash, amount), ())
        if len(matches) != 1:
            raise GovernedOutputConflict(
                f"bundle must create exactly one {label} output"
            )
        output = matches[0]
        current = output
        visited: set[bytes32] = set()
        while current.parent_coin_info != ancestor_coin_id:
            parent_id = current.parent_coin_info
            if parent_id in visited:
                raise GovernedOutputConflict(
                    f"{label} output ancestry contains a cycle"
                )
            visited.add(parent_id)
            parent = self._removals_by_id.get(parent_id)
            if (
                parent is None
                or self._additions_by_id.get(parent_id) != parent
                or int(parent.amount) != amount
            ):
                raise GovernedOutputConflict(
                    f"{label} output does not descend from its governed input"
                )
            current = parent
        if ancestor_coin_id not in self._removals_by_id:
            raise GovernedOutputConflict(
                f"{label} governed input is absent from the atomic bundle"
            )
        return output


def find_exact_governed_descendant(
    bundle: Any,
    *,
    ancestor_coin_id: bytes32,
    puzzle_hash: bytes32,
    amount: int,
    label: str,
) -> Coin:
    """Compatibility entry point for a single lookup on one exact bundle."""
    return EvaluatedBundleOutputs(bundle).find_exact_descendant(
        ancestor_coin_id=ancestor_coin_id, puzzle_hash=puzzle_hash,
        amount=amount, label=label,
    )


@dataclass(frozen=True)
class GovernedOutputExpectation:
    ordinal: int
    coin_id: str
    parent_coin_id: str
    puzzle_hash: str
    amount: int
    deed_launcher_id: str | None = None


@dataclass(frozen=True)
class GovernedOutputRecord(GovernedOutputExpectation):
    purchase_id: str = ""
    delivery_kind: str = SMARTDEED
    confirmation_height: int | None = None


@dataclass(frozen=True)
class GovernedDeliveryRecord:
    purchase_id: str
    artifact_hash: str
    rail: str
    delivery_kind: str
    quantity: int
    state: str
    input_coin_ids: tuple[str, ...]
    protocol_bundle_id: str
    spend_bundle_id: str | None
    mempool_observed_at: str | None
    confirmation_height: int | None
    last_error: str | None
    created_at: int
    updated_at: int


class GovernedOutputIndex:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS governed_delivery_operations (
                    purchase_id TEXT PRIMARY KEY,
                    artifact_hash TEXT NOT NULL,
                    rail TEXT NOT NULL,
                    delivery_kind TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    input_coin_ids_json TEXT NOT NULL,
                    protocol_bundle_id TEXT NOT NULL,
                    spend_bundle_id TEXT UNIQUE,
                    mempool_observed_at TEXT,
                    confirmation_height INTEGER,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    CHECK (delivery_kind IN ('smartdeed', 'sgt')),
                    CHECK (quantity >= 1 AND quantity <= 1000000)
                );
                CREATE TABLE IF NOT EXISTS governed_delivery_outputs (
                    purchase_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    delivery_kind TEXT NOT NULL,
                    deed_launcher_id TEXT,
                    coin_id TEXT NOT NULL UNIQUE,
                    parent_coin_id TEXT NOT NULL,
                    puzzle_hash TEXT NOT NULL,
                    amount_text TEXT NOT NULL,
                    confirmation_height INTEGER,
                    PRIMARY KEY (purchase_id, ordinal),
                    FOREIGN KEY (purchase_id)
                        REFERENCES governed_delivery_operations(purchase_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS governed_delivery_state
                    ON governed_delivery_operations(state, updated_at);
                CREATE INDEX IF NOT EXISTS governed_delivery_deed
                    ON governed_delivery_outputs(deed_launcher_id)
                    WHERE deed_launcher_id IS NOT NULL;
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        try:
            yield connection
        finally:
            connection.close()

    def prepare(
        self,
        *,
        purchase_id: str,
        artifact_hash: str,
        rail: str,
        delivery_kind: str,
        quantity: int,
        input_coin_ids: Sequence[str],
        protocol_bundle_id: str,
        outputs: Sequence[GovernedOutputExpectation],
        now: int | None = None,
    ) -> GovernedDeliveryRecord:
        purchase_id = _hex32(purchase_id, "purchase ID")
        artifact_hash = _hex32(artifact_hash, "artifact hash")
        protocol_bundle_id = _hex32(protocol_bundle_id, "protocol bundle ID")
        if delivery_kind not in DELIVERY_KINDS:
            raise ValueError("delivery kind must be smartdeed or sgt")
        if not rail:
            raise ValueError("delivery rail is required")
        normalized_inputs = _canonical_ids(input_coin_ids, "input coin")
        normalized_outputs = _validate_outputs(
            outputs,
            delivery_kind=delivery_kind,
            quantity=quantity,
        )
        timestamp = int(time.time()) if now is None else now
        inputs_json = json.dumps(list(normalized_inputs))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if existing is None:
                try:
                    connection.execute(
                        """
                        INSERT INTO governed_delivery_operations(
                            purchase_id,artifact_hash,rail,delivery_kind,quantity,
                            state,input_coin_ids_json,protocol_bundle_id,
                            created_at,updated_at
                        ) VALUES (?,?,?,?,?,'PREPARED',?,?,?,?)
                        """,
                        (
                            purchase_id,
                            artifact_hash,
                            rail,
                            delivery_kind,
                            quantity,
                            inputs_json,
                            protocol_bundle_id,
                            timestamp,
                            timestamp,
                        ),
                    )
                    for output in normalized_outputs:
                        connection.execute(
                            """
                            INSERT INTO governed_delivery_outputs(
                                purchase_id,ordinal,delivery_kind,deed_launcher_id,
                                coin_id,parent_coin_id,puzzle_hash,amount_text
                            ) VALUES (?,?,?,?,?,?,?,?)
                            """,
                            (
                                purchase_id,
                                output.ordinal,
                                delivery_kind,
                                output.deed_launcher_id,
                                output.coin_id,
                                output.parent_coin_id,
                                output.puzzle_hash,
                                str(output.amount),
                            ),
                        )
                except sqlite3.IntegrityError as exc:
                    connection.execute("ROLLBACK")
                    raise GovernedOutputConflict(
                        "a governed output is already committed to another purchase"
                    ) from exc
            else:
                rows = connection.execute(
                    """SELECT * FROM governed_delivery_outputs
                       WHERE purchase_id=? ORDER BY ordinal""",
                    (purchase_id,),
                ).fetchall()
                if not _operation_matches(
                    existing,
                    artifact_hash=artifact_hash,
                    rail=rail,
                    delivery_kind=delivery_kind,
                    quantity=quantity,
                    input_coin_ids_json=inputs_json,
                    protocol_bundle_id=protocol_bundle_id,
                ) or tuple(_expectation(row) for row in rows) != normalized_outputs:
                    connection.execute("ROLLBACK")
                    raise GovernedOutputConflict(
                        "purchase ID is already bound to another governed output set"
                    )
            row = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _operation(row)

    def bind_submission(
        self,
        purchase_id: str,
        *,
        spend_bundle_id: str,
        input_coin_ids: Sequence[str],
        mempool_observed_at: str,
        now: int | None = None,
    ) -> GovernedDeliveryRecord:
        purchase_id = _hex32(purchase_id, "purchase ID")
        spend_bundle_id = _hex32(spend_bundle_id, "spend bundle ID")
        exact_inputs = _canonical_ids(input_coin_ids, "input coin")
        if not mempool_observed_at:
            raise ValueError("mempool observation is required")
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise GovernedOutputNotFound(purchase_id)
            if row["state"] == BLOCKED:
                connection.execute("ROLLBACK")
                raise GovernedOutputConflict(
                    "blocked governed delivery cannot be changed"
                )
            prepared_inputs = set(json.loads(row["input_coin_ids_json"]))
            if not prepared_inputs.issubset(exact_inputs):
                connection.execute("ROLLBACK")
                raise GovernedOutputConflict(
                    "submitted bundle drops a prepared protocol input"
                )
            existing_bundle = row["spend_bundle_id"]
            if existing_bundle is not None and (
                existing_bundle != spend_bundle_id
                or tuple(json.loads(row["input_coin_ids_json"])) != exact_inputs
            ):
                connection.execute("ROLLBACK")
                raise GovernedOutputConflict(
                    "governed delivery is already bound to another exact bundle"
                )
            connection.execute(
                """
                UPDATE governed_delivery_operations
                SET state=CASE WHEN state='CONFIRMED' THEN state ELSE 'MEMPOOL' END,
                    input_coin_ids_json=?,spend_bundle_id=?,
                    mempool_observed_at=COALESCE(mempool_observed_at,?),
                    updated_at=?
                WHERE purchase_id=? AND state IN ('PREPARED','MEMPOOL','CONFIRMED')
                """,
                (
                    json.dumps(list(exact_inputs)),
                    spend_bundle_id,
                    mempool_observed_at,
                    timestamp,
                    purchase_id,
                ),
            )
            result = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert result is not None
        return _operation(result)

    def record_confirmed(
        self,
        purchase_id: str,
        *,
        confirmation_height: int,
        now: int | None = None,
    ) -> GovernedDeliveryRecord:
        if confirmation_height <= 0:
            raise ValueError("confirmation height must be positive")
        return self._terminal_transition(
            purchase_id,
            state=CONFIRMED,
            confirmation_height=confirmation_height,
            error=None,
            now=now,
        )

    def record_blocked(
        self,
        purchase_id: str,
        *,
        error: str,
        now: int | None = None,
    ) -> GovernedDeliveryRecord:
        if not error:
            raise ValueError("blocked delivery requires an error")
        return self._terminal_transition(
            purchase_id,
            state=BLOCKED,
            confirmation_height=None,
            error=error,
            now=now,
        )

    def _terminal_transition(
        self,
        purchase_id: str,
        *,
        state: str,
        confirmation_height: int | None,
        error: str | None,
        now: int | None,
    ) -> GovernedDeliveryRecord:
        purchase_id = _hex32(purchase_id, "purchase ID")
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise GovernedOutputNotFound(purchase_id)
            if row["state"] == BLOCKED:
                if state == BLOCKED and row["last_error"] == error:
                    connection.execute("COMMIT")
                    return _operation(row)
                connection.execute("ROLLBACK")
                raise GovernedOutputConflict(
                    "blocked governed delivery cannot be changed"
                )
            if row["state"] == CONFIRMED and (
                state != CONFIRMED
                or int(row["confirmation_height"] or 0) != confirmation_height
            ):
                connection.execute("ROLLBACK")
                raise GovernedOutputConflict(
                    "confirmed governed delivery cannot be changed"
                )
            connection.execute(
                """UPDATE governed_delivery_operations
                   SET state=?,confirmation_height=COALESCE(?,confirmation_height),
                       last_error=?,updated_at=? WHERE purchase_id=?""",
                (state, confirmation_height, error, timestamp, purchase_id),
            )
            if confirmation_height is not None:
                connection.execute(
                    """UPDATE governed_delivery_outputs
                       SET confirmation_height=COALESCE(confirmation_height,?)
                       WHERE purchase_id=?""",
                    (confirmation_height, purchase_id),
                )
            result = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert result is not None
        return _operation(result)

    def get(self, purchase_id: str) -> GovernedDeliveryRecord:
        purchase_id = _hex32(purchase_id, "purchase ID")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM governed_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise GovernedOutputNotFound(purchase_id)
        return _operation(row)

    def outputs(self, purchase_id: str) -> tuple[GovernedOutputRecord, ...]:
        purchase_id = _hex32(purchase_id, "purchase ID")
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT * FROM governed_delivery_outputs
                   WHERE purchase_id=? ORDER BY ordinal""",
                (purchase_id,),
            ).fetchall()
        return tuple(_output(row) for row in rows)


async def reconcile_governed_delivery(
    index: GovernedOutputIndex,
    provider: Any,
    purchase_id: str,
) -> GovernedDeliveryRecord:
    operation = index.get(purchase_id)
    if operation.state in {CONFIRMED, BLOCKED}:
        return operation
    outputs = index.outputs(purchase_id)
    heights: list[int] = []
    for output in outputs:
        record = await provider.get_coin_record_by_name(output.coin_id)
        if record is None:
            heights.append(0)
            continue
        coin = _coin_from_record(record)
        if coin is None or (
            _coin_id(coin) != output.coin_id
            or _hex32("0x" + coin.parent_coin_info.hex(), "parent coin ID")
            != output.parent_coin_id
            or _hex32("0x" + coin.puzzle_hash.hex(), "puzzle hash")
            != output.puzzle_hash
            or int(coin.amount) != output.amount
        ):
            return index.record_blocked(
                purchase_id,
                error="a governed delivery coin differs from its committed output",
            )
        heights.append(int(record.get("confirmed_block_index") or 0))
    confirmed = [height for height in heights if height > 0]
    input_heights: list[int] = []
    for coin_id in operation.input_coin_ids:
        record = await provider.get_coin_record_by_name(coin_id)
        input_heights.append(
            int((record or {}).get("spent_block_index") or 0)
            if isinstance(record, Mapping)
            else 0
        )
    if confirmed and len(confirmed) != len(outputs):
        if any(height > 0 for height in input_heights):
            return index.record_blocked(
                purchase_id,
                error="only part of the governed output set exists after settlement",
            )
        return operation
    if not confirmed:
        if any(height > 0 for height in input_heights):
            return index.record_blocked(
                purchase_id,
                error="a delivery input was spent without every governed output",
            )
        return operation
    confirmation_height = confirmed[0]
    if any(height != confirmation_height for height in confirmed):
        return index.record_blocked(
            purchase_id,
            error="governed outputs confirmed at inconsistent heights",
        )
    if not input_heights or any(
        height != confirmation_height for height in input_heights
    ):
        return index.record_blocked(
            purchase_id,
            error="delivery inputs and governed outputs did not settle atomically",
        )
    return index.record_confirmed(
        purchase_id,
        confirmation_height=confirmation_height,
    )


def serialize_governed_delivery(
    operation: GovernedDeliveryRecord,
    outputs: Sequence[GovernedOutputRecord],
) -> dict[str, Any]:
    return {
        "schema": "solslot.governed-delivery-index.v1",
        "purchaseId": operation.purchase_id,
        "artifactHash": operation.artifact_hash,
        "rail": operation.rail,
        "deliveryKind": operation.delivery_kind,
        "quantity": operation.quantity,
        "state": operation.state,
        "spendBundleId": operation.spend_bundle_id,
        "mempoolObservedAt": operation.mempool_observed_at,
        "confirmationHeight": operation.confirmation_height,
        "lastError": operation.last_error,
        "outputs": [
            {
                "ordinal": output.ordinal,
                "deedLauncherId": output.deed_launcher_id,
                "coinId": output.coin_id,
                "parentCoinId": output.parent_coin_id,
                "puzzleHash": output.puzzle_hash,
                "amount": str(output.amount),
                "confirmationHeight": output.confirmation_height,
                "chainConfirmed": output.confirmation_height is not None,
            }
            for output in outputs
        ],
    }


def _validate_outputs(
    outputs: Sequence[GovernedOutputExpectation],
    *,
    delivery_kind: str,
    quantity: int,
) -> tuple[GovernedOutputExpectation, ...]:
    if not outputs or len(outputs) > 100:
        raise ValueError("governed output manifest must contain 1..100 outputs")
    if delivery_kind == SMARTDEED and quantity != len(outputs):
        raise ValueError("SmartDeed quantity must equal its exact output count")
    if delivery_kind == SGT and (len(outputs) != 1 or outputs[0].amount != quantity):
        raise ValueError("SGT quantity must be one exact aggregate CAT output")
    normalized: list[GovernedOutputExpectation] = []
    for expected_ordinal, output in enumerate(outputs):
        if output.ordinal != expected_ordinal:
            raise ValueError("governed output ordinals must be contiguous")
        amount = int(output.amount)
        if amount < 1 or amount > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("governed output amount must be uint64")
        deed_launcher = (
            _hex32(output.deed_launcher_id, "deed launcher ID")
            if output.deed_launcher_id is not None
            else None
        )
        if delivery_kind == SMARTDEED and (deed_launcher is None or amount != 1):
            raise ValueError("each SmartDeed output requires one deed launcher and one mojo")
        if delivery_kind == SGT and deed_launcher is not None:
            raise ValueError("SGT aggregate output cannot carry a deed launcher")
        normalized.append(
            GovernedOutputExpectation(
                ordinal=output.ordinal,
                coin_id=_hex32(output.coin_id, "output coin ID"),
                parent_coin_id=_hex32(output.parent_coin_id, "parent coin ID"),
                puzzle_hash=_hex32(output.puzzle_hash, "output puzzle hash"),
                amount=amount,
                deed_launcher_id=deed_launcher,
            )
        )
    if len({item.coin_id for item in normalized}) != len(normalized):
        raise ValueError("governed output coin IDs must be unique")
    if delivery_kind == SMARTDEED and len(
        {item.deed_launcher_id for item in normalized}
    ) != len(normalized):
        raise ValueError("SmartDeed output launchers must be unique")
    return tuple(normalized)


def _canonical_ids(values: Sequence[str], label: str) -> tuple[str, ...]:
    normalized = tuple(sorted((_hex32(value, label) for value in values)))
    if not normalized or len(normalized) > 102:
        raise ValueError(f"{label} manifest must contain 1..102 values")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} manifest contains duplicates")
    return normalized


def _operation_matches(
    row: sqlite3.Row,
    **expected: Any,
) -> bool:
    return all(row[name] == value for name, value in expected.items())


def _operation(row: sqlite3.Row) -> GovernedDeliveryRecord:
    return GovernedDeliveryRecord(
        purchase_id=str(row["purchase_id"]),
        artifact_hash=str(row["artifact_hash"]),
        rail=str(row["rail"]),
        delivery_kind=str(row["delivery_kind"]),
        quantity=int(row["quantity"]),
        state=str(row["state"]),
        input_coin_ids=tuple(json.loads(row["input_coin_ids_json"])),
        protocol_bundle_id=str(row["protocol_bundle_id"]),
        spend_bundle_id=row["spend_bundle_id"],
        mempool_observed_at=row["mempool_observed_at"],
        confirmation_height=(
            int(row["confirmation_height"])
            if row["confirmation_height"] is not None
            else None
        ),
        last_error=row["last_error"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _expectation(row: sqlite3.Row) -> GovernedOutputExpectation:
    return GovernedOutputExpectation(
        ordinal=int(row["ordinal"]),
        coin_id=str(row["coin_id"]),
        parent_coin_id=str(row["parent_coin_id"]),
        puzzle_hash=str(row["puzzle_hash"]),
        amount=int(row["amount_text"]),
        deed_launcher_id=row["deed_launcher_id"],
    )


def _output(row: sqlite3.Row) -> GovernedOutputRecord:
    value = _expectation(row)
    return GovernedOutputRecord(
        **value.__dict__,
        purchase_id=str(row["purchase_id"]),
        delivery_kind=str(row["delivery_kind"]),
        confirmation_height=(
            int(row["confirmation_height"])
            if row["confirmation_height"] is not None
            else None
        ),
    )


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping):
        return None
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            bytes32.fromhex(str(value["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(value["puzzle_hash"]).removeprefix("0x")),
            uint64(int(value["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _coin_id(coin: Coin) -> str:
    return "0x" + coin.name().hex()


def _hex32(value: str | None, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be hex")
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes")
    return normalized


_cached_indexes: dict[str, GovernedOutputIndex] = {}


def get_governed_output_index(path: str) -> GovernedOutputIndex:
    if path not in _cached_indexes:
        _cached_indexes[path] = GovernedOutputIndex(path)
    return _cached_indexes[path]


__all__ = [
    "BLOCKED",
    "CONFIRMED",
    "GovernedDeliveryRecord",
    "GovernedOutputConflict",
    "GovernedOutputExpectation",
    "GovernedOutputIndex",
    "GovernedOutputNotFound",
    "GovernedOutputRecord",
    "MEMPOOL",
    "PREPARED",
    "SGT",
    "SMARTDEED",
    "get_governed_output_index",
    "reconcile_governed_delivery",
    "serialize_governed_delivery",
]
