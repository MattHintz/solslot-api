"""SQLite-backed mint-proposal store for the Solslot Admin Desk.

Persists the lifecycle of every operator-initiated mint proposal so the
admin desk can survive process restart, surface accurate audit trails,
and enforce uniqueness invariants (one PROPERTY_ID at a time).

Mirrors the architectural pattern of ``vault_db.py``:
  * single-file SQLite database (WAL mode, normal sync) — concurrent
    readers + one writer per process,
  * dataclass record (``StoredMintProposal``) for wire-friendly transport,
  * explicit transaction context manager (``_txn``) with BEGIN IMMEDIATE,
  * ``PRAGMA user_version`` driven schema migrations,
  * threading.RLock around every public method for in-process safety.

Two tables:
  * ``mint_proposals`` — primary lifecycle table (DRAFT → ... → MINTED).
  * ``property_metadata`` — off-chain blobs keyed by deed launcher_id,
    populated only after MINTED.

State transitions are enforced *inside* the store: a caller that asks
to ``set_published`` on a proposal that isn't in DRAFT receives
``InvalidTransition`` rather than a silent no-op.  Each transition is a
discrete public method so the rules are visible at the call site.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Literal, Optional

logger = logging.getLogger(__name__)


# Bumping this triggers ``_migrate`` on next ``MintProposalStore`` open.
SCHEMA_VERSION = 4


# ── Lifecycle state machine ──────────────────────────────────────────────────
ProposalState = Literal[
    "DRAFT",       # operator created in API, not yet on-chain
    "PROPOSED",    # on-chain governance proposal opened (SGT lock)
    "VOTING",      # accumulating committee votes; deadline not reached
    "PASSED",      # quorum reached, awaiting execution
    "FAILED",      # deadline reached without quorum
    "EXECUTED",    # EXECUTE_MINT spend pushed; deed launcher pending
    "MINTED",      # deed singleton confirmed on-chain
    "CANCELED",    # operator-canceled (DRAFT only)
]

ALL_STATES: tuple[str, ...] = (
    "DRAFT", "PROPOSED", "VOTING", "PASSED",
    "FAILED", "EXECUTED", "MINTED", "CANCELED",
)

# Valid forward transitions.  Backwards moves are forbidden.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "DRAFT":    {"PROPOSED", "CANCELED"},
    "PROPOSED": {"VOTING", "FAILED"},
    "VOTING":   {"PASSED", "FAILED"},
    "PASSED":   {"EXECUTED"},
    "EXECUTED": {"MINTED"},
    "FAILED":   set(),
    "MINTED":   set(),
    "CANCELED": set(),
}


class MintProposalStoreError(Exception):
    """Base class for store-level errors."""


class InvalidTransition(MintProposalStoreError):
    """Caller attempted a transition that the lifecycle forbids."""


class DuplicateProperty(MintProposalStoreError):
    """A proposal for the same PROPERTY_ID is already in flight."""


class DuplicateProposalHash(MintProposalStoreError):
    """A proposal with the same on-chain proposal_hash already exists."""


class ProposalNotFound(MintProposalStoreError):
    """No proposal exists with the requested id."""


# ── Data classes ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class StoredMintProposal:
    """One row of the ``mint_proposals`` table.

    Bytes are stored as raw ``BLOB`` (32-byte hashes); the caller can
    convert to ``bytes32`` on the way out.  ``off_chain_metadata`` is a
    JSON-serialisable dict (or None).  Transition timestamps are unix
    seconds (int) — None means the transition hasn't happened.
    """
    id: str
    owner_pubkey: str
    state: str
    par_value: int
    asset_class: str
    property_id: str
    collection_id: str
    share_ppm: int
    jurisdiction: str
    royalty_puzhash: bytes
    royalty_bps: int

    # All four computed hashes depend on the launcher coin id (via
    # the SINGLETON_STRUCT curried into smart_deed_inner) and are
    # therefore None in DRAFT.  They become non-None at the
    # DRAFT → PROPOSED transition (set_published) once a faucet coin
    # has been selected to fund the launcher.
    smart_deed_inner_puzhash: Optional[bytes]
    eve_inner_puzhash: Optional[bytes]
    deed_full_puzhash: Optional[bytes]
    proposal_hash: Optional[bytes]

    proposal_tracker_coin_id: Optional[bytes]
    sgt_lock_coin_id: Optional[bytes]
    proposal_singleton_launcher_id: Optional[bytes]
    property_registry_coin_id: Optional[bytes]
    property_registry_puzzle_hash: Optional[bytes]
    published_bundle_id: Optional[str]
    executed_bundle_id: Optional[str]
    deed_launcher_id: Optional[bytes]

    vote_tally: int
    quorum_required: int
    deadline: Optional[int]

    created_at: int
    published_at: Optional[int]
    executed_at: Optional[int]
    minted_at: Optional[int]

    off_chain_metadata: Optional[dict[str, Any]] = field(default=None)

    def to_public_dict(self) -> dict[str, Any]:
        """Render as a JSON-friendly dict for API responses.

        Bytes columns are 0x-hex.  Nullable fields stay null.  No PII or
        secrets in any column — every field is safe to expose.
        """
        return {
            "id": self.id,
            "owner_pubkey": self.owner_pubkey,
            "state": self.state,
            "par_value": self.par_value,
            "asset_class": self.asset_class,
            "property_id": self.property_id,
            "collection_id": self.collection_id,
            "share_ppm": self.share_ppm,
            "jurisdiction": self.jurisdiction,
            "royalty_puzhash": "0x" + self.royalty_puzhash.hex(),
            "royalty_bps": self.royalty_bps,
            "computed": {
                "smart_deed_inner_puzhash":
                    ("0x" + self.smart_deed_inner_puzhash.hex())
                    if self.smart_deed_inner_puzhash else None,
                "eve_inner_puzhash":
                    ("0x" + self.eve_inner_puzhash.hex())
                    if self.eve_inner_puzhash else None,
                "deed_full_puzhash":
                    ("0x" + self.deed_full_puzhash.hex())
                    if self.deed_full_puzhash else None,
                "proposal_hash":
                    ("0x" + self.proposal_hash.hex())
                    if self.proposal_hash else None,
            },
            "on_chain": {
                "proposal_tracker_coin_id":
                    ("0x" + self.proposal_tracker_coin_id.hex())
                    if self.proposal_tracker_coin_id else None,
                "sgt_lock_coin_id":
                    ("0x" + self.sgt_lock_coin_id.hex())
                    if self.sgt_lock_coin_id else None,
                "proposal_singleton_launcher_id":
                    ("0x" + self.proposal_singleton_launcher_id.hex())
                    if self.proposal_singleton_launcher_id else None,
                "property_registry_coin_id":
                    ("0x" + self.property_registry_coin_id.hex())
                    if self.property_registry_coin_id else None,
                "property_registry_puzzle_hash":
                    ("0x" + self.property_registry_puzzle_hash.hex())
                    if self.property_registry_puzzle_hash else None,
                "deed_launcher_id":
                    ("0x" + self.deed_launcher_id.hex())
                    if self.deed_launcher_id else None,
                "published_bundle_id": self.published_bundle_id,
                "executed_bundle_id": self.executed_bundle_id,
            },
            "vote_tally": self.vote_tally,
            "quorum_required": self.quorum_required,
            "deadline": self.deadline,
            "timestamps": {
                "created_at": self.created_at,
                "published_at": self.published_at,
                "executed_at": self.executed_at,
                "minted_at": self.minted_at,
            },
            "off_chain_metadata": self.off_chain_metadata,
        }


# ── ID generation ────────────────────────────────────────────────────────────
def _new_proposal_id() -> str:
    """Generate a sortable-ish proposal id: ``mp_<ts8><rand16>``.

    8 hex chars of unix timestamp (good for ~1090 years past 1970, when
    unix time exceeds 32 bits the prefix grows to 9 chars and that's
    fine because we only ever use the value as an opaque string),
    followed by 16 hex chars of cryptographically-random suffix to
    make collisions astronomically unlikely without a database round
    trip to check.

    The string is k-sortable: rows created in the same second sort
    arbitrarily, but rows from different seconds sort in creation
    order.  That's a useful default for `ORDER BY id DESC`.
    """
    ts = format(int(time.time()), "x").rjust(8, "0")
    return f"mp_{ts}{secrets.token_hex(8)}"


# ── The store ────────────────────────────────────────────────────────────────
class MintProposalStore:
    """SQLite-backed persistent store for mint proposals.

    Open one instance per process.  ``close()`` is idempotent.  See the
    module docstring for design rationale; see ``vault_db.py`` for the
    sibling vault-registry store that uses the same patterns.
    """

    def __init__(self, path: str | Path, timeout: float = 5.0) -> None:
        self.path = str(path) if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            self.path,
            timeout=timeout,
            isolation_level=None,            # explicit transactions
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()

        self._configure_pragmas()
        self._migrate()
        logger.info(
            "MintProposalStore opened at %s (schema_version=%d)",
            self.path, SCHEMA_VERSION,
        )

    # ── connection setup ───────────────────────────────────────────

    def _configure_pragmas(self) -> None:
        cur = self._conn.cursor()
        if self.path != ":memory:":
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA temp_store=MEMORY")

    def _migrate(self) -> None:
        with self._lock, self._txn() as cur:
            current = cur.execute("PRAGMA user_version").fetchone()[0]
            if current >= SCHEMA_VERSION:
                return
            for v in range(current + 1, SCHEMA_VERSION + 1):
                method = getattr(self, f"_migrate_to_v{v}")
                method(cur)
                cur.execute(f"PRAGMA user_version = {v}")
                logger.info("MintProposalStore migrated to schema v%d", v)

    def _migrate_to_v1(self, cur: sqlite3.Cursor) -> None:
        """Initial schema: ``mint_proposals`` + ``property_metadata``.

        Constraints enforce the non-trivial invariants directly in the
        database so a buggy caller can't corrupt the registry:

          * length(<32-byte field>) == 32 — every puzhash / coin_id must
            be exactly bytes32,
          * ``state`` is one of the eight legal values,
          * ``property_id`` is unique while a proposal is active or
            minted; only failed/canceled rows allow a re-attempt,
          * ``proposal_hash`` is globally unique because two distinct
            proposals can never share the same on-chain identity.
        """
        cur.execute("""
            CREATE TABLE mint_proposals (
                id                          TEXT     PRIMARY KEY NOT NULL,
                owner_pubkey                TEXT     NOT NULL,
                state                       TEXT     NOT NULL,
                par_value                   INTEGER  NOT NULL,
                asset_class                 TEXT     NOT NULL,
                property_id                 TEXT     NOT NULL,
                collection_id               TEXT     NOT NULL,
                share_ppm                   INTEGER  NOT NULL,
                jurisdiction                TEXT     NOT NULL,
                royalty_puzhash             BLOB     NOT NULL,
                royalty_bps                 INTEGER  NOT NULL,

                -- All four computed hashes depend on the chosen
                -- launcher coin id (via the SINGLETON_STRUCT curried
                -- into smart_deed_inner), so they are nullable in
                -- DRAFT and populated atomically by set_published().
                smart_deed_inner_puzhash    BLOB,
                eve_inner_puzhash           BLOB,
                deed_full_puzhash           BLOB,
                proposal_hash               BLOB,

                proposal_tracker_coin_id    BLOB,
                sgt_lock_coin_id            BLOB,
                proposal_singleton_launcher_id BLOB,
                property_registry_coin_id   BLOB,
                property_registry_puzzle_hash BLOB,
                published_bundle_id         TEXT,
                executed_bundle_id          TEXT,
                deed_launcher_id            BLOB,

                vote_tally                  INTEGER  NOT NULL DEFAULT 0,
                quorum_required             INTEGER  NOT NULL,
                deadline                    INTEGER,

                created_at                  INTEGER  NOT NULL,
                published_at                INTEGER,
                executed_at                 INTEGER,
                minted_at                   INTEGER,

                off_chain_metadata          TEXT,

                CHECK (state IN (
                    'DRAFT','PROPOSED','VOTING','PASSED',
                    'FAILED','EXECUTED','MINTED','CANCELED'
                )),
                CHECK (par_value > 0),
                CHECK (share_ppm BETWEEN 1 AND 1000000),
                CHECK (royalty_bps BETWEEN 0 AND 10000),
                CHECK (length(royalty_puzhash)          = 32),
                CHECK (smart_deed_inner_puzhash IS NULL OR length(smart_deed_inner_puzhash) = 32),
                CHECK (eve_inner_puzhash        IS NULL OR length(eve_inner_puzhash)        = 32),
                CHECK (deed_full_puzhash        IS NULL OR length(deed_full_puzhash)        = 32),
                CHECK (proposal_hash            IS NULL OR length(proposal_hash)            = 32),
                CHECK (proposal_tracker_coin_id IS NULL OR length(proposal_tracker_coin_id) = 32),
                CHECK (sgt_lock_coin_id         IS NULL OR length(sgt_lock_coin_id)         = 32),
                CHECK (proposal_singleton_launcher_id IS NULL OR length(proposal_singleton_launcher_id) = 32),
                CHECK (property_registry_coin_id IS NULL OR length(property_registry_coin_id) = 32),
                CHECK (property_registry_puzzle_hash IS NULL OR length(property_registry_puzzle_hash) = 32),
                CHECK (deed_launcher_id         IS NULL OR length(deed_launcher_id)         = 32)
            )
        """)
        # Active-or-minted uniqueness: a property can be in at most one
        # proposal that can still become, or already is, a deed.
        cur.execute("""
            CREATE UNIQUE INDEX idx_mint_proposals_active_property
                ON mint_proposals (property_id)
                WHERE state NOT IN ('FAILED','CANCELED')
        """)
        cur.execute("""
            CREATE UNIQUE INDEX idx_mint_proposals_proposal_hash
                ON mint_proposals (proposal_hash)
        """)
        cur.execute("CREATE INDEX idx_mint_proposals_state        ON mint_proposals (state)")
        cur.execute("CREATE INDEX idx_mint_proposals_owner_pubkey ON mint_proposals (owner_pubkey)")

        # Off-chain metadata, populated at MINTED.
        cur.execute("""
            CREATE TABLE property_metadata (
                deed_launcher_id  BLOB PRIMARY KEY NOT NULL,
                payload_json      TEXT NOT NULL,
                updated_at        INTEGER NOT NULL,
                CHECK (length(deed_launcher_id) = 32)
            )
        """)

    def _migrate_to_v2(self, cur: sqlite3.Cursor) -> None:
        cur.execute("DROP INDEX IF EXISTS idx_mint_proposals_active_property")
        cur.execute("""
            CREATE UNIQUE INDEX idx_mint_proposals_active_property
                ON mint_proposals (property_id)
                WHERE state NOT IN ('FAILED','CANCELED')
        """)

    def _migrate_to_v3(self, cur: sqlite3.Cursor) -> None:
        """Add NAV collection metadata to pre-V3 draft stores."""
        columns = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(mint_proposals)").fetchall()
        }
        if "collection_id" not in columns:
            cur.execute("ALTER TABLE mint_proposals ADD COLUMN collection_id TEXT")
            cur.execute("""
                UPDATE mint_proposals
                SET collection_id = property_id
                WHERE collection_id IS NULL OR collection_id = ''
            """)
        if "share_ppm" not in columns:
            cur.execute(
                "ALTER TABLE mint_proposals "
                "ADD COLUMN share_ppm INTEGER NOT NULL DEFAULT 1000000"
            )

    def _migrate_to_v4(self, cur: sqlite3.Cursor) -> None:
        """Persist every immutable coordinate needed to validate EXECUTE.

        Older stores can continue to read their historical rows, but those
        rows intentionally cannot use the V2 execute path until republished
        into the fresh disposable-genesis state directory.
        """
        columns = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(mint_proposals)").fetchall()
        }
        for name in (
            "proposal_singleton_launcher_id",
            "property_registry_coin_id",
            "property_registry_puzzle_hash",
        ):
            if name not in columns:
                cur.execute(f"ALTER TABLE mint_proposals ADD COLUMN {name} BLOB")

    # ── transaction helper ─────────────────────────────────────────

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        finally:
            cur.close()

    # ── creation ────────────────────────────────────────────────────

    def create(
        self,
        *,
        owner_pubkey: str,
        par_value: int,
        asset_class: str,
        property_id: str,
        collection_id: str,
        share_ppm: int,
        jurisdiction: str,
        royalty_puzhash: bytes,
        royalty_bps: int,
        quorum_required: int,
        off_chain_metadata: Optional[dict[str, Any]] = None,
        proposal_id: Optional[str] = None,
    ) -> StoredMintProposal:
        """Insert a fresh DRAFT proposal carrying only the operator
        metadata fields.

        All four computed puzzle hashes (smart_deed_inner_puzhash,
        eve_inner_puzhash, deed_full_puzhash, proposal_hash) depend on
        the launcher coin id, which is selected at publish time.
        ``set_published`` populates all four atomically.

        Raises:
            DuplicateProperty: a non-terminal proposal already exists
                for the canonicalised ``property_id``.
            ValueError: any input fails its individual validation
                (bytes32 fields, positivity, range), or the
                ``property_id`` collapses to empty after canonicalisation.

        ``property_id`` is canonicalised by ``strip().upper()`` to
        defeat the trivial uniqueness bypass identified in
        POP-CANON-014: SQLite's default BINARY collation would
        otherwise treat ``"US-TX-1234"``, ``"us-tx-1234"``, and
        ``" US-TX-1234 "`` as three distinct active proposals.
        Real-world property identifiers (parcel numbers, MLS ids,
        ISO country / region codes) are conventionally upper-case,
        so canonicalising at the store layer is both safe and
        defence-in-depth against any caller that forgets to
        normalise.
        """
        if not _is_bytes32(royalty_puzhash):
            raise ValueError("royalty_puzhash must be bytes32")
        if par_value <= 0:
            raise ValueError("par_value must be positive")
        if share_ppm <= 0 or share_ppm > 1_000_000:
            raise ValueError("share_ppm must be in 1..1_000_000")
        if not 0 <= royalty_bps <= 10_000:
            raise ValueError("royalty_bps out of range")
        if quorum_required <= 0:
            raise ValueError("quorum_required must be positive")

        # POP-CANON-014: canonicalise property_id before the uniqueness
        # check.  See docstring above.
        canonical_pid = property_id.strip().upper()
        if not canonical_pid:
            raise ValueError("property_id must be non-empty after stripping whitespace")
        property_id = canonical_pid
        collection_id = collection_id.strip().upper()
        if not collection_id:
            raise ValueError("collection_id must be non-empty after stripping whitespace")

        if proposal_id is None:
            proposal_id = _new_proposal_id()
        elif not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", proposal_id):
            raise ValueError(
                "proposal_id must contain only letters, digits, '.', '_', ':', or '-'"
            )
        now = int(time.time())
        metadata_json = json.dumps(off_chain_metadata) if off_chain_metadata else None

        try:
            with self._lock, self._txn() as cur:
                cur.execute(
                    """
                    INSERT INTO mint_proposals (
                        id, owner_pubkey, state,
                        par_value, asset_class, property_id, collection_id, share_ppm, jurisdiction,
                        royalty_puzhash, royalty_bps,
                        vote_tally, quorum_required,
                        created_at, off_chain_metadata
                    ) VALUES (?, ?, 'DRAFT', ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        proposal_id, owner_pubkey,
                        par_value, asset_class, property_id, collection_id, share_ppm, jurisdiction,
                        royalty_puzhash, royalty_bps,
                        quorum_required,
                        now, metadata_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            # SQLite surfaces partial-index violations as
            # "UNIQUE constraint failed: <table>.<column>" — the column
            # name is the only stable signal across SQLite versions.
            msg = str(e)
            if "property_id" in msg:
                raise DuplicateProperty(
                    f"property_id={property_id!r} already has an active proposal"
                ) from e
            raise

        return self._get_or_raise(proposal_id)

    # ── reads ───────────────────────────────────────────────────────

    def get(self, proposal_id: str) -> Optional[StoredMintProposal]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM mint_proposals WHERE id = ?", (proposal_id,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def _get_or_raise(self, proposal_id: str) -> StoredMintProposal:
        rec = self.get(proposal_id)
        if rec is None:
            raise ProposalNotFound(proposal_id)
        return rec

    def get_by_deed_launcher_id(self, deed_launcher_id: bytes) -> Optional[StoredMintProposal]:
        """Return an unambiguous immutable-term witness for a minted launcher."""
        if len(deed_launcher_id) != 32:
            raise ValueError("deed launcher must be 32 bytes")
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM mint_proposals WHERE deed_launcher_id = ? LIMIT 2",
                (deed_launcher_id,),
            ).fetchall()
        if len(rows) > 1:
            raise ValueError("ambiguous mint records for deed launcher")
        return _row_to_record(rows[0]) if rows else None

    def get_by_property_id(self, property_id: str) -> Optional[StoredMintProposal]:
        """Return the *active* (non-terminal) proposal for ``property_id``.

        ``property_id`` is canonicalised the same way ``create()`` does
        (``strip().upper()``) so callers can pass either the raw
        operator input or the canonical form interchangeably
        (POP-CANON-014).

        Useful for the /admin/mint/propose pre-flight check so the API
        can return a friendly 409 instead of a database constraint
        violation."""
        property_id = property_id.strip().upper()
        if not property_id:
            return None
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM mint_proposals
                WHERE property_id = ?
                  AND state NOT IN ('FAILED','CANCELED')
                """,
                (property_id,),
            ).fetchone()
        return _row_to_record(row) if row else None

    def list(
        self,
        *,
        states: Optional[list[str]] = None,
        owner_pubkey: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[StoredMintProposal]:
        """List proposals, newest first.

        Filters compose by AND.  ``states`` is a list of state names;
        ``None`` means no state filter.  ``owner_pubkey`` filters to a
        single proposer.
        """
        if limit <= 0 or limit > 1000:
            raise ValueError("limit must be in 1..1000")
        clauses: list[str] = []
        params: list[Any] = []
        if states:
            placeholders = ",".join("?" * len(states))
            clauses.append(f"state IN ({placeholders})")
            params.extend(states)
        if owner_pubkey:
            clauses.append("owner_pubkey = ?")
            params.append(owner_pubkey)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        params.append(offset)
        sql = (
            "SELECT * FROM mint_proposals "
            f"{where_sql} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [_row_to_record(r) for r in rows]

    def count(self, *, state: Optional[str] = None) -> int:
        """Total number of proposals (optionally filtered by ``state``)."""
        with self._lock:
            if state is None:
                row = self._conn.execute("SELECT COUNT(*) FROM mint_proposals").fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM mint_proposals WHERE state = ?",
                    (state,),
                ).fetchone()
        return int(row[0])

    # ── transitions ─────────────────────────────────────────────────

    def cancel(self, proposal_id: str) -> StoredMintProposal:
        """DRAFT → CANCELED.  No on-chain effect."""
        return self._transition(
            proposal_id,
            target_state="CANCELED",
            updates=[],
        )

    def set_published(
        self,
        proposal_id: str,
        *,
        smart_deed_inner_puzhash: bytes,
        eve_inner_puzhash: bytes,
        deed_full_puzhash: bytes,
        proposal_hash: bytes,
        proposal_tracker_coin_id: bytes,
        sgt_lock_coin_id: bytes,
        proposal_singleton_launcher_id: bytes,
        property_registry_coin_id: bytes,
        property_registry_puzzle_hash: bytes,
        deed_launcher_id: bytes,
        published_bundle_id: str,
        deadline: int,
        off_chain_metadata: Optional[dict[str, Any]] = None,
    ) -> StoredMintProposal:
        """DRAFT → PROPOSED.

        Atomically commits all four launcher-id-dependent computed
        puzzle hashes plus the on-chain coin ids that the
        EXECUTE_MINT spend will later need to reference.

        ``deadline`` is a unix timestamp snapshotted from the
        operator's voting-window choice; the deadline lives on-chain
        inside the tracker singleton state but we cache it here for
        cheap UI lookups.

        Raises:
            DuplicateProposalHash: ``proposal_hash`` collides with a
                previously-published proposal (the on-chain identity
                must be globally unique).
        """
        for label, value in (
            ("smart_deed_inner_puzhash", smart_deed_inner_puzhash),
            ("eve_inner_puzhash",        eve_inner_puzhash),
            ("deed_full_puzhash",        deed_full_puzhash),
            ("proposal_hash",            proposal_hash),
            ("proposal_tracker_coin_id", proposal_tracker_coin_id),
            ("sgt_lock_coin_id",         sgt_lock_coin_id),
            ("proposal_singleton_launcher_id", proposal_singleton_launcher_id),
            ("property_registry_coin_id", property_registry_coin_id),
            ("property_registry_puzzle_hash", property_registry_puzzle_hash),
            ("deed_launcher_id", deed_launcher_id),
        ):
            if not _is_bytes32(value):
                raise ValueError(f"{label} must be bytes32")
        if deadline <= 0:
            raise ValueError("deadline must be positive")

        updates: list[tuple[str, Any]] = [
            ("smart_deed_inner_puzhash", smart_deed_inner_puzhash),
            ("eve_inner_puzhash",        eve_inner_puzhash),
            ("deed_full_puzhash",        deed_full_puzhash),
            ("proposal_hash",            proposal_hash),
            ("proposal_tracker_coin_id", proposal_tracker_coin_id),
            ("sgt_lock_coin_id",         sgt_lock_coin_id),
            ("proposal_singleton_launcher_id", proposal_singleton_launcher_id),
            ("property_registry_coin_id", property_registry_coin_id),
            ("property_registry_puzzle_hash", property_registry_puzzle_hash),
            ("deed_launcher_id", deed_launcher_id),
            ("published_bundle_id", published_bundle_id),
            ("deadline", deadline),
            ("published_at", int(time.time())),
        ]
        if off_chain_metadata is not None:
            updates.append(("off_chain_metadata", json.dumps(off_chain_metadata)))

        try:
            return self._transition(
                proposal_id,
                target_state="PROPOSED",
                updates=updates,
            )
        except sqlite3.IntegrityError as e:
            if "proposal_hash" in str(e):
                raise DuplicateProposalHash(
                    f"proposal_hash {proposal_hash.hex()} already exists"
                ) from e
            raise

    def update_vote_tally(
        self,
        proposal_id: str,
        *,
        vote_tally: int,
    ) -> StoredMintProposal:
        """Update the cached vote tally during PROPOSED/VOTING.

        Doesn't change state; the PROPOSED → VOTING bump happens in
        ``set_voting``.  Tally must monotonically increase (SGT lockups
        are append-only) — we enforce that.
        """
        if vote_tally < 0:
            raise ValueError("vote_tally must be non-negative")
        with self._lock, self._txn() as cur:
            row = cur.execute(
                "SELECT state, vote_tally FROM mint_proposals WHERE id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise ProposalNotFound(proposal_id)
            if row["state"] not in ("PROPOSED", "VOTING"):
                raise InvalidTransition(
                    f"vote tally update only allowed in PROPOSED/VOTING; current={row['state']}"
                )
            if vote_tally < int(row["vote_tally"]):
                raise InvalidTransition(
                    f"vote_tally must monotonically increase: "
                    f"current={row['vote_tally']}, requested={vote_tally}"
                )
            cur.execute(
                "UPDATE mint_proposals SET vote_tally = ? WHERE id = ?",
                (vote_tally, proposal_id),
            )
        return self._get_or_raise(proposal_id)

    def set_voting(self, proposal_id: str) -> StoredMintProposal:
        """PROPOSED → VOTING.

        A purely-cosmetic transition for the UI: tally has at least one
        committee vote on top of the operator's PROPOSE-mode lock.  The
        on-chain semantics don't distinguish PROPOSED from VOTING; this
        is a UX hint.
        """
        return self._transition(
            proposal_id, target_state="VOTING", updates=[],
        )

    def set_passed(self, proposal_id: str) -> StoredMintProposal:
        """VOTING → PASSED.  Quorum reached, deadline arrived."""
        return self._transition(
            proposal_id, target_state="PASSED", updates=[],
        )

    def set_failed(self, proposal_id: str) -> StoredMintProposal:
        """PROPOSED/VOTING → FAILED.  Deadline reached without quorum."""
        return self._transition(
            proposal_id,
            target_state="FAILED",
            updates=[],
            allowed_from={"PROPOSED", "VOTING"},
        )

    def set_executed(
        self,
        proposal_id: str,
        *,
        executed_bundle_id: str,
    ) -> StoredMintProposal:
        """PASSED → EXECUTED.  EXECUTE_MINT bundle pushed to mempool."""
        return self._transition(
            proposal_id,
            target_state="EXECUTED",
            updates=[
                ("executed_bundle_id", executed_bundle_id),
                ("executed_at",        int(time.time())),
            ],
        )

    def set_chain_executed(
        self,
        proposal_id: str,
        *,
        executed_bundle_id: str,
    ) -> StoredMintProposal:
        """Record an accepted canonical chain execution bundle.

        The local vote cache can lag the singleton.  A successfully accepted
        five-spend EXECUTE bundle is stronger evidence than that cache, so the
        canonical execute endpoint may advance from any open voting state.
        The CLVM bundle still enforces quorum and deadline.
        """
        return self._transition(
            proposal_id,
            target_state="EXECUTED",
            updates=[
                ("executed_bundle_id", executed_bundle_id),
                ("executed_at", int(time.time())),
            ],
            allowed_from={"PROPOSED", "VOTING", "PASSED"},
        )

    def set_minted(
        self,
        proposal_id: str,
        *,
        deed_launcher_id: bytes,
    ) -> StoredMintProposal:
        """EXECUTED → MINTED.

        Once the deed singleton is confirmed the operator can populate
        ``property_metadata`` for buyers.  ``deed_launcher_id`` is the
        bytes32 launcher coin id that uniquely identifies the deed
        singleton lineage.
        """
        if not _is_bytes32(deed_launcher_id):
            raise ValueError("deed_launcher_id must be bytes32")
        return self._transition(
            proposal_id,
            target_state="MINTED",
            updates=[
                ("deed_launcher_id", deed_launcher_id),
                ("minted_at",        int(time.time())),
            ],
        )

    def _transition(
        self,
        proposal_id: str,
        *,
        target_state: str,
        updates: list[tuple[str, Any]],
        allowed_from: Optional[set[str]] = None,
    ) -> StoredMintProposal:
        """Generic state-machine transition.

        Reads the current state inside the transaction, validates that
        ``current → target_state`` is allowed (looking the source set
        up in ``ALLOWED_TRANSITIONS`` unless ``allowed_from`` overrides
        it), then applies ``updates`` plus the state column.
        """
        with self._lock, self._txn() as cur:
            row = cur.execute(
                "SELECT state FROM mint_proposals WHERE id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise ProposalNotFound(proposal_id)
            current = row["state"]

            valid_sources = (
                allowed_from
                if allowed_from is not None
                else {s for s, dests in ALLOWED_TRANSITIONS.items() if target_state in dests}
            )
            if current not in valid_sources:
                raise InvalidTransition(
                    f"cannot transition {proposal_id} {current} → {target_state}; "
                    f"allowed sources: {sorted(valid_sources)}"
                )

            assignments = ["state = ?"] + [f"{col} = ?" for col, _ in updates]
            params: list[Any] = [target_state] + [val for _, val in updates] + [proposal_id]
            cur.execute(
                f"UPDATE mint_proposals SET {', '.join(assignments)} WHERE id = ?",
                tuple(params),
            )
        return self._get_or_raise(proposal_id)

    # ── property metadata ───────────────────────────────────────────

    def set_property_metadata(
        self,
        deed_launcher_id: bytes,
        payload: dict[str, Any],
    ) -> None:
        """Insert or replace the off-chain metadata blob for a minted deed.

        The payload is stored as JSON; the schema permits any
        JSON-serialisable shape.  Validation of individual fields is
        the caller's responsibility (the API layer enforces the
        wire schema).
        """
        if not _is_bytes32(deed_launcher_id):
            raise ValueError("deed_launcher_id must be bytes32")
        encoded = json.dumps(payload, separators=(",", ":"))
        now = int(time.time())
        with self._lock, self._txn() as cur:
            cur.execute(
                """
                INSERT INTO property_metadata (deed_launcher_id, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(deed_launcher_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at   = excluded.updated_at
                """,
                (deed_launcher_id, encoded, now),
            )

    def get_property_metadata(self, deed_launcher_id: bytes) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload_json FROM property_metadata WHERE deed_launcher_id = ?",
                (deed_launcher_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload_json"])

    # ── housekeeping ────────────────────────────────────────────────

    def schema_version(self) -> int:
        with self._lock:
            return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def close(self) -> None:
        """Close the SQLite connection.  Idempotent."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.ProgrammingError:
                pass

    def __enter__(self) -> "MintProposalStore":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


# ── helpers ─────────────────────────────────────────────────────────────────
def _is_bytes32(value: Any) -> bool:
    return isinstance(value, (bytes, bytearray)) and len(value) == 32


def _row_to_record(row: sqlite3.Row) -> StoredMintProposal:
    return StoredMintProposal(
        id=str(row["id"]),
        owner_pubkey=str(row["owner_pubkey"]),
        state=str(row["state"]),
        par_value=int(row["par_value"]),
        asset_class=str(row["asset_class"]),
        property_id=str(row["property_id"]),
        collection_id=str(row["collection_id"]),
        share_ppm=int(row["share_ppm"]),
        jurisdiction=str(row["jurisdiction"]),
        royalty_puzhash=bytes(row["royalty_puzhash"]),
        royalty_bps=int(row["royalty_bps"]),

        smart_deed_inner_puzhash=(
            bytes(row["smart_deed_inner_puzhash"])
            if row["smart_deed_inner_puzhash"] is not None else None
        ),
        eve_inner_puzhash=(
            bytes(row["eve_inner_puzhash"])
            if row["eve_inner_puzhash"] is not None else None
        ),
        deed_full_puzhash=(
            bytes(row["deed_full_puzhash"])
            if row["deed_full_puzhash"] is not None else None
        ),
        proposal_hash=(
            bytes(row["proposal_hash"])
            if row["proposal_hash"] is not None else None
        ),

        proposal_tracker_coin_id=(
            bytes(row["proposal_tracker_coin_id"])
            if row["proposal_tracker_coin_id"] is not None else None
        ),
        sgt_lock_coin_id=(
            bytes(row["sgt_lock_coin_id"])
            if row["sgt_lock_coin_id"] is not None else None
        ),
        proposal_singleton_launcher_id=(
            bytes(row["proposal_singleton_launcher_id"])
            if row["proposal_singleton_launcher_id"] is not None else None
        ),
        property_registry_coin_id=(
            bytes(row["property_registry_coin_id"])
            if row["property_registry_coin_id"] is not None else None
        ),
        property_registry_puzzle_hash=(
            bytes(row["property_registry_puzzle_hash"])
            if row["property_registry_puzzle_hash"] is not None else None
        ),
        published_bundle_id=row["published_bundle_id"],
        executed_bundle_id=row["executed_bundle_id"],
        deed_launcher_id=(
            bytes(row["deed_launcher_id"])
            if row["deed_launcher_id"] is not None else None
        ),

        vote_tally=int(row["vote_tally"]),
        quorum_required=int(row["quorum_required"]),
        deadline=int(row["deadline"]) if row["deadline"] is not None else None,

        created_at=int(row["created_at"]),
        published_at=int(row["published_at"]) if row["published_at"] is not None else None,
        executed_at=int(row["executed_at"]) if row["executed_at"] is not None else None,
        minted_at=int(row["minted_at"]) if row["minted_at"] is not None else None,

        off_chain_metadata=(
            json.loads(row["off_chain_metadata"])
            if row["off_chain_metadata"] is not None else None
        ),
    )


__all__ = [
    "ProposalState",
    "ALL_STATES",
    "ALLOWED_TRANSITIONS",
    "StoredMintProposal",
    "MintProposalStore",
    "MintProposalStoreError",
    "InvalidTransition",
    "DuplicateProperty",
    "DuplicateProposalHash",
    "ProposalNotFound",
    "SCHEMA_VERSION",
]
