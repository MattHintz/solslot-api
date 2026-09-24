"""Revisioned SQLite workspace for chain-verifiable property collections.

The legacy mint table remains available for RC16 proposal execution, but new
collections are authored here.  This store intentionally owns its own schema
marker instead of SQLite ``user_version`` because it shares the Admin Desk WAL
database with ``MintProposalStore``.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Iterator, Optional

from fastapi import Depends
from pydantic import ValidationError

from .property_metadata import (
    PropertyAmendmentV1,
    PropertyDossierDraftV1,
    PropertyDossierV1,
    validate_amendment_paths,
)
from .config import Settings, get_settings


COLLECTION_SCHEMA_VERSION = 3
COLLECTION_STATES = ("DRAFT", "REVIEW", "SEALED", "PUBLISHED")
ASSET_STATES = ("PENDING_UPLOAD", "UPLOADED", "VERIFIED", "PINNED", "FAILED")


class CollectionStoreError(Exception):
    pass


class CollectionNotFound(CollectionStoreError):
    pass


class CollectionConflict(CollectionStoreError):
    pass


class CollectionForbidden(CollectionStoreError):
    pass


class CollectionInvalidState(CollectionStoreError):
    pass


class CollectionNotReady(CollectionStoreError):
    def __init__(self, issues: list[dict[str, str]]) -> None:
        super().__init__("collection is not ready to seal")
        self.issues = issues


class CollectionStore:
    """Thread-safe SQLite-WAL store with optimistic revision checks."""

    def __init__(self, path: str | Path, timeout: float = 5.0) -> None:
        self.path = str(path) if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self.path,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._configure()
        self._create_schema()

    def _configure(self) -> None:
        cur = self._conn.cursor()
        if self.path != ":memory:":
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    def _create_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS collection_schema_versions (
                    component TEXT PRIMARY KEY,
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS property_collections (
                    id TEXT PRIMARY KEY,
                    slug TEXT NOT NULL UNIQUE,
                    owner_subject TEXT NOT NULL,
                    owner_auth_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    dossier_json TEXT NOT NULL,
                    canonical_json BLOB,
                    metadata_root BLOB,
                    metadata_anchor_id BLOB,
                    first_proposal_id TEXT,
                    allocation_locked INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    sealed_at INTEGER,
                    published_at INTEGER,
                    CHECK (state IN ('DRAFT','REVIEW','SEALED','PUBLISHED')),
                    CHECK (revision > 0),
                    CHECK (metadata_root IS NULL OR length(metadata_root) = 32),
                    CHECK (metadata_anchor_id IS NULL OR length(metadata_anchor_id) = 32)
                );

                CREATE TABLE IF NOT EXISTS property_collection_deeds (
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    deed_id TEXT NOT NULL COLLATE NOCASE,
                    ordinal INTEGER NOT NULL,
                    share_ppm INTEGER NOT NULL,
                    par_value_mojos TEXT NOT NULL,
                    proposal_id TEXT,
                    proposal_state TEXT NOT NULL DEFAULT 'PLANNED',
                    proposal_hash BLOB,
                    proposal_launcher_id BLOB,
                    deed_launcher_id BLOB,
                    output_coin_id BLOB,
                    publish_bundle_id TEXT,
                    execute_bundle_id TEXT,
                    confirmation_height INTEGER,
                    PRIMARY KEY (collection_id, deed_id),
                    UNIQUE (collection_id, ordinal),
                    CHECK (share_ppm BETWEEN 1 AND 1000000),
                    CHECK (proposal_hash IS NULL OR length(proposal_hash) = 32),
                    CHECK (proposal_launcher_id IS NULL OR length(proposal_launcher_id) = 32),
                    CHECK (deed_launcher_id IS NULL OR length(deed_launcher_id) = 32),
                    CHECK (output_coin_id IS NULL OR length(output_coin_id) = 32)
                );

                CREATE TABLE IF NOT EXISTS property_collection_assets (
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    asset_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    role TEXT,
                    title TEXT,
                    alt_text TEXT,
                    category TEXT,
                    visibility TEXT NOT NULL DEFAULT 'PUBLIC',
                    expected_sha256 TEXT NOT NULL,
                    expected_mime_type TEXT NOT NULL,
                    expected_byte_size INTEGER NOT NULL,
                    object_key TEXT,
                    verified_https_url TEXT,
                    ipfs_cid TEXT,
                    actual_sha256 TEXT,
                    actual_mime_type TEXT,
                    actual_byte_size INTEGER,
                    malware_status TEXT NOT NULL DEFAULT 'PENDING',
                    availability_status TEXT NOT NULL DEFAULT 'PENDING',
                    state TEXT NOT NULL,
                    failure_reason TEXT,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (collection_id, asset_id),
                    CHECK (kind IN ('MEDIA','DOCUMENT')),
                    CHECK (visibility IN ('PUBLIC','PRIVATE')),
                    CHECK (state IN ('PENDING_UPLOAD','UPLOADED','VERIFIED','PINNED','FAILED')),
                    CHECK (expected_byte_size > 0),
                    CHECK (revision > 0)
                );

                CREATE TABLE IF NOT EXISTS property_collection_comments (
                    id TEXT PRIMARY KEY,
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    actor_subject TEXT NOT NULL,
                    section TEXT NOT NULL,
                    body TEXT NOT NULL,
                    blocking INTEGER NOT NULL DEFAULT 1,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    resolved_at INTEGER,
                    resolved_by TEXT
                );

                CREATE TABLE IF NOT EXISTS property_collection_reviews (
                    id TEXT PRIMARY KEY,
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    reviewer_subject TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (decision IN ('APPROVED','CHANGES_REQUESTED')),
                    note TEXT,
                    collection_revision INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS property_metadata_versions (
                    id TEXT PRIMARY KEY,
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    version_kind TEXT NOT NULL,
                    metadata_root BLOB NOT NULL,
                    previous_root BLOB,
                    canonical_json BLOB NOT NULL,
                    envelope_json TEXT,
                    actor_subject TEXT NOT NULL,
                    effective_date TEXT,
                    created_at INTEGER NOT NULL,
                    UNIQUE (collection_id, sequence),
                    CHECK (version_kind IN ('ISSUANCE','OWNER_AMENDMENT')),
                    CHECK (length(metadata_root) = 32),
                    CHECK (previous_root IS NULL OR length(previous_root) = 32)
                );

                CREATE TABLE IF NOT EXISTS property_collection_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    actor_subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS property_anchor_evidence (
                    id TEXT PRIMARY KEY,
                    collection_id TEXT NOT NULL REFERENCES property_collections(id) ON DELETE CASCADE,
                    deed_id TEXT NOT NULL,
                    anchor_coin_id BLOB NOT NULL,
                    spend_bundle_id TEXT,
                    confirmation_height INTEGER,
                    puzzle_solution_hash TEXT,
                    reconstructed_root BLOB,
                    status TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    checked_at INTEGER NOT NULL,
                    UNIQUE (collection_id, anchor_coin_id),
                    CHECK (length(anchor_coin_id) = 32),
                    CHECK (reconstructed_root IS NULL OR length(reconstructed_root) = 32),
                    CHECK (status IN ('PENDING','CONFIRMED','MISMATCH','ORPHANED'))
                );

                CREATE INDEX IF NOT EXISTS idx_property_collections_owner
                    ON property_collections(owner_subject, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_collection_comments_collection
                    ON property_collection_comments(collection_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_collection_audit_collection
                    ON property_collection_audit_events(collection_id, occurred_at);
                """
            )
            comment_columns = {
                row[1] for row in cur.execute("PRAGMA table_info(property_collection_comments)")
            }
            if "blocking" not in comment_columns:
                cur.execute(
                    "ALTER TABLE property_collection_comments ADD COLUMN blocking INTEGER NOT NULL DEFAULT 1"
                )
            asset_columns = {
                row[1] for row in cur.execute("PRAGMA table_info(property_collection_assets)")
            }
            if "visibility" not in asset_columns:
                cur.execute(
                    "ALTER TABLE property_collection_assets ADD COLUMN visibility TEXT NOT NULL DEFAULT 'PUBLIC'"
                )
            cur.execute(
                """
                INSERT INTO collection_schema_versions(component, version)
                VALUES ('chain_verifiable_collections', ?)
                ON CONFLICT(component) DO UPDATE SET version = excluded.version
                """,
                (COLLECTION_SCHEMA_VERSION,),
            )
            cur.close()

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

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def schema_version(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT version FROM collection_schema_versions WHERE component = ?",
                ("chain_verifiable_collections",),
            ).fetchone()
        return int(row[0]) if row else 0

    def create(
        self,
        *,
        collection_id: str,
        title: str,
        owner_subject: str,
        owner_auth_type: str,
        slug: Optional[str] = None,
    ) -> dict[str, Any]:
        now = int(time.time())
        draft = PropertyDossierDraftV1(
            collectionId=collection_id,
            revision=1,
            title=title,
        )
        chosen_slug = slug or _slugify(title)
        if draft.collection_id != collection_id:
            raise ValueError("collection ID must match its metadata representation exactly")
        with self._lock, self._txn() as cur:
            if cur.execute("SELECT 1 FROM property_collections WHERE slug=?", (collection_id,)).fetchone():
                raise CollectionConflict("collection ID conflicts with an existing public slug")
            chosen_slug = self._unique_slug(cur, chosen_slug)
            try:
                cur.execute(
                    """
                    INSERT INTO property_collections(
                        id, slug, owner_subject, owner_auth_type, state, revision,
                        dossier_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'DRAFT', 1, ?, ?, ?)
                    """,
                    (
                        collection_id,
                        chosen_slug,
                        owner_subject.lower(),
                        owner_auth_type,
                        _json(draft.model_dump(mode="json", by_alias=True, exclude_none=True)),
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CollectionConflict(f"collection {collection_id!r} already exists") from exc
            self._audit(cur, collection_id, owner_subject, "COLLECTION_CREATED", {})
        return self.get(collection_id)

    def list(
        self,
        *,
        state: Optional[str] = None,
        owner_subject: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if state:
            if state not in COLLECTION_STATES:
                raise ValueError(f"unknown collection state {state}")
            clauses.append("state = ?")
            params.append(state)
        if owner_subject:
            clauses.append("owner_subject = ?")
            params.append(owner_subject.lower())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.extend([max(1, min(limit, 250)), max(0, offset)])
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM property_collections{where} "
                "ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [self._render_collection(row, include_related=True) for row in rows]

    def get(self, identifier: str, *, include_related: bool = True) -> dict[str, Any]:
        with self._lock:
            row = self._collection_row(identifier, allow_slug=True)
            return self._render_collection(row, include_related=include_related)

    def update_draft(
        self,
        collection_id: str,
        *,
        draft: PropertyDossierDraftV1,
        expected_revision: int,
        actor_subject: str,
        submit_for_review: bool = False,
    ) -> dict[str, Any]:
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            self._require_revision(row, expected_revision)
            if row["state"] not in ("DRAFT", "REVIEW"):
                raise CollectionInvalidState("sealed collections require an owner amendment")
            if draft.collection_id != collection_id:
                raise ValueError("dossier collectionId does not match route collection id")
            previous = PropertyDossierDraftV1.model_validate_json(row["dossier_json"])
            if row["allocation_locked"]:
                _assert_protected_fields_unchanged(previous, draft)
            next_revision = expected_revision + 1
            updated = draft.model_copy(update={"revision": next_revision})
            state = "REVIEW" if submit_for_review else row["state"]
            cur.execute(
                """
                UPDATE property_collections
                SET dossier_json = ?, revision = ?, state = ?, canonical_json = NULL,
                    metadata_root = NULL, updated_at = ?
                WHERE id = ?
                """,
                (
                    _json(updated.model_dump(mode="json", by_alias=True, exclude_none=True)),
                    next_revision,
                    state,
                    int(time.time()),
                    collection_id,
                ),
            )
            self._sync_deeds(cur, collection_id, updated, bool(row["allocation_locked"]))
            self._audit(
                cur,
                collection_id,
                actor_subject,
                "DRAFT_UPDATED",
                {"revision": next_revision, "state": state},
            )
        return self.get(collection_id)

    def declare_asset(
        self,
        collection_id: str,
        *,
        asset_id: str,
        kind: str,
        expected_sha256: str,
        expected_mime_type: str,
        expected_byte_size: int,
        actor_subject: str,
        role: Optional[str] = None,
        title: Optional[str] = None,
        alt_text: Optional[str] = None,
        category: Optional[str] = None,
        visibility: str = "PUBLIC",
    ) -> dict[str, Any]:
        kind = kind.upper()
        if kind not in ("MEDIA", "DOCUMENT"):
            raise ValueError("asset kind must be MEDIA or DOCUMENT")
        visibility = visibility.upper()
        if visibility not in ("PUBLIC", "PRIVATE"):
            raise ValueError("asset visibility must be PUBLIC or PRIVATE")
        if visibility == "PRIVATE" and kind != "DOCUMENT":
            raise ValueError("only documents may be private originals")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise ValueError("expected_sha256 must be 64 hexadecimal characters")
        if expected_byte_size <= 0:
            raise ValueError("expected_byte_size must be positive")
        now = int(time.time())
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            if row["state"] not in ("DRAFT", "REVIEW", "PUBLISHED"):
                raise CollectionInvalidState("assets cannot be changed in this collection state")
            existing = cur.execute(
                "SELECT * FROM property_collection_assets WHERE collection_id = ? AND asset_id = ?",
                (collection_id, asset_id),
            ).fetchone()
            if row["state"] == "PUBLISHED" and existing is not None:
                raise CollectionConflict(
                    "published asset IDs are immutable; declare a new asset ID for an amendment"
                )
            revision = int(existing["revision"]) + 1 if existing else 1
            cur.execute(
                """
                INSERT INTO property_collection_assets(
                    collection_id, asset_id, kind, role, title, alt_text, category, visibility,
                    expected_sha256, expected_mime_type, expected_byte_size,
                    state, revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_UPLOAD', ?, ?, ?)
                ON CONFLICT(collection_id, asset_id) DO UPDATE SET
                    kind=excluded.kind, role=excluded.role, title=excluded.title,
                    alt_text=excluded.alt_text, category=excluded.category,
                    visibility=excluded.visibility,
                    expected_sha256=excluded.expected_sha256,
                    expected_mime_type=excluded.expected_mime_type,
                    expected_byte_size=excluded.expected_byte_size,
                    object_key=NULL, verified_https_url=NULL, ipfs_cid=NULL,
                    actual_sha256=NULL, actual_mime_type=NULL, actual_byte_size=NULL,
                    malware_status='PENDING', availability_status='PENDING',
                    state='PENDING_UPLOAD', failure_reason=NULL,
                    revision=excluded.revision, updated_at=excluded.updated_at
                """,
                (
                    collection_id, asset_id, kind, role, title, alt_text, category, visibility,
                    expected_sha256.lower(), expected_mime_type.lower(), expected_byte_size,
                    revision, now, now,
                ),
            )
            self._audit(
                cur, collection_id, actor_subject, "ASSET_DECLARED",
                {"assetId": asset_id, "revision": revision, "visibility": visibility},
            )
            result = self._render_asset(self._asset_row(collection_id, asset_id, cur=cur))
        return result

    def mark_asset_uploaded(
        self,
        collection_id: str,
        asset_id: str,
        *,
        object_key: str,
        actor_subject: str,
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        return self._update_asset(
            collection_id,
            asset_id,
            actor_subject=actor_subject,
            action="ASSET_UPLOADED",
            expected_revision=expected_revision,
            updates={"object_key": object_key, "state": "UPLOADED", "failure_reason": None},
        )

    def assign_asset_object_key(
        self,
        collection_id: str,
        asset_id: str,
        *,
        object_key: str,
        actor_subject: str,
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        """Remember the presigned destination without claiming upload success."""
        return self._update_asset(
            collection_id,
            asset_id,
            actor_subject=actor_subject,
            action="ASSET_UPLOAD_AUTHORIZED",
            expected_revision=expected_revision,
            updates={"object_key": object_key, "state": "PENDING_UPLOAD"},
        )

    def mark_asset_verified(
        self,
        collection_id: str,
        asset_id: str,
        *,
        actual_sha256: str,
        actual_mime_type: str,
        actual_byte_size: int,
        malware_status: str,
        verified_https_url: Optional[str],
        ipfs_cid: Optional[str],
        availability_status: str,
        actor_subject: str,
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        with self._lock:
            asset = self._asset_row(collection_id, asset_id)
            if expected_revision is not None:
                self._require_revision(asset, expected_revision)
        mismatches: list[str] = []
        if actual_sha256.lower() != asset["expected_sha256"]:
            mismatches.append("SHA-256")
        if actual_mime_type.lower() != asset["expected_mime_type"]:
            mismatches.append("MIME type")
        if int(actual_byte_size) != int(asset["expected_byte_size"]):
            mismatches.append("byte size")
        if mismatches:
            self.mark_asset_failed(
                collection_id,
                asset_id,
                reason="verified bytes do not match declared " + ", ".join(mismatches),
                actor_subject=actor_subject,
                expected_revision=int(asset["revision"]),
            )
            raise CollectionConflict("asset verification mismatch: " + ", ".join(mismatches))
        if asset["visibility"] == "PRIVATE":
            if verified_https_url is not None or ipfs_cid is not None:
                raise CollectionConflict("private originals cannot have public URLs or IPFS CIDs")
            state = "VERIFIED" if malware_status == "CLEAN" else "UPLOADED"
        else:
            state = (
                "PINNED"
                if malware_status == "CLEAN" and availability_status == "HEALTHY" and ipfs_cid
                else "VERIFIED"
            )
        return self._update_asset(
            collection_id,
            asset_id,
            actor_subject=actor_subject,
            action="ASSET_VERIFIED",
            expected_revision=int(asset["revision"]),
            updates={
                "actual_sha256": actual_sha256.lower(),
                "actual_mime_type": actual_mime_type.lower(),
                "actual_byte_size": actual_byte_size,
                "malware_status": malware_status,
                "verified_https_url": verified_https_url,
                "ipfs_cid": ipfs_cid,
                "availability_status": availability_status,
                "state": state,
                "failure_reason": None,
            },
        )

    def mark_asset_failed(
        self,
        collection_id: str,
        asset_id: str,
        *,
        reason: str,
        actor_subject: str,
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        return self._update_asset(
            collection_id,
            asset_id,
            actor_subject=actor_subject,
            action="ASSET_FAILED",
            expected_revision=expected_revision,
            updates={"state": "FAILED", "failure_reason": reason},
        )

    def get_asset(self, collection_id: str, asset_id: str) -> dict[str, Any]:
        with self._lock:
            return self._render_asset(self._asset_row(collection_id, asset_id))

    def authorize_private_asset_download(
        self,
        collection_id: str,
        asset_id: str,
        *,
        actor_subject: str,
    ) -> dict[str, Any]:
        with self._lock, self._txn() as cur:
            self._collection_row(collection_id, cur=cur)
            row = self._asset_row(collection_id, asset_id, cur=cur)
            if row["visibility"] != "PRIVATE":
                raise CollectionForbidden("asset is not a private original")
            if row["state"] != "VERIFIED" or row["malware_status"] != "CLEAN":
                raise CollectionInvalidState("private original is not verified")
            self._audit(
                cur,
                collection_id,
                actor_subject,
                "PRIVATE_DOCUMENT_ACCESSED",
                {"assetId": asset_id},
            )
            result = self._render_asset(row)
        return result

    def add_comment(
        self,
        collection_id: str,
        *,
        actor_subject: str,
        section: str,
        body: str,
        blocking: bool = True,
    ) -> dict[str, Any]:
        if not body.strip():
            raise ValueError("comment body is required")
        comment_id = "comment_" + uuid.uuid4().hex
        now = int(time.time())
        with self._lock, self._txn() as cur:
            self._collection_row(collection_id, cur=cur)
            cur.execute(
                """
                INSERT INTO property_collection_comments(
                    id, collection_id, actor_subject, section, body, blocking, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (comment_id, collection_id, actor_subject.lower(), section, body.strip(), int(blocking), now),
            )
            self._audit(
                cur,
                collection_id,
                actor_subject,
                "COMMENT_ADDED",
                {"commentId": comment_id, "blocking": blocking},
            )
        return self._comment(comment_id)

    def submit_review(
        self,
        collection_id: str,
        *,
        reviewer_subject: str,
        decision: str,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        decision = decision.strip().upper()
        if decision not in ("APPROVED", "CHANGES_REQUESTED"):
            raise ValueError("review decision must be APPROVED or CHANGES_REQUESTED")
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            if row["state"] != "REVIEW":
                raise CollectionInvalidState("collection must be submitted for review")
            reviewer = reviewer_subject.lower()
            if reviewer == row["owner_subject"]:
                raise CollectionForbidden("collection owner cannot approve their own collection")
            review_id = "review_" + uuid.uuid4().hex
            now = int(time.time())
            cur.execute(
                """
                INSERT INTO property_collection_reviews(
                    id, collection_id, reviewer_subject, decision, note,
                    collection_revision, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (review_id, collection_id, reviewer, decision, note, row["revision"], now),
            )
            self._audit(
                cur,
                collection_id,
                reviewer_subject,
                "REVIEW_" + decision,
                {"reviewId": review_id, "revision": row["revision"]},
            )
        return self.get(collection_id)

    def resolve_comment(
        self,
        collection_id: str,
        comment_id: str,
        *,
        actor_subject: str,
    ) -> dict[str, Any]:
        with self._lock, self._txn() as cur:
            self._collection_row(collection_id, cur=cur)
            changed = cur.execute(
                """
                UPDATE property_collection_comments
                SET resolved=1, resolved_at=?, resolved_by=?
                WHERE id=? AND collection_id=? AND resolved=0
                """,
                (int(time.time()), actor_subject.lower(), comment_id, collection_id),
            ).rowcount
            if not changed:
                raise CollectionNotFound(f"unresolved comment {comment_id!r} not found")
            self._audit(cur, collection_id, actor_subject, "COMMENT_RESOLVED", {"commentId": comment_id})
        return self._comment(comment_id)

    def readiness(self, collection_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._collection_row(collection_id, allow_slug=True)
            draft = PropertyDossierDraftV1.model_validate_json(row["dossier_json"])
            assets = {
                asset["asset_id"]: asset
                for asset in self._conn.execute(
                    "SELECT * FROM property_collection_assets WHERE collection_id = ?",
                    (row["id"],),
                ).fetchall()
            }
        issues: list[dict[str, str]] = []
        if draft.classification is None:
            issues.append(
                {
                    "code": "CLASSIFICATION_REQUIRED",
                    "path": "/classification",
                    "message": "asset class, subtype, and project stage are required",
                }
            )
        dossier: Optional[PropertyDossierV1] = None
        try:
            dossier = draft.to_sealed_dossier()
        except ValidationError as exc:
            for error in exc.errors(include_url=False)[:100]:
                path = "/" + "/".join(str(part) for part in error["loc"])
                issues.append({"code": "DOSSIER_INVALID", "path": path, "message": error["msg"]})

        commitment = None
        if dossier is not None:
            try:
                commitment = dossier.commitment()
            except ValueError as exc:
                issues.append({"code": "METADATA_INVALID", "path": "/", "message": str(exc)})
            if not any(asset.role == "hero" for asset in dossier.media):
                issues.append({"code": "HERO_REQUIRED", "path": "/media", "message": "one verified hero image is required"})
            for descriptor in [*dossier.media, *dossier.documents]:
                asset = assets.get(descriptor.asset_id)
                path = f"/assets/{descriptor.asset_id}"
                if asset is None:
                    issues.append({"code": "ASSET_MISSING", "path": path, "message": "asset has not been uploaded"})
                    continue
                if asset["state"] != "PINNED":
                    issues.append({"code": "ASSET_UNVERIFIED", "path": path, "message": f"asset state is {asset['state']}"})
                expected_https = asset["verified_https_url"]
                expected_cid = asset["ipfs_cid"]
                if expected_https not in descriptor.uris or f"ipfs://{expected_cid}" not in descriptor.uris:
                    issues.append({"code": "ASSET_URI_MISMATCH", "path": path, "message": "dossier URIs do not match verified storage locations"})
                if descriptor.sha256.lower() != (asset["actual_sha256"] or ""):
                    issues.append({"code": "ASSET_HASH_MISMATCH", "path": path, "message": "dossier SHA-256 does not match verified bytes"})
                if descriptor.cid != expected_cid:
                    issues.append({"code": "ASSET_CID_MISMATCH", "path": path, "message": "dossier CID does not match pinned bytes"})
                if descriptor.mime_type.lower() != (asset["actual_mime_type"] or ""):
                    issues.append({"code": "ASSET_MIME_MISMATCH", "path": path, "message": "dossier MIME type does not match verified bytes"})
                if descriptor.byte_size != asset["actual_byte_size"]:
                    issues.append({"code": "ASSET_SIZE_MISMATCH", "path": path, "message": "dossier byte size does not match verified bytes"})
                if asset["malware_status"] != "CLEAN":
                    issues.append({"code": "MALWARE_SCAN_REQUIRED", "path": path, "message": "asset has not passed malware scanning"})
                if asset["availability_status"] != "HEALTHY":
                    issues.append({"code": "ASSET_UNAVAILABLE", "path": path, "message": "HTTPS and IPFS availability checks must pass"})

            for descriptor in draft.private_documents:
                asset = assets.get(descriptor.asset_id)
                path = f"/privateDocuments/{descriptor.asset_id}"
                if asset is None:
                    issues.append({"code": "PRIVATE_ASSET_MISSING", "path": path, "message": "private original has not been uploaded"})
                elif asset["visibility"] != "PRIVATE":
                    issues.append({"code": "PRIVATE_ASSET_PUBLIC", "path": path, "message": "private original is incorrectly stored as a public asset"})
                elif asset["state"] != "VERIFIED" or asset["malware_status"] != "CLEAN":
                    issues.append({"code": "PRIVATE_ASSET_UNVERIFIED", "path": path, "message": "private original must be hash-verified and malware-scanned"})

        unresolved = self._conn.execute(
            """
            SELECT COUNT(*) FROM property_collection_comments
            WHERE collection_id=? AND blocking=1 AND resolved=0
            """,
            (row["id"],),
        ).fetchone()[0]
        if unresolved:
            issues.append(
                {
                    "code": "BLOCKING_COMMENTS",
                    "path": "/review",
                    "message": f"{unresolved} blocking review comment(s) remain unresolved",
                }
            )
        approval = self._conn.execute(
            """
            SELECT 1 FROM property_collection_reviews
            WHERE collection_id=? AND decision='APPROVED'
              AND reviewer_subject<>? AND collection_revision=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (row["id"], row["owner_subject"], row["revision"]),
        ).fetchone()
        if approval is None:
            issues.append(
                {
                    "code": "INDEPENDENT_REVIEW_REQUIRED",
                    "path": "/review",
                    "message": "a different enrolled administrator must approve the current revision",
                }
            )

        return {
            "ready": not issues,
            "issues": issues,
            "metadataRoot": "0x" + commitment.metadata_root.hex() if commitment else None,
            "canonicalByteSize": commitment.byte_size if commitment else None,
            "allocationPpm": sum(item.share_ppm or 0 for item in draft.deed_allocation),
            "assetCount": len(assets),
        }

    def seal(
        self,
        collection_id: str,
        *,
        expected_revision: int,
        actor_subject: str,
    ) -> dict[str, Any]:
        with self._lock:
            current = self._collection_row(collection_id)
            self._require_owner(current, actor_subject)
            self._require_revision(current, expected_revision)
            if current["state"] not in ("DRAFT", "REVIEW"):
                raise CollectionInvalidState(
                    f"cannot seal collection in {current['state']} state"
                )
        readiness = self.readiness(collection_id)
        if not readiness["ready"]:
            raise CollectionNotReady(readiness["issues"])
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            self._require_owner(row, actor_subject)
            self._require_revision(row, expected_revision)
            if row["state"] not in ("DRAFT", "REVIEW"):
                raise CollectionInvalidState(f"cannot seal collection in {row['state']} state")
            dossier = PropertyDossierDraftV1.model_validate_json(row["dossier_json"]).to_sealed_dossier()
            commitment = dossier.commitment()
            now = int(time.time())
            cur.execute(
                """
                UPDATE property_collections
                SET state='SEALED', canonical_json=?, metadata_root=?, updated_at=?, sealed_at=?
                WHERE id=?
                """,
                (commitment.canonical_json, bytes(commitment.metadata_root), now, now, collection_id),
            )
            self._audit(
                cur, collection_id, actor_subject, "COLLECTION_SEALED",
                {"metadataRoot": "0x" + commitment.metadata_root.hex(), "byteSize": commitment.byte_size},
            )
        return self.get(collection_id)

    def record_proposal_publication(
        self,
        collection_id: str,
        deed_id: str,
        *,
        actor_subject: str,
        proposal_id: str,
        proposal_hash: bytes,
        proposal_launcher_id: bytes,
        deed_launcher_id: bytes,
        output_coin_id: bytes,
        publish_bundle_id: str,
    ) -> dict[str, Any]:
        for label, value in (
            ("proposal_hash", proposal_hash),
            ("proposal_launcher_id", proposal_launcher_id),
            ("deed_launcher_id", deed_launcher_id),
            ("output_coin_id", output_coin_id),
        ):
            if len(value) != 32:
                raise ValueError(f"{label} must be bytes32")
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            self._require_owner(row, actor_subject)
            if row["state"] not in ("SEALED", "PUBLISHED"):
                raise CollectionInvalidState("collection must be sealed before proposal publication")
            deed = cur.execute(
                "SELECT * FROM property_collection_deeds WHERE collection_id=? AND deed_id=? COLLATE NOCASE",
                (collection_id, deed_id),
            ).fetchone()
            if deed is None:
                raise CollectionNotFound(f"deed {deed_id!r} is not in the sealed allocation")
            if deed["proposal_id"] and deed["proposal_id"] != proposal_id:
                raise CollectionConflict(f"deed {deed_id!r} already has a proposal")
            if deed["publish_bundle_id"]:
                expected = {"publish_bundle_id": publish_bundle_id, "proposal_hash": proposal_hash,
                    "proposal_launcher_id": proposal_launcher_id, "deed_launcher_id": deed_launcher_id,
                    "output_coin_id": output_coin_id}
                if any(deed[key] != value for key, value in expected.items()):
                    raise CollectionConflict("publication already has different chain commitments")
                # A reconciler and the HTTP response may finish together. Do
                # not replay audit entries or downgrade later execution state.
                return self.get(collection_id)
            first = row["metadata_anchor_id"] is None
            anchor = deed_launcher_id if first else bytes(row["metadata_anchor_id"])
            if not first and bytes(row["metadata_root"]) == b"":
                raise CollectionInvalidState("published collection has no metadata root")
            now = int(time.time())
            cur.execute(
                """
                UPDATE property_collection_deeds
                SET proposal_id=?, proposal_state='PROPOSED', proposal_hash=?,
                    proposal_launcher_id=?, deed_launcher_id=?, output_coin_id=?,
                    publish_bundle_id=?
                WHERE collection_id=? AND deed_id=? COLLATE NOCASE
                """,
                (
                    proposal_id, proposal_hash, proposal_launcher_id, deed_launcher_id,
                    output_coin_id, publish_bundle_id, collection_id, deed_id,
                ),
            )
            cur.execute(
                """
                UPDATE property_collections
                SET state='PUBLISHED', metadata_anchor_id=?,
                    first_proposal_id=COALESCE(first_proposal_id, ?),
                    allocation_locked=1, updated_at=?, published_at=COALESCE(published_at, ?)
                WHERE id=?
                """,
                (anchor, proposal_id, now, now, collection_id),
            )
            if first:
                version_id = "metadata_" + uuid.uuid4().hex
                cur.execute(
                    """
                    INSERT INTO property_metadata_versions(
                        id, collection_id, sequence, version_kind, metadata_root,
                        canonical_json, actor_subject, created_at
                    ) VALUES (?, ?, 1, 'ISSUANCE', ?, ?, ?, ?)
                    """,
                    (
                        version_id, collection_id, row["metadata_root"], row["canonical_json"],
                        actor_subject.lower(), now,
                    ),
                )
            self._audit(
                cur, collection_id, actor_subject, "PROPOSAL_PUBLISHED",
                {
                    "deedId": deed_id,
                    "proposalId": proposal_id,
                    "metadataAnchorId": "0x" + anchor.hex(),
                    "firstProposal": first,
                    "outputCoinId": "0x" + output_coin_id.hex(),
                },
            )
        return self.get(collection_id)

    def record_proposal_execution(
        self,
        proposal_id: str,
        *,
        execute_bundle_id: str,
        actor_subject: str,
    ) -> Optional[dict[str, Any]]:
        """Mirror an accepted EXECUTE bundle into its collection deed row.

        Legacy mint proposals are intentionally allowed to have no collection
        workspace, so a missing proposal id returns ``None``.  Conflicting
        bundle ids are rejected because execution is an append-only event.
        """
        if not execute_bundle_id:
            raise ValueError("execute_bundle_id must be non-empty")
        with self._lock, self._txn() as cur:
            deed = cur.execute(
                """
                SELECT collection_id, deed_id, execute_bundle_id
                FROM property_collection_deeds
                WHERE proposal_id=?
                """,
                (proposal_id,),
            ).fetchone()
            if deed is None:
                return None
            existing = deed["execute_bundle_id"]
            if existing and existing != execute_bundle_id:
                raise CollectionConflict(
                    f"proposal {proposal_id!r} already has a different execute bundle"
                )
            if existing:
                return self.get(deed["collection_id"])
            cur.execute(
                """
                UPDATE property_collection_deeds
                SET proposal_state='EXECUTED', execute_bundle_id=?
                WHERE proposal_id=?
                """,
                (execute_bundle_id, proposal_id),
            )
            now = int(time.time())
            cur.execute(
                "UPDATE property_collections SET updated_at=? WHERE id=?",
                (now, deed["collection_id"]),
            )
            self._audit(
                cur,
                deed["collection_id"],
                actor_subject,
                "PROPOSAL_EXECUTION_SUBMITTED",
                {
                    "deedId": deed["deed_id"],
                    "proposalId": proposal_id,
                    "executeBundleId": execute_bundle_id,
                },
            )
        return self.get(deed["collection_id"])

    def append_amendment(
        self,
        collection_id: str,
        *,
        dossier: PropertyDossierV1,
        amendment: PropertyAmendmentV1,
        expected_revision: int,
        actor_subject: str,
    ) -> dict[str, Any]:
        validate_amendment_paths(amendment.changed_fields)
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            self._require_owner(row, actor_subject)
            self._require_revision(row, expected_revision)
            if row["state"] != "PUBLISHED":
                raise CollectionInvalidState("only published collections accept amendments")
            if dossier.collection_id != collection_id or amendment.collection_id != collection_id:
                raise ValueError("amendment collectionId mismatch")
            current = PropertyDossierV1.model_validate_json(bytes(row["canonical_json"]))
            _assert_protected_fields_unchanged(current, dossier)
            next_revision = expected_revision + 1
            next_dossier = dossier.model_copy(update={"revision": next_revision})
            commitment = next_dossier.commitment()
            self._require_verified_assets(cur, collection_id, next_dossier)
            current_root = "0x" + bytes(row["metadata_root"]).hex()
            if amendment.previous_root.lower() != current_root:
                raise CollectionConflict("amendment previousRoot does not match current metadata root")
            if amendment.new_root.lower() != "0x" + commitment.metadata_root.hex():
                raise CollectionConflict("amendment newRoot does not match the supplied dossier")
            sequence = int(
                cur.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM property_metadata_versions WHERE collection_id=?",
                    (collection_id,),
                ).fetchone()[0]
            )
            now = int(time.time())
            canonical_payload = next_dossier.canonical_payload()
            cur.execute(
                """
                UPDATE property_collections
                SET revision=?, dossier_json=?, canonical_json=?, metadata_root=?, updated_at=?
                WHERE id=?
                """,
                (
                    next_revision, _json(canonical_payload), commitment.canonical_json,
                    bytes(commitment.metadata_root), now, collection_id,
                ),
            )
            cur.execute(
                """
                INSERT INTO property_metadata_versions(
                    id, collection_id, sequence, version_kind, metadata_root,
                    previous_root, canonical_json, envelope_json, actor_subject,
                    effective_date, created_at
                ) VALUES (?, ?, ?, 'OWNER_AMENDMENT', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "metadata_" + uuid.uuid4().hex, collection_id, sequence,
                    bytes(commitment.metadata_root), row["metadata_root"], commitment.canonical_json,
                    _json(amendment.model_dump(mode="json", by_alias=True)), actor_subject.lower(),
                    amendment.effective_date, now,
                ),
            )
            self._audit(
                cur, collection_id, actor_subject, "OWNER_AMENDMENT_APPENDED",
                {"sequence": sequence, "changedFields": amendment.changed_fields, "metadataRoot": amendment.new_root},
            )
        return self.get(collection_id)

    def record_anchor_evidence(
        self,
        collection_id: str,
        deed_id: str,
        *,
        anchor_coin_id: bytes,
        status: str,
        reconstructed_root: Optional[bytes],
        spend_bundle_id: Optional[str],
        confirmation_height: Optional[int],
        puzzle_solution_hash: Optional[str],
        details: dict[str, Any],
        actor_subject: str = "chain-indexer",
    ) -> dict[str, Any]:
        if len(anchor_coin_id) != 32 or (reconstructed_root is not None and len(reconstructed_root) != 32):
            raise ValueError("anchor and reconstructed roots must be bytes32")
        if status not in ("PENDING", "CONFIRMED", "MISMATCH", "ORPHANED"):
            raise ValueError("unknown evidence status")
        now = int(time.time())
        evidence_id = "evidence_" + uuid.uuid4().hex
        with self._lock, self._txn() as cur:
            row = self._collection_row(collection_id, cur=cur)
            cur.execute(
                """
                INSERT INTO property_anchor_evidence(
                    id, collection_id, deed_id, anchor_coin_id, spend_bundle_id,
                    confirmation_height, puzzle_solution_hash, reconstructed_root,
                    status, details_json, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(collection_id, anchor_coin_id) DO UPDATE SET
                    deed_id=excluded.deed_id, spend_bundle_id=excluded.spend_bundle_id,
                    confirmation_height=excluded.confirmation_height,
                    puzzle_solution_hash=excluded.puzzle_solution_hash,
                    reconstructed_root=excluded.reconstructed_root,
                    status=excluded.status, details_json=excluded.details_json,
                    checked_at=excluded.checked_at
                """,
                (
                    evidence_id, collection_id, deed_id, anchor_coin_id, spend_bundle_id,
                    confirmation_height, puzzle_solution_hash, reconstructed_root,
                    status, _json(details), now,
                ),
            )
            if confirmation_height is not None:
                cur.execute(
                    """
                    UPDATE property_collection_deeds
                    SET confirmation_height=?,
                        proposal_state=CASE
                            WHEN proposal_state='EXECUTED' THEN proposal_state
                            ELSE ?
                        END
                    WHERE collection_id=? AND deed_id=? COLLATE NOCASE
                    """,
                    (confirmation_height, "CONFIRMED" if status == "CONFIRMED" else status, collection_id, deed_id),
                )
            self._audit(
                cur, collection_id, actor_subject, "ANCHOR_EVIDENCE_INDEXED",
                {"status": status, "coinId": "0x" + anchor_coin_id.hex()},
            )
            if status == "CONFIRMED" and reconstructed_root != row["metadata_root"]:
                # Current root can be an owner amendment. Compare to issuance below
                # in the public verification renderer; do not rewrite chain truth.
                pass
        return self.get(collection_id)

    def versions(self, collection_id: str) -> list[dict[str, Any]]:
        with self._lock:
            collection = self._collection_row(collection_id, allow_slug=True)
            rows = self._conn.execute(
                "SELECT * FROM property_metadata_versions WHERE collection_id=? ORDER BY sequence",
                (collection["id"],),
            ).fetchall()
        return [self._render_version(row) for row in rows]

    def audit_events(self, collection_id: str) -> list[dict[str, Any]]:
        with self._lock:
            collection = self._collection_row(collection_id, allow_slug=True)
            rows = self._conn.execute(
                "SELECT * FROM property_collection_audit_events WHERE collection_id=? ORDER BY id",
                (collection["id"],),
            ).fetchall()
        return [
            {
                "id": row["id"], "actorSubject": row["actor_subject"],
                "action": row["action"], "details": json.loads(row["details_json"]),
                "occurredAt": row["occurred_at"],
            }
            for row in rows
        ]

    def public_collection(self, identifier: str) -> dict[str, Any]:
        result = self.get(identifier)
        if result["state"] != "PUBLISHED":
            raise CollectionNotFound(identifier)
        with self._lock:
            row = self._collection_row(identifier, allow_slug=True)
            canonical_json = row["canonical_json"]
        if canonical_json is None:
            raise CollectionInvalidState(
                "published collection has no canonical public metadata"
            )
        # The admin draft intentionally retains private document descriptors.
        # Public responses must come from the sealed canonical bytes, which
        # exclude those descriptors and are the bytes committed on chain.
        result["dossier"] = json.loads(bytes(canonical_json))
        versions = result["metadataVersions"]
        issuance = next((version for version in versions if version["kind"] == "ISSUANCE"), None)
        confirmed = any(
            evidence["status"] == "CONFIRMED"
            and issuance is not None
            and evidence["reconstructedRoot"] == issuance["metadataRoot"]
            for evidence in result["anchorEvidence"]
        )
        dossier = result["dossier"]
        referenced_asset_ids = {
            item["assetId"]
            for section in (dossier.get("media", []), dossier.get("documents", []))
            for item in section
            if item.get("assetId")
        }
        assets_by_id = {asset["assetId"]: asset for asset in result["assets"]}
        asset_healthy = bool(referenced_asset_ids) and all(
            asset_id in assets_by_id
            and assets_by_id[asset_id]["state"] == "PINNED"
            and assets_by_id[asset_id]["malwareStatus"] == "CLEAN"
            and assets_by_id[asset_id]["availabilityStatus"] == "HEALTHY"
            for asset_id in referenced_asset_ids
        )
        result["verification"] = {
            "chainReconstructed": confirmed,
            "mediaVerified": asset_healthy,
            "verified": confirmed and asset_healthy,
            "issuanceMetadataRoot": issuance["metadataRoot"] if issuance else None,
            "currentMetadataRoot": result["metadataRoot"],
            "currentVersionGovernance": (
                "SGT_GOVERNED" if len(versions) <= 1 else "OWNER_SIGNED_UPDATE"
            ),
        }
        result.pop("auditEvents", None)
        result.pop("comments", None)
        result.pop("reviews", None)
        result["assets"] = [
            asset for asset in result["assets"] if asset["visibility"] == "PUBLIC"
        ]
        return result

    def public_deed(self, deed_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT d.*, c.slug, c.id AS parent_collection_id
                FROM property_collection_deeds d
                JOIN property_collections c ON c.id=d.collection_id
                WHERE d.deed_id=? COLLATE NOCASE AND c.state='PUBLISHED'
                """,
                (deed_id,),
            ).fetchone()
        if row is None:
            raise CollectionNotFound(deed_id)
        rendered = self._render_deed(row)
        rendered["collectionId"] = row["parent_collection_id"]
        rendered["collectionSlug"] = row["slug"]
        return rendered

    def sols_market_candidates(self) -> list[dict[str, Any]]:
        """Return only published, executed deeds that can be checked on chain.

        This is intentionally a candidate feed rather than an availability
        feed. Pool custody, current NAV evidence, and the live deed lineage are
        verified by the SOLS market reader before anything reaches a buyer.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    d.*,
                    c.id AS parent_collection_id,
                    c.slug,
                    c.canonical_json,
                    c.metadata_root
                FROM property_collection_deeds d
                JOIN property_collections c ON c.id=d.collection_id
                WHERE c.state='PUBLISHED'
                  AND d.proposal_state='EXECUTED'
                  AND d.deed_launcher_id IS NOT NULL
                  AND d.output_coin_id IS NOT NULL
                  AND d.confirmation_height IS NOT NULL
                ORDER BY c.created_at, d.ordinal, d.deed_id
                """
            ).fetchall()

        candidates: list[dict[str, Any]] = []
        for row in rows:
            if row["canonical_json"] is None:
                continue
            dossier = json.loads(bytes(row["canonical_json"]))
            candidates.append(
                {
                    **self._render_deed(row),
                    "collectionId": row["parent_collection_id"],
                    "collectionSlug": row["slug"],
                    "collectionTitle": dossier.get("title"),
                    "collectionSummary": dossier.get("summary"),
                    "metadataRoot": _hex(row["metadata_root"]),
                }
            )
        return candidates

    def _update_asset(
        self,
        collection_id: str,
        asset_id: str,
        *,
        actor_subject: str,
        action: str,
        updates: dict[str, Any],
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        allowed = {
            "object_key", "verified_https_url", "ipfs_cid", "actual_sha256",
            "actual_mime_type", "actual_byte_size", "malware_status",
            "availability_status", "state", "failure_reason",
        }
        if not updates or not set(updates).issubset(allowed):
            raise ValueError("invalid asset update")
        if "state" in updates and updates["state"] not in ASSET_STATES:
            raise ValueError("invalid asset state")
        with self._lock, self._txn() as cur:
            collection = self._collection_row(collection_id, cur=cur)
            current = self._asset_row(collection_id, asset_id, cur=cur)
            if expected_revision is not None:
                self._require_revision(current, expected_revision)
            if "object_key" in updates:
                if collection["state"] == "SEALED":
                    raise CollectionInvalidState("sealed asset storage is immutable")
                if current["object_key"] and current["object_key"] != updates["object_key"]:
                    raise CollectionConflict("asset object key is immutable for this upload attempt")
                if current["state"] in ("PINNED", "VERIFIED"):
                    raise CollectionConflict("verified assets cannot be authorized for another upload")
                if cur.execute(
                    "SELECT 1 FROM property_collection_assets WHERE object_key=? "
                    "AND NOT (collection_id=? AND asset_id=?)",
                    (updates["object_key"], collection_id, asset_id),
                ).fetchone():
                    raise CollectionConflict("object key is already assigned to another asset")
            assignments = [f"{name}=?" for name in updates]
            values = list(updates.values())
            assignments.extend(["revision=?", "updated_at=?"])
            values.extend([int(current["revision"]) + 1, int(time.time()), collection_id, asset_id])
            cur.execute(
                f"UPDATE property_collection_assets SET {', '.join(assignments)} "
                "WHERE collection_id=? AND asset_id=?",
                values,
            )
            self._audit(cur, collection_id, actor_subject, action, {"assetId": asset_id})
            result = self._render_asset(self._asset_row(collection_id, asset_id, cur=cur))
        return result

    def _sync_deeds(
        self,
        cur: sqlite3.Cursor,
        collection_id: str,
        draft: PropertyDossierDraftV1,
        locked: bool,
    ) -> None:
        if locked:
            return
        cur.execute("DELETE FROM property_collection_deeds WHERE collection_id=?", (collection_id,))
        for ordinal, deed in enumerate(draft.deed_allocation):
            if not deed.deed_id or deed.share_ppm is None or not deed.par_value_mojos:
                continue
            cur.execute(
                """
                INSERT INTO property_collection_deeds(
                    collection_id, deed_id, ordinal, share_ppm, par_value_mojos
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (collection_id, deed.deed_id, ordinal, deed.share_ppm, deed.par_value_mojos),
            )

    def _require_verified_assets(
        self,
        cur: sqlite3.Cursor,
        collection_id: str,
        dossier: PropertyDossierV1,
    ) -> None:
        assets = {
            row["asset_id"]: row
            for row in cur.execute(
                "SELECT * FROM property_collection_assets WHERE collection_id=?",
                (collection_id,),
            ).fetchall()
        }
        issues: list[dict[str, str]] = []
        for descriptor in [*dossier.media, *dossier.documents]:
            row = assets.get(descriptor.asset_id)
            path = f"/assets/{descriptor.asset_id}"
            if row is None:
                issues.append({"code": "ASSET_MISSING", "path": path, "message": "asset is missing"})
                continue
            expected_uris = {row["verified_https_url"], f"ipfs://{row['ipfs_cid']}"}
            if (
                row["state"] != "PINNED"
                or row["malware_status"] != "CLEAN"
                or row["availability_status"] != "HEALTHY"
                or descriptor.sha256.lower() != (row["actual_sha256"] or "")
                or descriptor.mime_type.lower() != (row["actual_mime_type"] or "")
                or descriptor.byte_size != row["actual_byte_size"]
                or descriptor.cid != row["ipfs_cid"]
                or not expected_uris.issubset(set(descriptor.uris))
            ):
                issues.append(
                    {
                        "code": "ASSET_UNVERIFIED",
                        "path": path,
                        "message": "amendment references media that is not fully verified",
                    }
                )
        if issues:
            raise CollectionNotReady(issues)

    def _render_collection(self, row: sqlite3.Row, *, include_related: bool) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": row["id"],
            "slug": row["slug"],
            "ownerSubject": row["owner_subject"],
            "ownerAuthType": row["owner_auth_type"],
            "state": row["state"],
            "revision": row["revision"],
            "dossier": json.loads(row["dossier_json"]),
            "metadataRoot": _hex(row["metadata_root"]),
            "metadataAnchorId": _hex(row["metadata_anchor_id"]),
            "firstProposalId": row["first_proposal_id"],
            "allocationLocked": bool(row["allocation_locked"]),
            "canonicalByteSize": len(row["canonical_json"]) if row["canonical_json"] else None,
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
            "sealedAt": row["sealed_at"],
            "publishedAt": row["published_at"],
        }
        if not include_related:
            return result
        collection_id = row["id"]
        result["deeds"] = [
            self._render_deed(item)
            for item in self._conn.execute(
                "SELECT * FROM property_collection_deeds WHERE collection_id=? ORDER BY ordinal",
                (collection_id,),
            ).fetchall()
        ]
        result["assets"] = [
            self._render_asset(item)
            for item in self._conn.execute(
                "SELECT * FROM property_collection_assets WHERE collection_id=? ORDER BY created_at, asset_id",
                (collection_id,),
            ).fetchall()
        ]
        result["comments"] = [
            self._render_comment(item)
            for item in self._conn.execute(
                "SELECT * FROM property_collection_comments WHERE collection_id=? ORDER BY created_at, id",
                (collection_id,),
            ).fetchall()
        ]
        result["reviews"] = [
            {
                "id": item["id"],
                "reviewerSubject": item["reviewer_subject"],
                "decision": item["decision"],
                "note": item["note"],
                "collectionRevision": item["collection_revision"],
                "createdAt": item["created_at"],
            }
            for item in self._conn.execute(
                "SELECT * FROM property_collection_reviews WHERE collection_id=? ORDER BY created_at, id",
                (collection_id,),
            ).fetchall()
        ]
        result["metadataVersions"] = [
            self._render_version(item)
            for item in self._conn.execute(
                "SELECT * FROM property_metadata_versions WHERE collection_id=? ORDER BY sequence",
                (collection_id,),
            ).fetchall()
        ]
        result["anchorEvidence"] = [
            self._render_evidence(item)
            for item in self._conn.execute(
                "SELECT * FROM property_anchor_evidence WHERE collection_id=? ORDER BY checked_at DESC",
                (collection_id,),
            ).fetchall()
        ]
        result["auditEvents"] = self.audit_events(collection_id)
        result["readiness"] = self.readiness(collection_id)
        return result

    def _render_asset(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "assetId": row["asset_id"], "kind": row["kind"], "role": row["role"],
            "title": row["title"], "alt": row["alt_text"], "category": row["category"],
            "visibility": row["visibility"],
            "expectedSha256": row["expected_sha256"],
            "expectedMimeType": row["expected_mime_type"],
            "expectedByteSize": row["expected_byte_size"], "objectKey": row["object_key"],
            "verifiedHttpsUrl": row["verified_https_url"], "ipfsCid": row["ipfs_cid"],
            "actualSha256": row["actual_sha256"], "actualMimeType": row["actual_mime_type"],
            "actualByteSize": row["actual_byte_size"], "malwareStatus": row["malware_status"],
            "availabilityStatus": row["availability_status"], "state": row["state"],
            "failureReason": row["failure_reason"], "revision": row["revision"],
        }

    def _render_deed(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "deedId": row["deed_id"], "ordinal": row["ordinal"],
            "sharePpm": row["share_ppm"], "parValueMojos": row["par_value_mojos"],
            "proposalId": row["proposal_id"], "proposalState": row["proposal_state"],
            "proposalHash": _hex(row["proposal_hash"]),
            "proposalLauncherId": _hex(row["proposal_launcher_id"]),
            "deedLauncherId": _hex(row["deed_launcher_id"]),
            "outputCoinId": _hex(row["output_coin_id"]),
            "publishBundleId": row["publish_bundle_id"],
            "executeBundleId": row["execute_bundle_id"],
            "confirmationHeight": row["confirmation_height"],
        }

    def _render_comment(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "actorSubject": row["actor_subject"],
            "section": row["section"], "body": row["body"],
            "blocking": bool(row["blocking"]),
            "resolved": bool(row["resolved"]), "createdAt": row["created_at"],
            "resolvedAt": row["resolved_at"], "resolvedBy": row["resolved_by"],
        }

    def _render_version(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "sequence": row["sequence"], "kind": row["version_kind"],
            "metadataRoot": _hex(row["metadata_root"]), "previousRoot": _hex(row["previous_root"]),
            "canonicalMetadata": json.loads(bytes(row["canonical_json"])),
            "envelope": json.loads(row["envelope_json"]) if row["envelope_json"] else None,
            "actorSubject": row["actor_subject"], "effectiveDate": row["effective_date"],
            "createdAt": row["created_at"],
        }

    def _render_evidence(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "deedId": row["deed_id"],
            "anchorCoinId": _hex(row["anchor_coin_id"]),
            "spendBundleId": row["spend_bundle_id"],
            "confirmationHeight": row["confirmation_height"],
            "puzzleSolutionHash": row["puzzle_solution_hash"],
            "reconstructedRoot": _hex(row["reconstructed_root"]),
            "status": row["status"], "details": json.loads(row["details_json"]),
            "checkedAt": row["checked_at"],
        }

    def _collection_row(
        self, identifier: str, *, cur: Optional[sqlite3.Cursor] = None, allow_slug: bool = False
    ) -> sqlite3.Row:
        db = cur or self._conn
        row = db.execute(
            "SELECT * FROM property_collections WHERE id=?",
            (identifier,),
        ).fetchone()
        if row is None and allow_slug:
            row = db.execute("SELECT * FROM property_collections WHERE slug=?", (identifier,)).fetchone()
        if row is None:
            raise CollectionNotFound(identifier)
        return row

    def _asset_row(
        self,
        collection_id: str,
        asset_id: str,
        *,
        cur: Optional[sqlite3.Cursor] = None,
    ) -> sqlite3.Row:
        db = cur or self._conn
        row = db.execute(
            "SELECT * FROM property_collection_assets WHERE collection_id=? AND asset_id=?",
            (collection_id, asset_id),
        ).fetchone()
        if row is None:
            raise CollectionNotFound(f"asset {asset_id!r}")
        return row

    def _comment(self, comment_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM property_collection_comments WHERE id=?", (comment_id,)
            ).fetchone()
        if row is None:
            raise CollectionNotFound(comment_id)
        return self._render_comment(row)

    def _require_revision(self, row: sqlite3.Row, expected: int) -> None:
        actual = int(row["revision"])
        if expected != actual:
            raise CollectionConflict(f"revision conflict: expected {expected}, current {actual}")

    def _require_owner(self, row: sqlite3.Row, actor_subject: str) -> None:
        if row["owner_subject"] != actor_subject.lower():
            raise CollectionForbidden("only the collection owner can perform this action")

    def _unique_slug(self, cur: sqlite3.Cursor, candidate: str) -> str:
        base = _slugify(candidate)
        slug = base
        counter = 2
        while cur.execute("SELECT 1 FROM property_collections WHERE slug=? OR id=?", (slug, slug)).fetchone():
            slug = f"{base}-{counter}"
            counter += 1
        return slug

    def _audit(
        self,
        cur: sqlite3.Cursor,
        collection_id: str,
        actor_subject: str,
        action: str,
        details: dict[str, Any],
    ) -> None:
        cur.execute(
            """
            INSERT INTO property_collection_audit_events(
                collection_id, actor_subject, action, details_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (collection_id, actor_subject.lower(), action, _json(details), int(time.time())),
        )


def _assert_protected_fields_unchanged(old: Any, new: Any) -> None:
    old_payload = old.model_dump(mode="json", by_alias=True, exclude_none=True)
    new_payload = new.model_dump(mode="json", by_alias=True, exclude_none=True)
    paths = (
        ("deedAllocation",),
        ("classification",),
        ("offering", "parValueMojos"),
        ("offering", "assetClass"),
        ("offering", "jurisdiction"),
        ("offering", "royaltyPuzhash"),
        ("offering", "royaltyBps"),
        ("offering", "governanceQuorum"),
        ("offering", "targetRaiseMinor"),
        ("legal", "securityStructure"),
        ("legal", "settlementBasis"),
    )
    for path in paths:
        if _lookup(old_payload, path) != _lookup(new_payload, path):
            raise CollectionInvalidState("protected issuance field changed: /" + "/".join(path))


def _lookup(payload: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = payload
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug[:96] or "collection"


def _hex(value: Any) -> Optional[str]:
    return "0x" + bytes(value).hex() if value is not None else None


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


_cached_store: Optional[CollectionStore] = None
_cached_store_path: Optional[str] = None


def get_collection_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> CollectionStore:
    global _cached_store, _cached_store_path
    if _cached_store is None or _cached_store_path != settings.admin_db_path:
        if _cached_store is not None:
            _cached_store.close()
        _cached_store = CollectionStore(settings.admin_db_path)
        _cached_store_path = settings.admin_db_path
    return _cached_store


def reset_collection_store_for_tests() -> None:
    global _cached_store, _cached_store_path
    if _cached_store is not None:
        try:
            _cached_store.close()
        except Exception:
            pass
    _cached_store = None
    _cached_store_path = None


__all__ = [
    "COLLECTION_SCHEMA_VERSION",
    "CollectionConflict",
    "CollectionForbidden",
    "CollectionInvalidState",
    "CollectionNotFound",
    "CollectionNotReady",
    "CollectionStore",
    "get_collection_store",
    "reset_collection_store_for_tests",
]
