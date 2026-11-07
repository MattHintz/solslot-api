"""Fail-closed bindings for generation-local SQLite state.

The old files are never migrated into a new generation. A marker is admitted
only in an empty database, before schema setup or journal-mode changes.
"""
from pathlib import Path
import sqlite3

from .generation_context import generation_bytes


class GenerationStorageError(ValueError):
    pass


class GenerationRetentionFull(RuntimeError):
    """Retained evidence requires an operator archive review; never delete it."""


def admit_retained_bytes(connection, retained: int, additional: int, limit: int) -> None:
    # Admission belongs inside the caller's immediate write transaction so
    # concurrent preparations cannot each claim the same remaining capacity.
    if not connection.in_transaction or any(type(v) is not int or v < 0 for v in (retained, additional, limit)):
        raise GenerationStorageError('retention admission requires a bounded atomic write')
    if retained + additional > limit:
        raise GenerationRetentionFull('retained generation evidence needs an explicit archive review')


def connect_generation_sqlite(database, *args, generation_id=None, generation_network='testnet11', **kwargs) -> sqlite3.Connection:
    """Admit a generation-scoped writable database before any migration.

    Legacy paths and read-only evidence connections keep their existing
    behavior. All owned store constructors use this entry point, so copying
    an old database into a new namespace cannot silently admit its receipts.
    """
    con=sqlite3.connect(database,*args,**kwargs)
    try:
        path=Path(str(database))
        if path.parent.parent.name=='generations':
            generation='0x'+path.parent.name
            generation_bytes(generation)
            if generation_id is not None and generation_bytes(generation_id)!=generation_bytes(generation):
                raise GenerationStorageError('state path belongs to another deployment generation')
            generation_id=generation
        bind_generation(con,generation_id,generation_network)
        return con
    except Exception:
        con.close()
        raise


def generation_path(path: str, generation_id: str | None) -> str:
    if generation_id is None or path == ':memory:':
        return path
    generation = generation_bytes(generation_id).hex()
    original = Path(path)
    if original.parent.name == generation and original.parent.parent.name == 'generations':
        return str(original)
    if original.parent.parent.name == 'generations':
        raise GenerationStorageError('state path belongs to another deployment generation')
    return str(original.parent / 'generations' / generation / original.name)


def bind_generation(connection: sqlite3.Connection, generation_id: str | None, network: str = 'testnet11') -> None:
    """Call before any store migration. Recheck admission under a write lock."""
    if generation_id is not None:
        generation_id = '0x' + generation_bytes(generation_id).hex()
        if network != 'testnet11':
            raise GenerationStorageError('replacement generation is restricted to Testnet11')

    def check():
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'deployment_generation_binding' in tables:
            rows = connection.execute('SELECT generation_id,network FROM deployment_generation_binding').fetchall()
            if len(rows) != 1 or tuple(rows[0]) != (generation_id, network):
                raise GenerationStorageError('database belongs to another deployment generation')
            return True
        if generation_id is not None and tables - {'sqlite_sequence'}:
            raise GenerationStorageError('existing database cannot be rebound to a replacement generation')
        return False

    # Wrong-generation opens remain read-only, including their SQLite bytes.
    if check() or generation_id is None:
        return
    connection.execute('BEGIN IMMEDIATE')
    try:
        if not check():
            connection.execute('CREATE TABLE deployment_generation_binding '
                '(singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation_id TEXT NOT NULL, network TEXT NOT NULL)')
            connection.execute('INSERT INTO deployment_generation_binding VALUES (1,?,?)', (generation_id, network))
        connection.execute('COMMIT')
    except Exception:
        connection.execute('ROLLBACK')
        raise
