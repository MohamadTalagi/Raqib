"""Serializes append-only sequential-ID generation (EV-, VD-, ASMT-, ASM-,
CEV-, EXC-, RPT-, RB- prefixes) so two concurrent requests targeting the
same table's date-prefixed sequence can never compute the same id and
collide on insert.

Every call site previously ran its own unguarded
`COUNT(*) WHERE id LIKE 'PREFIX-date-%' + 1` - correct for a single
request, racy under concurrency (two requests can read the same count
before either has inserted, then both attempt the identical id).

A Postgres transaction-scoped advisory lock (`pg_advisory_xact_lock`) keyed
on the target table makes concurrent callers for the same sequence wait
their turn instead of racing. It auto-releases at this connection's own
commit/rollback - no explicit unlock needed - matching db.get_connection()'s
per-request connection lifecycle (one fresh, non-autocommit connection per
request, explicitly committed and closed by the caller). Keyed on table
alone, not table+date: a request spanning a day rollover would otherwise
risk two callers computing a lock key for two different "current" dates and
never actually contending: the extremely rare cross-midnight case only
costs a moment of unnecessary serialization against a different day's
generation, never a missed lock.
"""
from datetime import datetime, timezone


def lock_id_sequence(conn, table: str) -> None:
    """Acquire the advisory lock for `table`'s id sequence. Call once per
    request before counting; safe to call again for a different table (a
    different lock key) within the same request. Needed directly (instead
    of only via next_sequential_id) by a call site that mints several ids
    from one counted total within a single request - e.g.
    main.py::recompute_verdicts, which counts once and increments a local
    sequence number in a loop rather than re-querying per id."""
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)", (f"id-gen:{table}",))


def next_sequential_id(conn, prefix: str, table: str, id_column: str, now: datetime | None = None) -> str:
    """Generate the next PREFIX-YYYY-MM-DD-NNNN id for `table`, safe under
    concurrency. For a call site that needs several ids from the same table
    in one request, call lock_id_sequence() once up front instead and
    increment the count locally - this function is for the common
    single-id case."""
    lock_id_sequence(conn, table)
    now = now or datetime.now(timezone.utc)
    full_prefix = f"{prefix}-{now:%Y-%m-%d}-"
    existing = conn.execute(
        f"SELECT {id_column} FROM {table} WHERE {id_column} LIKE %s", (f"{full_prefix}%",)
    ).fetchall()
    return f"{full_prefix}{len(existing) + 1:04d}"
