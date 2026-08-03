"""Configurable scan-target boundary ("Network Scope") - a separate
APIRouter (same pattern as risk_routes.py/vuln_routes.py) mounted via
app.include_router() in main.py.

`network_scopes` is the single source of truth for which CIDRs are legal
scan targets, replacing the previously hardcoded 172.30.0.0/24 constant
(device_validation.ALLOWED_NETWORK, scan_tests.AUDIT_NETWORK_CIDR). Both of
those modules stay free of DB/HTTP imports on purpose (see
device_validation.py's own module docstring) - this router is the one place
that reads the table and pushes the active CIDR list into both of them via
their configure_*() setters, in-process, after every write. auditor-worker
has no direct DB access, so it reaches the same current list via
GET /network-scope/active (job_runner.py polls this periodically - see that
module's own NETWORK_SCOPE_REFRESH_INTERVAL_SECONDS).

Rows are never hard-deleted, matching every other append-only table in this
project - deactivating sets is_active=false plus deactivated_at/by, which
*is* the audit trail; there is no separate audit-event table.
"""

import ipaddress

from fastapi import APIRouter, HTTPException

from db import get_connection
from device_validation import (
    MIN_SCOPE_PREFIX_LENGTH,
    PRIVATE_RANGES,
    PROTECTED_RANGES,
    ValidationError,
    configure_allowed_networks,
)
from policies.catalog.scan_tests import configure_active_scopes

router = APIRouter(prefix="/network-scope", tags=["network-scope"])

NETWORK_SCOPE_COLUMNS = (
    "id, label, cidr, kind, source, is_active, added_by, reason, "
    "created_at, deactivated_at, deactivated_by"
)


def _row_to_network_scope(row: tuple) -> dict:
    (
        scope_id, label, cidr, kind, source, is_active, added_by, reason,
        created_at, deactivated_at, deactivated_by,
    ) = row
    return {
        "id": scope_id,
        "label": label,
        "cidr": cidr,
        "kind": kind,
        "source": source,
        "is_active": is_active,
        "added_by": added_by,
        "reason": reason,
        "created_at": created_at.isoformat(),
        "deactivated_at": deactivated_at.isoformat() if deactivated_at else None,
        "deactivated_by": deactivated_by,
    }


def _validate_new_cidr(value: str) -> str:
    """Guardrails applied only here, at scope-creation time - never inside
    device_validation.validate_host(), which just trusts whatever is
    currently configured, exactly as it always trusted the single hardcoded
    constant before this feature existed."""
    if not isinstance(value, str) or not value:
        raise ValidationError("cidr", "cidr is required")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValidationError(
            "cidr", f"not a valid CIDR (must have no host bits set): {exc}"
        ) from None

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValidationError("cidr", "only IPv4 ranges are supported today")

    if network.prefixlen < MIN_SCOPE_PREFIX_LENGTH:
        raise ValidationError(
            "cidr",
            f"range is too broad (/{network.prefixlen}) - must be /{MIN_SCOPE_PREFIX_LENGTH} "
            "or narrower, to bound how much address space a single scope can sweep",
        )

    if not any(network.subnet_of(private) for private in PRIVATE_RANGES):
        raise ValidationError(
            "cidr",
            "must be a private range (RFC1918 10.0.0.0/8, 172.16.0.0/12, "
            "192.168.0.0/16, or link-local 169.254.0.0/16)",
        )

    if any(network.overlaps(protected) for protected in PROTECTED_RANGES):
        raise ValidationError(
            "cidr",
            "overlaps a protected range (this platform's own backend network or loopback) "
            "and can never be a legal scan target",
        )

    return str(network)


def _active_cidrs(conn) -> list[str]:
    rows = conn.execute(
        "SELECT cidr FROM network_scopes WHERE is_active ORDER BY id"
    ).fetchall()
    return [row[0] for row in rows]


def _reconfigure_from(conn) -> list[str]:
    """The one place both device_validation and scan_tests are re-pushed
    the current active list from the database - called after every write
    below, so this API process's own very next request already sees the
    change with zero propagation delay."""
    cidrs = _active_cidrs(conn)
    configure_allowed_networks(cidrs)
    configure_active_scopes(cidrs)
    return cidrs


@router.get("")
def list_network_scopes() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT {NETWORK_SCOPE_COLUMNS} FROM network_scopes "
            "ORDER BY is_active DESC, created_at"
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_network_scope(row) for row in rows]


@router.get("/active")
def list_active_network_scopes() -> dict:
    """The one endpoint auditor-worker actually polls (job_runner.py) -
    kept intentionally small (just the CIDR list) rather than the full row
    shape, since the worker only ever needs to feed it straight into
    configure_allowed_networks()/configure_active_scopes()."""
    conn = get_connection()
    try:
        cidrs = _active_cidrs(conn)
    finally:
        conn.close()
    return {"cidrs": cidrs}


@router.post("", status_code=201)
def create_network_scope(payload: dict) -> dict:
    label = payload.get("label")
    if not isinstance(label, str) or not label.strip():
        raise ValidationError("label", "label is required")
    added_by = payload.get("added_by")
    if not isinstance(added_by, str) or not added_by.strip():
        raise ValidationError("added_by", "added_by is required")
    cidr = _validate_new_cidr(payload.get("cidr", ""))
    source = payload.get("source", "manual")
    if source not in ("manual", "detected"):
        raise ValidationError("source", "source must be 'manual' or 'detected'")
    reason = payload.get("reason")

    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM network_scopes WHERE cidr = %s AND is_active", (cidr,),
        ).fetchone()
        if existing is not None:
            raise ValidationError("cidr", f"{cidr} is already an active scope")

        row = conn.execute(
            f"""
            INSERT INTO network_scopes (label, cidr, kind, source, added_by, reason)
            VALUES (%s, %s, 'custom', %s, %s, %s)
            RETURNING {NETWORK_SCOPE_COLUMNS}
            """,
            (label.strip(), cidr, source, added_by.strip(), reason),
        ).fetchone()
        _reconfigure_from(conn)
        conn.commit()
    finally:
        conn.close()
    return _row_to_network_scope(row)


def _affected_device_count(conn, cidr: str) -> int:
    """How many registered devices' host would stop validating if this
    scope were deactivated - shown to the user before they confirm, so
    deactivation is never a silent surprise. Only ever counts a device
    whose host is a real IP inside this CIDR; a container-name host isn't
    affected by a scope change at all (see INFRASTRUCTURE_HOSTS)."""
    network = ipaddress.ip_network(cidr)
    rows = conn.execute("SELECT host FROM devices").fetchall()
    count = 0
    for (host,) in rows:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        if address in network:
            count += 1
    return count


@router.get("/{scope_id}/deactivation-impact")
def get_deactivation_impact(scope_id: int) -> dict:
    """A dry-run count, called by the frontend before it even shows the
    deactivate confirmation dialog - deactivating is a real mutation
    (POST .../deactivate below), this endpoint changes nothing, so the
    affected-device count can be shown *before* the user commits to
    anything, not just echoed back after the fact."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT cidr FROM network_scopes WHERE id = %s", (scope_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="network scope not found")
        affected = _affected_device_count(conn, row[0])
    finally:
        conn.close()
    return {"affected_device_count": affected}


@router.post("/{scope_id}/deactivate")
def deactivate_network_scope(scope_id: int, payload: dict) -> dict:
    actor = payload.get("actor")
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError("actor", "actor is required")
    reason = payload.get("reason")

    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT cidr, is_active FROM network_scopes WHERE id = %s", (scope_id,),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="network scope not found")
        cidr, is_active = existing
        if not is_active:
            raise ValidationError("scope_id", "this scope is already inactive")

        affected = _affected_device_count(conn, cidr)

        row = conn.execute(
            f"""
            UPDATE network_scopes
            SET is_active = false, deactivated_at = now(), deactivated_by = %s
            WHERE id = %s
            RETURNING {NETWORK_SCOPE_COLUMNS}
            """,
            (actor.strip(), scope_id),
        ).fetchone()
        _reconfigure_from(conn)
        conn.commit()
    finally:
        conn.close()
    return {**_row_to_network_scope(row), "affected_device_count": affected}


@router.post("/{scope_id}/reactivate")
def reactivate_network_scope(scope_id: int) -> dict:
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT cidr, is_active FROM network_scopes WHERE id = %s", (scope_id,),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="network scope not found")
        cidr, is_active = existing
        if is_active:
            raise ValidationError("scope_id", "this scope is already active")

        conflict = conn.execute(
            "SELECT id FROM network_scopes WHERE cidr = %s AND is_active AND id != %s",
            (cidr, scope_id),
        ).fetchone()
        if conflict is not None:
            raise ValidationError(
                "cidr", f"{cidr} is already active on another scope entry"
            )

        row = conn.execute(
            f"""
            UPDATE network_scopes
            SET is_active = true, deactivated_at = NULL, deactivated_by = NULL
            WHERE id = %s
            RETURNING {NETWORK_SCOPE_COLUMNS}
            """,
            (scope_id,),
        ).fetchone()
        _reconfigure_from(conn)
        conn.commit()
    finally:
        conn.close()
    return _row_to_network_scope(row)
