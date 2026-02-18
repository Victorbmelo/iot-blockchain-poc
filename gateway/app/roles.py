"""
Role-based access control for the Audit Gateway.

Defines the four roles in the construction site accountability framework
and the operations each role is permitted to perform.

In Fabric mode, role is determined by the submitting MSP identity attributes.
In stub mode, role is passed via the X-Role request header (for demo purposes).

Roles:
  contractor      - submits events (IoT gateway); cannot read own history post-incident
  safety_manager  - reads and queries; flags events; cannot write
  inspector       - reads, queries, verifies; produces audit packages
  insurer         - reads and verifies only; no write; time-limited access

The chaincode enforces write access at the MSP level.
The gateway enforces read-path role restrictions.
"""
from enum import Enum
from typing import Optional

from fastapi import Header, HTTPException, Request


class Role(str, Enum):
    CONTRACTOR = "contractor"        # AuditGatewayMSP - writer
    SAFETY_MANAGER = "safety_manager"  # AuditGatewayMSP - reader/supervisor
    INSPECTOR = "inspector"          # InspectorMSP - auditor
    INSURER = "insurer"              # InsurerMSP (read-only observer)


# Permissions matrix - maps role to allowed operation groups
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.CONTRACTOR: {
        "submit_event",          # POST /events
        "read_own_events",       # GET /events/{id} (own events only in production)
        "read_health",
    },
    Role.SAFETY_MANAGER: {
        "read_health",
        "read_events",           # GET /events, /actors/{id}/events, /zones/{id}/events
        "read_near_misses",      # GET /near-misses
        "query_stats",           # GET /stats
    },
    Role.INSPECTOR: {
        "read_health",
        "read_events",
        "read_near_misses",
        "query_stats",
        "verify_event",          # POST /verify
        "trace_chain",           # GET /events/{id}/chain
        "read_history",          # GET /events/{id}/history
        "export_audit_report",   # GET /audit/report
        "read_pubkey",           # GET /pubkey
    },
    Role.INSURER: {
        "read_health",
        "read_events",
        "verify_event",
        "read_pubkey",
    },
}

# Default role when no X-Role header is present (stub/dev mode)
_DEFAULT_ROLE = Role.INSPECTOR


def _resolve_role(x_role: Optional[str]) -> Role:
    """Resolve the caller's role from the X-Role header value."""
    if not x_role:
        return _DEFAULT_ROLE
    try:
        return Role(x_role.lower())
    except ValueError:
        return _DEFAULT_ROLE


def has_permission(role: Role, operation: str) -> bool:
    return operation in ROLE_PERMISSIONS.get(role, set())


def require_permission(operation: str):
    """FastAPI dependency: raises 403 if the caller's role lacks the operation."""
    def _check(x_role: Optional[str] = Header(default=None, alias="X-Role")):
        role = _resolve_role(x_role)
        if not has_permission(role, operation):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "access_denied",
                    "operation": operation,
                    "role": role,
                    "hint": f"This operation requires one of: "
                            f"{[r for r, perms in ROLE_PERMISSIONS.items() if operation in perms]}",
                },
            )
        return role
    return _check


def get_role(x_role: Optional[str] = Header(default=None, alias="X-Role")) -> Role:
    """FastAPI dependency: returns caller role without enforcing a specific permission."""
    return _resolve_role(x_role)


# Human-readable role descriptions for documentation and API responses
ROLE_DESCRIPTIONS = {
    Role.CONTRACTOR: {
        "msp": "AuditGatewayMSP",
        "description": "IoT gateway operator; submits safety events from the site platform",
        "can_write": True,
        "can_read": True,
        "can_verify": False,
        "can_export_audit": False,
    },
    Role.SAFETY_MANAGER: {
        "msp": "AuditGatewayMSP",
        "description": "Site safety manager; monitors events and near-misses in real time",
        "can_write": False,
        "can_read": True,
        "can_verify": False,
        "can_export_audit": False,
    },
    Role.INSPECTOR: {
        "msp": "InspectorMSP",
        "description": "Regulatory inspector or auditor; verifies integrity and exports audit packages",
        "can_write": False,
        "can_read": True,
        "can_verify": True,
        "can_export_audit": True,
    },
    Role.INSURER: {
        "msp": "InsurerMSP",
        "description": "Insurance adjuster; reads events and verifies hashes for claim validation",
        "can_write": False,
        "can_read": True,
        "can_verify": True,
        "can_export_audit": False,
    },
}
