"""
roles.py - Role-based access control.

Roles (matches the accountability framework):
  operator       - IoT gateway; submits events (POST /events only)
  safety_manager - site supervisor; reads events, no verify
  inspector      - auditor; reads + verifies + exports
  insurer        - adjuster; reads + verifies (no export)

In production, role is determined by the client TLS certificate MSP attribute.
In stub/dev mode, pass X-Role header.
"""
from enum import Enum
from typing import Optional
from fastapi import Header, HTTPException


class Role(str, Enum):
    OPERATOR       = "operator"
    SAFETY_MANAGER = "safety_manager"
    INSPECTOR      = "inspector"
    INSURER        = "insurer"


PERMISSIONS: dict[Role, set[str]] = {
    Role.OPERATOR:       {"submit_event", "read_health"},
    Role.SAFETY_MANAGER: {"read_events", "read_batches", "read_stats", "read_health"},
    Role.INSPECTOR:      {"read_events", "read_batches", "read_stats",
                          "verify_batch", "verify_event", "export_report", "read_health"},
    Role.INSURER:        {"read_events", "read_batches", "verify_batch",
                          "verify_event", "read_health"},
}


def resolve_role(x_role: Optional[str]) -> Role:
    try:
        return Role(x_role.lower()) if x_role else Role.INSPECTOR
    except ValueError:
        return Role.INSPECTOR


def require(operation: str):
    def _dep(x_role: Optional[str] = Header(default=None, alias="X-Role")) -> Role:
        role = resolve_role(x_role)
        if operation not in PERMISSIONS.get(role, set()):
            raise HTTPException(403, detail={
                "error": "access_denied", "operation": operation, "role": role,
                "allowed_roles": [r for r, p in PERMISSIONS.items() if operation in p],
            })
        return role
    return _dep


def get_role(x_role: Optional[str] = Header(default=None, alias="X-Role")) -> Role:
    return resolve_role(x_role)
