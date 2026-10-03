"""Audit records, JSONL, CSV export. Spec section 4 step 10, section 13. Owner: Person 4."""
from __future__ import annotations

from gateway.models import AuditRecord


def write_audit(record: AuditRecord) -> None:
    """Append exactly one audit record for the request; never values. Spec section 4 step 10, I8, I12."""
    raise NotImplementedError
