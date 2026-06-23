"""Cooperative scan cancellation.

A running scan can't be force-killed across processes, so executors cooperate: the API
sets Scan.cancel_requested = True, and each executor (the DB worker and the backend scan
threads) periodically calls is_cancelled() and aborts cleanly, marking the scan
'cancelled'. is_cancelled() issues a fresh SELECT so it sees the flag set by the API's
separate DB session.
"""
from ..models import Scan


class ScanCancelled(Exception):
    """Raised inside an executor when the operator has requested a stop."""


def is_cancelled(db, scan_id: int) -> bool:
    return bool(db.query(Scan.cancel_requested).filter(Scan.id == scan_id).scalar())
