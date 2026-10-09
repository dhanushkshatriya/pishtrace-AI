from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def compute_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def build_evidence_record(email: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        'investigation_id': f"INV-{hashlib.sha256((email.get('id', '') + str(datetime.now(timezone.utc).timestamp())).encode()).hexdigest()[:12]}",
        'message_digest': email.get('digest') or compute_digest(json.dumps(email, sort_keys=True).encode()),
        'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
        'analysis_version': 'phishtrace-v1',
        'risk_score': analysis.get('risk_score', 0),
        'risk_category': analysis.get('risk_category', 'Low'),
        'signals': analysis.get('signals', []),
        'evidence': analysis.get('evidence', []),
        'model_status': analysis.get('model_status', 'local-fallback'),
        'source': email.get('source', 'demo'),
    }
    return evidence


def verify_integrity(record: dict[str, Any], content: bytes) -> dict[str, Any]:
    current_digest = compute_digest(content)
    stored = record.get('message_digest')
    return {
        'matches': current_digest == stored,
        'stored_digest': stored,
        'current_digest': current_digest,
        'verified_at': datetime.now(timezone.utc).isoformat(),
    }
