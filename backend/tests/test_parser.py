from pathlib import Path

import pytest

from app.services.email_parser import parse_email_bytes, parse_email_file
from app.services.threat_engine import compute_risk


def test_legitimate_sample_parses():
    email = parse_email_file(Path(__file__).resolve().parents[2] / 'samples' / 'legitimate-bank.eml')
    assert email['subject'] == 'Account statement is ready'
    assert email['from']
    assert 'spf=pass' in (email['authentication_results'] or '').lower()


def test_suspicious_sample_scores_high():
    email = parse_email_file(Path(__file__).resolve().parents[2] / 'samples' / 'suspicious-scholarship.eml')
    risk = compute_risk(email)
    assert 0 <= risk['risk_score'] <= 100
    assert risk['risk_score'] >= 45
    assert 'Embedded URLs detected' in risk['signals']


def test_bad_email_fails_safely():
    with pytest.raises(ValueError):
        parse_email_bytes(b'not-a-real-email')
