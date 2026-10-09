from __future__ import annotations

import hashlib
import re
from typing import Any


def compute_risk(email: dict[str, Any]) -> dict[str, Any]:
    signals: list[str] = []
    score = 0
    from_value = (email.get('from') or '').lower()
    subject = (email.get('subject') or '').lower()
    body = (email.get('body') or '').lower()
    urls = email.get('urls') or []
    auth = (email.get('authentication_results') or '').lower()

    if 'urgent' in subject or 'immediate' in subject or 'payment' in subject or 'award' in subject or 'scholarship' in subject:
        score += 18
        signals.append('Urgency or award-fraud cues in subject')
    if any(term in body for term in ['wire transfer', 'invoice', 'pay now', 'verify account', 'credentials', 'click here', 'processing fee', 'selected for a scholarship', 'deadline']):
        score += 18
        signals.append('Credential or payment pressure language')
    if '@' in from_value and ('paypal' in from_value or 'campus-awards' in from_value or 'finance' in from_value):
        score += 12
        signals.append('Impersonation pattern in sender address')
    if len(urls) > 0:
        score += min(20, len(urls) * 6)
        signals.append('Embedded URLs detected')
    if 'spf=fail' in auth or 'dkim=fail' in auth or 'dmarc=fail' in auth:
        score += 18
        signals.append('Authentication failures observed')
    if (email.get('reply_to') or '').lower() or 'no-reply' in (email.get('from') or '').lower():
        score += 8
        signals.append('Reply-to mismatch or generic sender')
    if any(ext in body for ext in ['.exe', '.js', '.zip', '.scr', '.dll']):
        score += 10
        signals.append('Suspicious file/URL indicators')
    if 'urgent payment' in subject or 'bank' in subject or 'payment processing fee' in subject:
        score += 10
        signals.append('Business email compromise style subject')

    # Cap and normalize risk
    score = max(0, min(100, score))
    if score < 25:
        category = 'Low'
    elif score < 50:
        category = 'Guarded'
    elif score < 75:
        category = 'High'
    else:
        category = 'Critical'

    if not signals:
        signals = ['No strong email threats detected']

    return {
        'risk_score': score,
        'risk_category': category,
        'confidence': 'Moderate' if score >= 35 else 'Low',
        'signals': signals,
        'evidence': [
            'Subject line tone and urgency cues',
            'Embedded links and suspicious payload indicators',
            'Authentication status and sender metadata',
        ],
        'recommended_actions': [
            'Review sender identity and domain reputation',
            'Verify any requested action through a known channel',
            'Check for malicious URLs or attachment payloads',
        ],
        'summary': 'Deterministic evaluation suggests the message should be reviewed with caution.',
    }


def build_demo_analysis(email: dict[str, Any]) -> dict[str, Any]:
    risk = compute_risk(email)
    return {
        'message_id': email.get('id', 'demo-email'),
        'from': email.get('from', 'unknown@demo.local'),
        'subject': email.get('subject', 'demo'),
        'risk_score': risk['risk_score'],
        'risk_category': risk['risk_category'],
        'confidence': risk['confidence'],
        'summary': risk['summary'],
        'signals': risk['signals'],
        'evidence': risk['evidence'],
        'recommended_actions': risk['recommended_actions'],
        'model_status': 'local-fallback',
    }
