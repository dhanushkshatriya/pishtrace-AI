from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

PRIVATE_IP_RE = re.compile(r'^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|fc00:|fe80:|fd00:|ff00:|localhost)$')


def parse_email_bytes(raw_bytes: bytes, source: str = 'upload') -> dict[str, Any]:
    if not raw_bytes:
        raise ValueError('Email message is empty or invalid')
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    if not msg.items():
        raise ValueError('No RFC-style email headers were found.')

    headers = {k.lower(): v for k, v in msg.items()}
    from_value = headers.get('from', '')
    to_value = headers.get('to', '')
    subject = headers.get('subject', '')
    date_value = headers.get('date', '')
    message_id = headers.get('message-id', '')
    reply_to = headers.get('reply-to', '')
    return_path = headers.get('return-path', '')
    auth_results = headers.get('authentication-results', '')

    received = msg.get_all('received', []) or []
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)
    body = extract_body_text(msg)
    digest = hashlib.sha256(raw_bytes).hexdigest()

    return {
        'id': message_id or digest[:12],
        'source': source,
        'from': from_value,
        'to': to_value,
        'reply_to': reply_to,
        'return_path': return_path,
        'subject': subject,
        'date': date_value,
        'message_id': message_id,
        'received_headers': received,
        'authentication_results': auth_results,
        'urls': urls,
        'attachments': attachments,
        'body': body,
        'digest': digest,
        'metadata': {
            'content_type': msg.get_content_type(),
            'content_charset': msg.get_content_charset(),
            'has_attachments': bool(attachments),
        },
        'parsed_at': datetime.now(timezone.utc).isoformat(),
    }


def extract_body_text(msg: Any) -> str:
    parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if content_type.startswith('text/'):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    text = payload.decode('utf-8', errors='replace')
                except Exception:
                    text = payload.decode('latin-1', errors='replace')
                parts.append(text)
    return '\n'.join(parts)


def extract_urls(msg: Any) -> list[str]:
    text = extract_body_text(msg)
    found = set(re.findall(r'https?://[^\s\)\]>"\']+', text, flags=re.IGNORECASE))
    return sorted(found)


def extract_attachments(msg: Any) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        sanitized = sanitize_filename(filename)
        payload = part.get_payload(decode=True) or b''
        attachments.append({
            'filename': sanitized,
            'mime_type': part.get_content_type(),
            'size': len(payload),
            'sha256': hashlib.sha256(payload).hexdigest(),
        })
    return attachments


def sanitize_filename(name: str) -> str:
    candidate = os.path.basename(name).replace('..', '')
    return candidate[:120] or 'attachment.bin'


def get_public_candidate_ips(received_headers: list[str]) -> list[str]:
    ips: list[str] = []
    pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9:]+)\b')
    for header in received_headers:
        for match in pattern.findall(header):
            if is_private_ip_or_loopback(match):
                continue
            ips.append(match)
    return ips


def is_private_ip_or_loopback(value: str) -> bool:
    val = value.strip().rstrip('.')
    if val.startswith('[') and val.endswith(']'):
        val = val[1:-1]
    if val.lower() in {'localhost', '::1'}:
        return True
    if '.' in val:
        parts = val.split('.')
        if len(parts) != 4:
            return True
        try:
            ints = [int(p) for p in parts]
        except ValueError:
            return True
        if any(p < 0 or p > 255 for p in ints):
            return True
        return any([
            ints[0] == 10,
            ints[0] == 127,
            ints[0] == 169 and ints[1] == 254,
            ints[0] == 192 and ints[1] == 168,
            ints[0] == 172 and 16 <= ints[1] <= 31,
            ints[0] == 0,
        ])
    if ':' in val:
        return val.lower().startswith(('fc', 'fd', 'fe80', '::1'))
    return False


def parse_email_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(path)
    if file_path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Email file exceeds 8 MB limit')
    return parse_email_bytes(file_path.read_bytes(), source='upload')
