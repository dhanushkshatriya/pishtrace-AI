from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.config import GEMINI_API_KEY, GEMINI_MODEL
from app.services.email_parser import parse_email_bytes
from app.services.evidence_service import build_evidence_record, compute_digest, verify_integrity
from app.services.gemini_provider import explain_with_gemini, get_ai_status, summarize_email
from app.services.threat_engine import compute_risk

app = FastAPI(title='PhishTrace', version='0.1.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'],
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(health_router, prefix='/api')
UPLOADED_EMAILS: dict[str, dict[str, Any]] = {}
EVIDENCE_RECORDS: dict[str, dict[str, Any]] = {}
RAW_MESSAGES: dict[str, bytes] = {}


def _analysis_for(email: dict) -> dict:
    analysis = compute_risk(email)
    analysis['message_id'] = email['id']
    analysis['model_status'] = get_ai_status()
    analysis['ai_summary'] = summarize_email({'risk': analysis})
    return analysis


@app.get('/api/dashboard/summary')
def dashboard_summary():
    emails = [{**email, 'risk_score': _analysis_for(email)['risk_score']} for email in UPLOADED_EMAILS.values()]
    high_risk = sum(1 for email in emails if email['risk_score'] >= 50)
    return {
        'total_emails': len(emails),
        'high_risk': high_risk,
        'gmail_connected': False,
        'ai_status': get_ai_status(),
        'latest_risk': emails[-1]['risk_score'] if emails else 0,
    }


@app.get('/api/emails')
def list_emails():
    rows = []
    for email in UPLOADED_EMAILS.values():
        analysis = _analysis_for(email)
        rows.append({
            'id': email['id'],
            'from': email['from'],
            'subject': email['subject'],
            'risk_score': analysis['risk_score'],
            'risk_category': analysis['risk_category'],
            'status': 'analyzed',
            'source': email['source'],
            'received_at': email['date'],
        })
    return {'emails': rows}


@app.post('/api/emails/upload')
async def upload_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(('.eml', '.txt')):
        raise HTTPException(status_code=400, detail='Upload an .eml or .txt email file.')
    raw = await file.read(8 * 1024 * 1024 + 1)
    if not raw:
        raise HTTPException(status_code=400, detail='The uploaded email file is empty.')
    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail='Email files must be 8 MB or smaller.')
    try:
        parsed = parse_email_bytes(raw, source='uploaded file')
    except (ValueError, UnicodeError) as error:
        raise HTTPException(status_code=400, detail=f'Unable to parse email: {error}') from error
    if not parsed.get('from') and not parsed.get('subject') and not parsed.get('body'):
        raise HTTPException(status_code=400, detail='The file does not contain recognizable email content.')
    digest = compute_digest(raw)
    message_id = f'email-{digest[:16]}'
    parsed['id'] = message_id
    parsed['digest'] = digest
    UPLOADED_EMAILS[message_id] = parsed
    RAW_MESSAGES[message_id] = raw
    analysis = _analysis_for(parsed)
    record = build_evidence_record(parsed, analysis)
    EVIDENCE_RECORDS[record['investigation_id']] = record
    return {
        'message': 'Uploaded email parsed and analyzed locally.',
        'email': {
            'id': message_id,
            'from': parsed['from'],
            'to': parsed['to'],
            'reply_to': parsed['reply_to'],
            'return_path': parsed['return_path'],
            'subject': parsed['subject'],
            'date': parsed['date'],
            'received_headers': parsed['received_headers'],
            'authentication_results': parsed['authentication_results'],
            'urls': parsed['urls'],
            'attachments': parsed['attachments'],
            'digest': digest,
            'metadata': parsed['metadata'],
        },
        'analysis': analysis,
        'evidence_record': record,
    }


@app.get('/api/emails/{message_id}')
def get_email(message_id: str):
    email = UPLOADED_EMAILS.get(message_id)
    if email is None:
        raise HTTPException(status_code=404, detail='Uploaded email not found.')
    record = next(
        (item for item in EVIDENCE_RECORDS.values() if item['message_digest'] == email['digest']),
        None,
    )
    if record is None:
        raise HTTPException(status_code=404, detail='Evidence record for this email is unavailable.')
    return {**email, 'analysis': _analysis_for(email), 'evidence_record': record}


@app.post('/api/emails/{message_id}/analyze')
def analyze_email(message_id: str):
    email = UPLOADED_EMAILS.get(message_id)
    if email is None:
        raise HTTPException(status_code=404, detail='Uploaded email not found.')
    analysis = _analysis_for(email)
    return {
        'message_id': message_id,
        'from': email['from'],
        'subject': email['subject'],
        **analysis,
    }


@app.post('/api/emails/{message_id}/explain-with-gemini')
async def explain_email(message_id: str):
    email = UPLOADED_EMAILS.get(message_id)
    if email is None:
        raise HTTPException(status_code=404, detail='Uploaded email not found.')
    if not GEMINI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail='Gemini API key is not configured. Add GEMINI_API_KEY to the backend environment and restart it.',
        )
    risk = compute_risk(email)
    try:
        explanation = await asyncio.to_thread(explain_with_gemini, email, risk)
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return {
        'message_id': message_id,
        'risk_score': risk['risk_score'],
        'risk_category': risk['risk_category'],
        'explanation': explanation,
        'notice': 'Gemini explanation only; deterministic risk score is unchanged.',
    }


@app.get('/api/campaigns')
def campaigns():
    return {'campaigns': [], 'message': 'Campaign correlation requires multiple uploaded emails.'}


@app.get('/api/evidence')
def evidence():
    return {'items': list(EVIDENCE_RECORDS.values())}


@app.post('/api/evidence/{investigation_id}/verify')
def verify_investigation(investigation_id: str):
    record = EVIDENCE_RECORDS.get(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail='Evidence record not found.')
    message_id = next(
        (key for key, email in UPLOADED_EMAILS.items() if email['digest'] == record['message_digest']),
        None,
    )
    if message_id is None:
        raise HTTPException(status_code=404, detail='Original uploaded message is no longer available.')
    return verify_integrity(record, RAW_MESSAGES[message_id])


@app.get('/api/integrations/gmail/status')
def gmail_status():
    return {
        'connected': False,
        'mode': 'not configured',
        'message': 'Google OAuth is not configured. Upload an .eml file to analyze a message locally.',
        'scope': 'https://www.googleapis.com/auth/gmail.readonly',
    }


@app.get('/api/ai/status')
def ai_status():
    return {
        'provider': 'Google Gemini',
        'model': GEMINI_MODEL,
        'configured': bool(GEMINI_API_KEY),
        'model_status': get_ai_status(),
    }


@app.get('/')
def root():
    return {'ok': True, 'project': 'PhishTrace'}
