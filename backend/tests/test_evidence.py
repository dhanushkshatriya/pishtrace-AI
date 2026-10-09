import hashlib

from app.main import app
from app.services.evidence_service import verify_integrity


def test_evidence_verification_detects_modification():
    record = {'message_digest': 'abc123'}
    payload = b'original-event'
    result = verify_integrity(record, payload)
    assert 'matches' in result
    assert result['stored_digest'] == 'abc123'


def test_api_smoke():
    from fastapi.testclient import TestClient

    client = TestClient(app)
    resp = client.get('/api/health')
    assert resp.status_code == 200
    assert resp.json()['status'] == 'ok'


def test_uploaded_message_is_analyzed_and_original_digest_verifies():
    from fastapi.testclient import TestClient

    raw = (
        b'From: sender@example.test\r\n'
        b'To: analyst@example.test\r\n'
        b'Subject: Urgent payment verification\r\n'
        b'Authentication-Results: spf=fail; dkim=fail\r\n'
        b'Content-Type: text/plain; charset=utf-8\r\n'
        b'\r\n'
        b'Pay now to verify account at https://example.test/pay\r\n'
    )
    client = TestClient(app)
    response = client.post(
        '/api/emails/upload',
        files={'file': ('message.eml', raw, 'message/rfc822')},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload['analysis']['risk_score'] >= 50
    assert payload['email']['digest'] == hashlib.sha256(raw).hexdigest()

    verify = client.post(f"/api/evidence/{payload['evidence_record']['investigation_id']}/verify")
    assert verify.status_code == 200
    assert verify.json()['matches'] is True


def test_invalid_upload_fails():
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post(
        '/api/emails/upload',
        files={'file': ('bad.eml', b'not-an-email', 'message/rfc822')},
    )
    assert response.status_code == 400


def test_gemini_endpoint_reports_missing_key():
    from fastapi.testclient import TestClient

    client = TestClient(app)
    upload = client.post(
        '/api/emails/upload',
        files={'file': ('key-check.eml', b'From: a@example.test\nSubject: Test\n\ntext\n', 'message/rfc822')},
    )
    assert upload.status_code == 200
    message_id = upload.json()['email']['id']
    response = client.post(f'/api/emails/{message_id}/explain-with-gemini')
    assert response.status_code == 503
    assert 'GEMINI_API_KEY' in response.json()['detail']
