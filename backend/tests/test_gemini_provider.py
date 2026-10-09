import json

import pytest

from app.services import gemini_provider


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return self.payload


def test_gemini_response_is_parsed_and_unmatched_evidence_is_removed(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY', 'test-key')
    monkeypatch.setattr(
        gemini_provider.urllib.request,
        'urlopen',
        lambda request, timeout: FakeResponse({
            'steps': [{
                'type': 'model_output',
                'content': [{
                    'type': 'text',
                    'text': json.dumps({
                        'suspected_threat': 'Possible phishing',
                        'summary': 'The message requests payment.',
                        'evidence_references': ['Observed URL', 'fabricated indicator'],
                        'recommended_actions': ['Verify using a known contact'],
                        'uncertainties': ['Sender identity is not verified'],
                    }),
                }],
            }],
        }),
    )
    result = gemini_provider.explain_with_gemini(
        {
            'from': 'person@example.test',
            'subject': 'Payment request',
            'body': 'Please pay now',
            'urls': ['https://example.test'],
        },
        {
            'risk_score': 72,
            'risk_category': 'High',
            'signals': ['Payment pressure'],
            'evidence': ['Observed URL'],
            'recommended_actions': ['Inspect the URL'],
        },
    )
    assert result['provider'] == 'Google Gemini'
    assert result['evidence_references'] == ['Observed URL']


def test_gemini_requires_key(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    with pytest.raises(RuntimeError, match='GEMINI_API_KEY'):
        gemini_provider.explain_with_gemini({}, {})
