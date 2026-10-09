from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)

GMAIL_CLIENT_ID = os.getenv('GMAIL_CLIENT_ID', '')
GMAIL_CLIENT_SECRET = os.getenv('GMAIL_CLIENT_SECRET', '')
GMAIL_REDIRECT_URI = os.getenv('GMAIL_REDIRECT_URI', 'http://localhost:8000/api/integrations/gmail/callback')
GMAIL_READ_ONLY_SCOPE = os.getenv('GMAIL_READ_ONLY_SCOPE', 'https://www.googleapis.com/auth/gmail.readonly')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.8-flash')
AI_ENABLED = os.getenv('USE_LOCAL_LLM', 'false').lower() == 'true'
