# PhishTrace

PhishTrace is a local-first email investigation prototype. Upload an email file to parse its headers and body, calculate an explainable rules-based risk score, and verify the SHA-256 digest of the exact original bytes. The inbox starts empty: the app does not present synthetic messages as live data.

## Run locally

Requirements: Python 3.11+ and Node.js 20+.

### Backend (Windows PowerShell)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend (second terminal)

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173, choose an `.eml` or `.txt` email file (up to 8 MB), and select **Analyze email**. The deterministic analysis runs locally. The uploaded message is held in process memory while the backend is running; restarting it clears the in-memory history.

## What works in this preview

- MIME/RFC-style email parsing, including sender fields, Received headers, authentication results, URLs, and attachment hashes.
- Deterministic, evidence-explained threat scoring with a 0–100 score and risk category.
- Analysis history for messages uploaded during the current backend process.
- SHA-256 of the original file bytes and a verification action that re-hashes those bytes.
- Empty inbox until a user supplies an actual message.
- Optional, user-consented Gemini explanation via Google's Interactions API. It does not alter the deterministic score.

The `samples/` folder contains explicitly synthetic `.eml` files for parser testing. They are not loaded into the application.

## Optional Google Gemini explanation

1. Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/api-keys).
2. Copy `backend/.env.example` to `backend/.env` and set `GEMINI_API_KEY`. Keep the key private; `.env` is ignored by Git.
3. Start the backend with the env file loaded:

   ```powershell
   cd backend
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 --env-file .env
   ```

4. Restart the frontend page, upload an email, select the cloud-content consent checkbox, then choose **Explain with Gemini**.

The app only sends email fields to Google after the user explicitly requests an explanation. The request is limited to the sender, subject, first 6,000 characters of the text body, URLs, observed authentication results, and local findings. Do not use this for confidential messages unless your organization's data-handling policy allows it. Google API access, quotas, pricing, and retention are governed by your Google account and Google's current terms. The API key remains in the backend environment and is never returned to the browser. No Gemini request was made during development because no API key was supplied.

Model default: `gemini-3.8-flash`, as shown in Google's [Gemini API model documentation](https://ai.google.dev/gemini-api/docs/models) and [Interactions API quickstart](https://ai.google.dev/gemini-api/docs/get-started). Override with `GEMINI_MODEL` if your account does not have access to it.

## Other integration status

- **Gmail:** not connected; no OAuth flow is implemented. Gmail status is not represented as successful.
- **Campaigns and geolocation:** not implemented in this preview.
- **Storage:** uploaded messages and evidence are currently in memory and cleared when the backend process restarts.

Risk scores are prototype heuristics, not calibrated probabilities. Received headers can be forged, observed SPF/DKIM/DMARC text is not independent cryptographic verification, and IP information cannot establish a person's identity or precise location. Do not treat reports as legally certified evidence.

## Tests

```powershell
cd backend
python -m pytest -q
```

## License

MIT. See [LICENSE](./LICENSE).
