import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';

type EmailSummary = {
  id: string;
  from: string;
  subject: string;
  risk_score: number;
  risk_category: string;
  status: string;
  source: string;
  received_at: string;
};

type DashboardSummary = {
  total_emails: number;
  high_risk: number;
  gmail_connected: boolean;
  ai_status: string;
  latest_risk: number;
};

type Investigation = {
  id: string;
  from: string;
  to: string;
  reply_to: string;
  return_path: string;
  subject: string;
  date: string;
  received_headers: string[];
  authentication_results: string;
  urls: string[];
  attachments: { filename: string; mime_type: string; size: number; sha256: string }[];
  digest: string;
  metadata: { content_type: string; content_charset: string | null; has_attachments: boolean };
  analysis: {
    risk_score: number;
    risk_category: string;
    confidence: string;
    signals: string[];
    evidence: string[];
    recommended_actions: string[];
    summary: string;
    model_status: string;
    ai_summary: { suspected_threat: string; summary: string; uncertainties: string[] };
  };
  evidence_record: { investigation_id: string; analysis_timestamp: string; analysis_version: string };
};

type GeminiExplanation = {
  suspected_threat: string;
  summary: string;
  evidence_references: string[];
  recommended_actions: string[];
  uncertainties: string[];
  provider: string;
  model: string;
};

type AiStatus = {
  provider: string;
  model: string;
  configured: boolean;
  model_status: string;
};

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

function App() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  const [emails, setEmails] = useState<EmailSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [geminiExplanation, setGeminiExplanation] = useState<GeminiExplanation | null>(null);
  const [consentToCloud, setConsentToCloud] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [verification, setVerification] = useState<string | null>(null);

  useEffect(() => {
    void loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      const [summaryResponse, emailsResponse] = await Promise.all([
        fetch(`${API_BASE}/api/dashboard/summary`),
        fetch(`${API_BASE}/api/emails`),
      ]);
      const aiResponse = await fetch(`${API_BASE}/api/ai/status`);
      if (!summaryResponse.ok || !emailsResponse.ok) {
        throw new Error('PhishTrace API is unavailable. Start the backend on port 8000.');
      }
      const [summaryData, emailsData, aiData] = await Promise.all([
        summaryResponse.json(),
        emailsResponse.json(),
        aiResponse.ok ? aiResponse.json() : Promise.resolve(null),
      ]);
      setSummary(summaryData);
      setEmails(emailsData.emails ?? []);
      setAiStatus(aiData);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to connect to the API.');
    }
  }

  async function uploadEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError('Choose an .eml or .txt email file first.');
      return;
    }

    setLoading(true);
    setError('');
    setVerification(null);
    setGeminiExplanation(null);
    setConsentToCloud(false);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE}/api/emails/upload`, {
        method: 'POST',
        body: formData,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail ?? 'The email could not be analyzed.');
      }
      const result: Investigation = { ...payload.email, analysis: payload.analysis, evidence_record: payload.evidence_record };
      setInvestigation(result);
      setSelectedId(result.id);
      setFile(null);
      const picker = document.querySelector<HTMLInputElement>('#email-file');
      if (picker) picker.value = '';
      await loadDashboard();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Email analysis failed.');
    } finally {
      setLoading(false);
    }
  }

  async function requestGeminiExplanation() {
    if (!investigation || !consentToCloud) return;
    setLoading(true);
    setError('');
    setGeminiExplanation(null);
    try {
      const response = await fetch(
        `${API_BASE}/api/emails/${investigation.id}/explain-with-gemini`,
        { method: 'POST' },
      );
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? 'Gemini explanation failed.');
      setGeminiExplanation(payload.explanation);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Gemini explanation failed.');
    } finally {
      setLoading(false);
    }
  }

  async function verifyEvidence() {
    if (!investigation) return;
    setVerification(null);
    try {
      const response = await fetch(
        `${API_BASE}/api/evidence/${investigation.evidence_record.investigation_id}/verify`,
        { method: 'POST' },
      );
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? 'Verification failed.');
      setVerification(
        payload.matches
          ? `Verified: SHA-256 matches the uploaded original (${payload.current_digest}).`
          : `Mismatch: expected ${payload.stored_digest}, recalculated ${payload.current_digest}.`,
      );
    } catch (cause) {
      setVerification(cause instanceof Error ? cause.message : 'Verification failed.');
    }
  }

  async function openInvestigation(emailId: string) {
    setSelectedId(emailId);
    setError('');
    setGeminiExplanation(null);
    setConsentToCloud(false);
    try {
      const response = await fetch(`${API_BASE}/api/emails/${emailId}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? 'Unable to load this investigation.');
      setInvestigation(payload);
      setVerification(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load this investigation.');
    }
  }

  const selectedEmail = emails.find((email) => email.id === selectedId);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark">P</div>
          <div>
            <div className="brand">PhishTrace</div>
            <div className="muted">Email threat analysis · runs locally</div>
          </div>
        </div>
        <div className="actions">
          <span className="badge ok">Local analysis</span>
          <span className={`badge ${aiStatus?.configured ? 'ok' : 'warn'}`}>
            {aiStatus?.configured
              ? `Gemini configured · ${aiStatus.model}`
              : 'Gemini not configured · rules fallback'}
          </span>
        </div>
      </header>

      <section className="summary-grid">
        <Card title="Messages analyzed" value={String(summary?.total_emails ?? 0)} />
        <Card title="High risk" value={String(summary?.high_risk ?? 0)} accent="critical" />
        <Card title="Latest risk score" value={summary?.total_emails ? `${summary.latest_risk}/100` : '—'} />
        <Card title="Analysis provider" value="Local rules" accent="warn" />
      </section>

      <section className="upload-card card">
        <div className="section-heading">
          <div>
            <div className="eyebrow">Analyze your own message</div>
            <h2>Upload an email file</h2>
            <p className="muted">The original file is processed by this local backend. It is not sent to an external AI service.</p>
          </div>
          <div className="upload-symbol" aria-hidden="true">↥</div>
        </div>
        <form className="upload-form" onSubmit={(event) => void uploadEmail(event)}>
          <label className="file-picker" htmlFor="email-file">
            <span className="file-icon">.eml</span>
            <span>
              <strong>{file?.name ?? 'Choose an email file'}</strong>
              <small>{file ? `${(file.size / 1024).toFixed(1)} KB · ready to analyze` : 'RFC email format · maximum 8 MB'}</small>
            </span>
            <span className="pick-action">Browse files</span>
          </label>
          <input
            id="email-file"
            type="file"
            accept=".eml,.txt,message/rfc822,text/plain"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <button type="submit" disabled={loading || !file}>
            {loading ? 'Analyzing locally…' : 'Analyze email'}
          </button>
        </form>
        {error && <div className="error-message" role="alert">{error}</div>}
      </section>

      <div className="grid">
        <section className="card inbox-card">
          <div className="row section-title">
            <div>
              <div className="eyebrow">Your uploaded files</div>
              <h2>Analysis history</h2>
            </div>
            <button className="ghost" onClick={() => void loadDashboard()}>Refresh</button>
          </div>
          {emails.length ? (
            <div className="email-list">
              {emails.map((email) => (
                <button
                  className={`email-item ${selectedId === email.id ? 'selected' : ''}`}
                  key={email.id}
                  onClick={() => void openInvestigation(email.id)}
                >
                  <span className="email-info">
                    <strong>{email.subject || '(no subject)'}</strong>
                    <small>{email.from || '(unknown sender)'} · {email.received_at || 'Date not supplied'}</small>
                  </span>
                  <span className={`risk-score ${riskTone(email.risk_category)}`}>{email.risk_score}</span>
                </button>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <span className="empty-mark">＋</span>
              <strong>No messages analyzed yet</strong>
              <p>Upload a real .eml file above to create your first investigation.</p>
            </div>
          )}
        </section>

        <section className="card investigation-card">
          <div className="eyebrow">Investigation workspace</div>
          <h2>{investigation?.subject || selectedEmail?.subject || 'Your analysis will appear here'}</h2>
          {investigation ? (
            <>
              <div className="risk-banner">
                <div className={`risk-number ${riskTone(investigation.analysis.risk_category)}`}>
                  {investigation.analysis.risk_score}
                  <small>/100</small>
                </div>
                <div>
                  <span className={`badge ${riskTone(investigation.analysis.risk_category)}`}>{investigation.analysis.risk_category} risk</span>
                  <p>{investigation.analysis.summary}</p>
                  <small>Confidence: {investigation.analysis.confidence} · Prototype score, not a probability</small>
                </div>
              </div>

              <div className="detail-block">
                <h3>Detection signals</h3>
                <ul className="signal-list">
                  {investigation.analysis.signals.map((signal) => <li key={signal}>{signal}</li>)}
                </ul>
              </div>

              <div className="detail-block">
                <h3>Observed message details</h3>
                <dl className="details">
                  <dt>From</dt><dd>{investigation.from || 'Unknown'}</dd>
                  <dt>To</dt><dd>{investigation.to || 'Unknown'}</dd>
                  <dt>Reply-To</dt><dd>{investigation.reply_to || 'Not provided'}</dd>
                  <dt>Authentication</dt><dd>{investigation.authentication_results || 'Not present (unknown)'}</dd>
                  <dt>URLs</dt><dd>{investigation.urls.length ? investigation.urls.join(', ') : 'None found'}</dd>
                  <dt>Attachments</dt><dd>{investigation.attachments.length ? investigation.attachments.map((a) => `${a.filename} (${a.mime_type}, ${a.size} bytes)`).join('; ') : 'None found'}</dd>
                </dl>
              </div>

              <div className="detail-block">
                <h3>Original file integrity</h3>
                <p className="digest">{investigation.digest}</p>
                <small>SHA-256 of the exact uploaded file bytes</small>
                <div className="actions verify-actions">
                  <button className="secondary" onClick={() => void verifyEvidence()}>Verify original digest</button>
                  {verification && <span className="verify-result">{verification}</span>}
                </div>
              </div>
              <div className="notice">
                Rules-based score is deterministic. A Gemini explanation is optional and never changes that score.
              </div>
              <div className="detail-block gemini-block">
                <h3>Optional cloud explanation</h3>
                <p className="cloud-disclosure">
                  {aiStatus?.configured
                    ? `If requested, the sender, subject, message text (up to 6,000 characters), URLs, authentication results, and rule findings will be sent to Google Gemini (${aiStatus.model}).`
                    : 'Gemini is not configured. Set GEMINI_API_KEY in backend/.env and restart the API to enable this optional feature.'}
                </p>
                <label className="consent-row">
                  <input
                    type="checkbox"
                    checked={consentToCloud}
                    onChange={(event) => setConsentToCloud(event.target.checked)}
                    disabled={!aiStatus?.configured || loading}
                  />
                  <span>I consent to send this email content to Google Gemini for an explanation.</span>
                </label>
                <button
                  className="secondary"
                  onClick={() => void requestGeminiExplanation()}
                  disabled={!aiStatus?.configured || !consentToCloud || loading}
                >
                  {loading ? 'Requesting explanation…' : 'Explain with Gemini'}
                </button>
                {geminiExplanation && (
                  <div className="gemini-result">
                    <div className="row">
                      <strong>{geminiExplanation.suspected_threat}</strong>
                      <span className="badge ok">{geminiExplanation.provider} · {geminiExplanation.model}</span>
                    </div>
                    <p>{geminiExplanation.summary}</p>
                    <h4>Evidence references (matched against extracted findings)</h4>
                    <ul>{geminiExplanation.evidence_references.map((item) => <li key={item}>{item}</li>)}</ul>
                    <h4>Suggested actions</h4>
                    <ul>{geminiExplanation.recommended_actions.map((item) => <li key={item}>{item}</li>)}</ul>
                    <h4>Uncertainties</h4>
                    <ul>{geminiExplanation.uncertainties.map((item) => <li key={item}>{item}</li>)}</ul>
                    <small>The deterministic risk score was not changed by this model output.</small>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="empty-investigation">
              <p>Upload an email to inspect the risk signals, headers, links, attachments, and original-file digest.</p>
              {selectedEmail && <p className="muted">Select this message again after its upload to reload the report.</p>}
            </div>
          )}
        </section>
      </div>
      <footer className="footer">PhishTrace is a local prototype. Findings need analyst review and do not establish attacker identity.</footer>
    </main>
  );
}

function riskTone(category?: string): 'ok' | 'warn' | 'critical' {
  if (category === 'Critical' || category === 'High') return 'critical';
  if (category === 'Guarded') return 'warn';
  return 'ok';
}

function Card({ title, value, accent = 'ok' }: { title: string; value: string; accent?: 'ok' | 'warn' | 'critical' }) {
  return (
    <div className="card metric-card">
      <div className="metric-label">{title}</div>
      <div className={`metric-value ${accent === 'critical' ? 'metric-critical' : ''}`}>{value}</div>
    </div>
  );
}

export default App;
