"use client";

import {useEffect, useMemo, useState} from "react";
import {AlertTriangle, Download, FileUp, KeyRound, LogIn, MessageSquarePlus, ShieldCheck} from "lucide-react";

import {addNote, Alert, downloadIncidentReport, getAlerts, login, register, uploadLogs} from "@/lib/api";

const severityRank: Record<Alert["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

export function Dashboard() {
  const [token, setToken] = useState<string>("");
  const [email, setEmail] = useState("analyst@example.com");
  const [password, setPassword] = useState("sentinel123");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [note, setNote] = useState("");
  const [status, setStatus] = useState("Sign in or create an analyst account to begin.");
  const [isBusy, setIsBusy] = useState(false);

  const selected = alerts.find((alert) => alert.id === selectedId) ?? alerts[0] ?? null;
  const sortedAlerts = useMemo(
    () => [...alerts].sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || b.risk_score - a.risk_score),
    [alerts]
  );

  useEffect(() => {
    if (alerts.length && selectedId === null) {
      setSelectedId(alerts[0].id);
    }
  }, [alerts, selectedId]);

  async function authenticate(mode: "login" | "register") {
    setIsBusy(true);
    try {
      const nextToken = mode === "login" ? await login(email, password) : await register(email, password);
      setToken(nextToken);
      setStatus("Authenticated. Upload a CSV log file to generate detections.");
      setAlerts(await getAlerts(nextToken));
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Authentication failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function handleUpload(file: File | null) {
    if (!file || !token) {
      setStatus("Authenticate first, then select a CSV file.");
      return;
    }
    setIsBusy(true);
    try {
      const result = await uploadLogs(file, token);
      setAlerts(result.alerts);
      setSelectedId(result.alerts[0]?.id ?? null);
      setStatus(`Parsed ${result.parsed_events} events and created ${result.alerts_created} alerts.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Upload failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function submitNote() {
    if (!selected || !note.trim() || !token) {
      return;
    }
    await addNote(selected.id, note.trim(), token);
    setNote("");
    setAlerts(await getAlerts(token));
    setStatus("Investigation note saved.");
  }

  async function exportReport(alert: Alert) {
    if (!token) {
      setStatus("Authenticate before exporting a report.");
      return;
    }
    try {
      await downloadIncidentReport(alert.id, token);
      setStatus("Incident report exported.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Report export failed.");
    }
  }

  return (
    <main className="shell">
      <section className="topbar">
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <h1>SentinelAI</h1>
            <p>ML threat detection and incident triage</p>
          </div>
        </div>
        <div className="auth">
          <input value={email} onChange={(event) => setEmail(event.target.value)} aria-label="Email" />
          <input
            value={password}
            type="password"
            onChange={(event) => setPassword(event.target.value)}
            aria-label="Password"
          />
          <button onClick={() => authenticate("login")} disabled={isBusy}>
            <LogIn size={16} /> Login
          </button>
          <button onClick={() => authenticate("register")} disabled={isBusy}>
            <KeyRound size={16} /> Register
          </button>
        </div>
      </section>

      <section className="toolbar">
        <label className="upload">
          <FileUp size={18} />
          Upload CSV
          <input type="file" accept=".csv,text/csv" onChange={(event) => handleUpload(event.target.files?.[0] ?? null)} />
        </label>
        <span>{status}</span>
      </section>

      <section className="metrics">
        <Metric label="Total alerts" value={alerts.length.toString()} />
        <Metric label="Critical/high" value={alerts.filter((alert) => ["critical", "high"].includes(alert.severity)).length.toString()} />
        <Metric label="MITRE mapped" value={alerts.filter((alert) => alert.mitre_technique_id).length.toString()} />
        <Metric label="Avg risk" value={alerts.length ? Math.round(alerts.reduce((sum, alert) => sum + alert.risk_score, 0) / alerts.length).toString() : "0"} />
      </section>

      <section className="workspace">
        <aside className="alertList" aria-label="Alerts">
          {sortedAlerts.map((alert) => (
            <button
              key={alert.id}
              className={selected?.id === alert.id ? "alertRow active" : "alertRow"}
              onClick={() => setSelectedId(alert.id)}
            >
              <span className={`severity ${alert.severity}`}>{alert.severity}</span>
              <strong>{alert.title}</strong>
              <small>{alert.mitre_technique_id} · Risk {alert.risk_score}</small>
            </button>
          ))}
          {!alerts.length && (
            <div className="empty">
              <AlertTriangle size={24} />
              <p>No alerts yet. Upload the sample CSV to run the detection engine.</p>
            </div>
          )}
        </aside>

        <section className="detail">
          {selected ? (
            <>
              <div className="detailHeader">
                <div>
                  <span className={`severity ${selected.severity}`}>{selected.severity}</span>
                  <h2>{selected.title}</h2>
                  <p>{selected.mitre_technique_id} · {selected.mitre_technique_name}</p>
                </div>
                <button className="download" onClick={() => exportReport(selected)}>
                  <Download size={16} /> PDF
                </button>
              </div>
              <div className="risk">
                <div style={{width: `${Math.min(100, selected.risk_score)}%`}} />
              </div>
              <p className="explanation">{selected.explanation}</p>
              <div className="grids">
                <JsonBlock title="Entities" value={selected.entities} />
                <JsonBlock title="Evidence" value={selected.evidence} />
              </div>
              <div className="timeline">
                <h3>Timeline</h3>
                <div>{selected.event_time ? new Date(selected.event_time).toLocaleString() : "No timestamp"}</div>
                <div>Ingested from {selected.source_file}</div>
                <div>Created {new Date(selected.created_at).toLocaleString()}</div>
              </div>
              <div className="notes">
                <h3>Investigation Notes</h3>
                {selected.notes.map((item) => (
                  <p key={item.id}>{item.body}</p>
                ))}
                <div className="noteEntry">
                  <input value={note} onChange={(event) => setNote(event.target.value)} placeholder="Add analyst note" />
                  <button onClick={submitNote}>
                    <MessageSquarePlus size={16} /> Save
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="empty large">
              <ShieldCheck size={42} />
              <p>Upload logs to populate the investigation workspace.</p>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

function Metric({label, value}: {label: string; value: string}) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function JsonBlock({title, value}: {title: string; value: Record<string, unknown>}) {
  return (
    <div className="jsonBlock">
      <h3>{title}</h3>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}
