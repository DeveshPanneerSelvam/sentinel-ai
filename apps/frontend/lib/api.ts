export type Alert = {
  id: number;
  title: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  risk_score: number;
  mitre_technique_id: string;
  mitre_technique_name: string;
  explanation: string;
  event_time: string | null;
  entities: Record<string, unknown>;
  evidence: Record<string, unknown>;
  source_file: string;
  created_at: string;
  notes: Array<{ id: number; body: string; created_at: string }>;
};

export type UploadResult = {
  parsed_events: number;
  alerts_created: number;
  alerts: Alert[];
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export async function register(email: string, password: string): Promise<string> {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email, password})
  });
  return tokenFromResponse(response);
}

export async function login(email: string, password: string): Promise<string> {
  const body = new URLSearchParams({username: email, password});
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body
  });
  return tokenFromResponse(response);
}

export async function uploadLogs(file: File, token: string): Promise<UploadResult> {
  const form = new FormData();
  form.append("file", file);
  const response = await fetch(`${API_BASE_URL}/logs/upload`, {
    method: "POST",
    headers: {Authorization: `Bearer ${token}`},
    body: form
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export async function getAlerts(token: string): Promise<Alert[]> {
  const response = await fetch(`${API_BASE_URL}/alerts`, {
    headers: {Authorization: `Bearer ${token}`}
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export async function addNote(alertId: number, body: string, token: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/alerts/${alertId}/notes`, {
    method: "POST",
    headers: {"Content-Type": "application/json", Authorization: `Bearer ${token}`},
    body: JSON.stringify({body})
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
}

export async function downloadIncidentReport(alertId: number, token: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/reports/${alertId}/pdf`, {
    headers: {Authorization: `Bearer ${token}`}
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `incident-${alertId}.pdf`;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function tokenFromResponse(response: Response): Promise<string> {
  if (!response.ok) {
    throw new Error(await response.text());
  }
  const payload = (await response.json()) as { access_token: string };
  return payload.access_token;
}
