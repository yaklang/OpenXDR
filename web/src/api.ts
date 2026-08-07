export interface Verdict {
  verdict?: 'malicious' | 'suspicious' | 'benign'
  confidence?: number
  summary?: string
  kill_chain?: string[]
  actions?: string[]
  error?: string
  raw?: string
}

export interface GraphNode {
  id: string
  type: 'asset' | 'process' | 'alert' | string
  label: string
}

export interface GraphEdge {
  from: string
  to: string
  rel: string
}

export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  overflow: number
}

export interface IncidentSummary {
  id: string
  createdAt: string
  status: string
  title: string | null
  aiVerdict: Verdict | null
  alertCount: number
}

export interface AlertRow {
  id: string
  ts: string
  lastTs: string | null
  count: number
  severity: number
  ruleId: string
  ruleTitle: string | null
  event: unknown
}

export interface IncidentDetail extends Omit<IncidentSummary, 'alertCount'> {
  graph: Graph
  assetId: string | null
  alerts: AlertRow[]
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json()
}

export const fetchIncidents = () => get<IncidentSummary[]>('/api/incidents')

export const fetchIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`)

export async function setIncidentStatus(id: string, status: string): Promise<void> {
  const r = await fetch(`/api/incidents/${id}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
}

export interface CommandRow {
  id: string
  createdAt: string
  kind: string
  status: string
  dryRun: boolean
  assetId: string
  incidentId: string | null
  issuedBy: string
  detail: string | null
  completedAt: string | null
}

export const fetchCommands = (incidentId: string) =>
  get<CommandRow[]>(`/api/commands?incidentId=${incidentId}`)

export async function issueCommand(body: {
  kind: string
  assetId: string
  incidentId?: string
  pid?: number
  dryRun: boolean
}): Promise<CommandRow> {
  const r = await fetch('/api/commands', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export interface Suppression {
  id: string
  createdAt: string
  ruleId: string
  ruleTitle: string | null
  assetId: string | null
  reason: string | null
  createdBy: string
  expiresAt: string | null
  matchedCount: number
  lastMatchedAt: string | null
}

export const fetchSuppressions = () => get<Suppression[]>('/api/suppressions')

export async function createSuppression(body: {
  ruleId: string
  assetId?: string | null
  reason?: string
  expiresInDays?: number
}): Promise<Suppression> {
  const r = await fetch('/api/suppressions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteSuppression(id: string): Promise<void> {
  const r = await fetch(`/api/suppressions/${id}`, { method: 'DELETE' })
  if (!r.ok) throw new Error(await r.text())
}
