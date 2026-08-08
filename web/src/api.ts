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
  severity: number
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

// 会话失效时抛出，App 捕获后切回登录页
export class Unauthorized extends Error {}

function check(r: Response) {
  if (r.status === 401) throw new Unauthorized()
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url)
  check(r)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json()
}

async function post(url: string, body?: unknown): Promise<Response> {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  check(r)
  return r
}

export interface Me {
  username: string
  role: 'admin' | 'analyst' | 'viewer'
}

export const fetchMe = () => get<Me>('/api/me')

export async function login(username: string, password: string): Promise<Me> {
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export const logout = () => post('/api/logout')

export const fetchIncidents = (status?: string) =>
  get<IncidentSummary[]>(status ? `/api/incidents?status=${status}` : '/api/incidents')

export const fetchIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`)

export async function setIncidentStatus(id: string, status: string): Promise<void> {
  const r = await post(`/api/incidents/${id}/status`, { status })
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
  const r = await post('/api/commands', body)
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

export interface Asset {
  id: string
  hostname: string
  os: string | null
  ipAddrs: string[] | null
  agentId: string | null
  firstSeen: string
  lastSeen: string
}

export const fetchAssets = () => get<Asset[]>('/api/assets')

export const fetchSuppressions = () => get<Suppression[]>('/api/suppressions')

export async function createSuppression(body: {
  ruleId: string
  assetId?: string | null
  reason?: string
  expiresInDays?: number
}): Promise<Suppression> {
  const r = await post('/api/suppressions', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteSuppression(id: string): Promise<void> {
  const r = await fetch(`/api/suppressions/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}

export interface Stats {
  events24h: number
  alerts24h: number
  openIncidents: number
  incidentsByStatus: Record<string, number>
  alertTrend: { hour: string; count: number }[]
  topRules: { ruleId: string; ruleTitle: string | null; count: number }[]
  assetsTotal: number
  assetsOnline: number
}

export const fetchStats = () => get<Stats>('/api/stats')

export interface EventRow {
  id: string
  ts: string
  classUid: number
  source: string
  assetId: string | null
  username: string | null
  connTuple: string | null
  raw: unknown
}

export const searchEvents = (params: {
  q?: string
  source?: string
  classUid?: number
  hours?: number
}) => {
  const qs = new URLSearchParams()
  if (params.q) qs.set('q', params.q)
  if (params.source) qs.set('source', params.source)
  if (params.classUid) qs.set('classUid', String(params.classUid))
  if (params.hours)
    qs.set('from', new Date(Date.now() - params.hours * 3_600_000).toISOString())
  qs.set('limit', '200')
  return get<EventRow[]>(`/api/events?${qs}`)
}

export interface AttackCoverage {
  tactics: {
    tactic: string
    rules: number
    techniques: { id: string; rules: number; hasData: boolean }[] | null
  }[]
  untagged: number
  noDataSource: number
}

export const fetchAttack = () => get<AttackCoverage>('/api/attack')

export interface HuntStep {
  tool: string
  args: string
}

export async function hunt(question: string): Promise<{ answer: string; steps: HuntStep[] | null }> {
  const r = await post('/api/hunt', { question })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export interface RuleRow {
  id: string
  title: string
  severity: number
  classUid: number
  product: string
  ingested: boolean
  source: string
}

export const fetchRules = () => get<RuleRow[]>('/api/rules')

export interface IntelRow {
  id: string
  createdAt: string
  kind: 'ip' | 'domain' | 'hash'
  value: string
  source: string
  severity: number
  note: string | null
  expiresAt: string | null
  matchedCount: number
  lastMatchedAt: string | null
}

export const fetchIntel = () => get<IntelRow[]>('/api/intel')

export async function importIntel(body: {
  text: string
  source?: string
  severity?: number
  expiresInDays?: number
}): Promise<{ imported: number; skipped: number }> {
  const r = await post('/api/intel/import', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteIntel(id: string): Promise<void> {
  const r = await fetch(`/api/intel/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}

export interface UserRow {
  id: string
  createdAt: string
  username: string
  role: string
}

export const fetchUsers = () => get<UserRow[]>('/api/users')

export async function createUser(body: {
  username: string
  password: string
  role: string
}): Promise<UserRow> {
  const r = await post('/api/users', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteUser(id: string): Promise<void> {
  const r = await fetch(`/api/users/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}

export async function resetUserPassword(id: string, password: string): Promise<void> {
  const r = await post(`/api/users/${id}/password`, { password })
  if (!r.ok) throw new Error(await r.text())
}

export interface AuditRow {
  id: string
  ts: string
  username: string
  action: string
  target: string | null
  detail: string | null
  remoteAddr: string
}

export const fetchAudit = () => get<AuditRow[]>('/api/audit')
