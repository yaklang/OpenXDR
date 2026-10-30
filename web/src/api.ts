export interface RecordEvidence {
  id: string
  facts: { event_id: string; asset_id?: string; ts?: string; process_guid?: string; parent_process_guid?: string }
}

export interface QueryEvidence {
  records?: RecordEvidence[]
  id: string
  tool: string
  facts: { status?: string; returned?: number; truncated?: boolean; missing_ancestor?: boolean; raw_truncated_records?: number; dns_omitted_records?: number; baseline_status?: string; baseline_id?: string; baseline_path?: string; exe_path?: string; baseline_first_recorded_at?: string; collection_status?: string; collection_received_at?: string; collection_states?: Record<string, string> }
}

export interface Verdict {
  evidence_observations?: { evidence_id: string; field: string; text: string }[]
  query_evidence?: QueryEvidence[]
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
  // 告警主机所在组，逐行判断能否处置
  groupId: string | null
  // 结案：谁、何时、为什么
  resolution: string | null
  resolvedBy: string | null
  resolvedAt: string | null
  // AI 的结案建议：人一键采纳（结案仍记在人名下）或忽略
  closureProposal: ClosureProposal | null
  // 研判节奏：上次研判时刻与累计次数；retriage 为 pending（研判后又有新证据，冷却到期重研判）或 urgent（升级类，立即重研判）
  triagedAt: string | null
  triageCount: number
  triageStartedAt?: string
  retriage?: 'pending' | 'urgent'
  // 研判连续失败次数与下次重试时刻
  triageFailures?: number
  triageRetryAt?: string
}

export interface ClosureProposal {
  status: 'closed' | 'false_positive'
  note: string
  sessionId: string
  reportId?: string
  at: string
}

export interface AlertRow {
  id: string
  ts: string
  lastTs: string | null
  count: number
  severity: number
  ruleId: string
  ruleTitle: string | null
  // 规则作者：社区规则（DRL 1.1）要求命中展示时保留
  ruleAuthor?: string
  event: unknown
  // 合成检测（心跳等）的依据
  detail?: string
  // 来自运维自动化（进得了 incident 的只有高危例外）
  automation?: AutomationRef
}

// 告警或事件标注的运维自动化；watch 为高危例外（仍进研判）
export interface AutomationRef {
  id: string
  name: string
  watch: boolean
}

export interface IncidentDetail extends Omit<IncidentSummary, 'alertCount'> {
  graph: Graph
  assetId: string | null
  alerts: AlertRow[]
}

// 会话失效时抛出，App 捕获后切回登录页
export class Unauthorized extends Error {}
export const SESSION_EXPIRED = 'openxdr:session-expired'

// 接口报错：保留状态码与后端给的说明，界面按状态码选文案（见 components/format errText）
export class HttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function check(r: Response) {
  if (r.status === 401) {
    window.dispatchEvent(new Event(SESSION_EXPIRED))
    throw new Unauthorized()
  }
}

async function fail(r: Response): Promise<never> {
  throw new HttpError(r.status, (await r.text()).trim() || r.statusText)
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url)
  check(r)
  if (!r.ok) await fail(r)
  return r.json()
}

// 列表接口：后端会截断（limit），总数走 X-Total-Count、截断走 X-Truncated，界面据此提示而不是假装看全了
export interface Page<T> {
  items: T[]
  total?: number
  truncated: boolean
}

async function list<T>(url: string): Promise<Page<T>> {
  const r = await fetch(url)
  check(r)
  if (!r.ok) await fail(r)
  const total = r.headers.get('X-Total-Count')
  return { items: await r.json(), total: total === null ? undefined : Number(total), truncated: r.headers.get('X-Truncated') === '1' }
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
  if (!r.ok) await fail(r)
  return r.json()
}

export const logout = () => send('POST', '/api/logout')

// status 可取 unresolved（open + triaged，未人工结案）、review（未结案里需要人复核的）；按 offset/limit 翻页，total 是筛选后的总数
export const fetchIncidents = (params: { status?: string; assetId?: string; limit?: number; offset?: number } = {}) => {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.assetId) qs.set('assetId', params.assetId)
  qs.set('limit', String(params.limit ?? 50))
  if (params.offset) qs.set('offset', String(params.offset))
  return list<IncidentSummary>(`/api/incidents?${qs}`)
}

export const fetchIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`)

// 结案（closed / false_positive）必须带结论备注，改回 open 不用
export const dismissClosureProposal = (id: string) => send('DELETE', `/api/incidents/${id}/closure-proposal`)

export async function setIncidentStatus(id: string, status: string, note?: string): Promise<void> {
  const r = await post(`/api/incidents/${id}/status`, { status, note })
  if (!r.ok) await fail(r)
}

// 按规则归并：未结案事件按主告警的规则 + 主机分组（情报命中按同一目标），只是视图，不合并 incident
export interface IncidentGroup {
  key: string
  ruleId: string
  ruleTitle: string | null
  assetId: string | null
  hostname: string | null
  count: number
  severity: number
  firstAt: string
  lastAt: string
  // AI 研判分布，none 为未研判
  verdicts: Partial<Record<'benign' | 'suspicious' | 'malicious' | 'none', number>>
  incidents: IncidentSummary[]
}

// status 只能是 review / unresolved；后端最多扫最近 2000 个事件，超出时 truncated
export const fetchIncidentGroups = (status: string) => list<IncidentGroup>(`/api/incidents/groups?status=${status}`)

// 批量结案上限，与后端一致
export const BATCH_RESOLVE_MAX = 200

// 批量结案：一个事务内整批成功或整批不动；含 AI 判恶意的按误报关须 confirmMalicious
export async function resolveIncidents(ids: string[], status: 'closed' | 'false_positive', note: string, confirmMalicious = false): Promise<number> {
  const r = await post('/api/incidents/batch-status', { ids, status, note, confirmMalicious })
  if (!r.ok) await fail(r)
  return (await r.json()).resolved
}

// 运维待办：巡检 AI 登记与复查；人标已处理或忽略（须写原因，忽略原因会告诉 AI）
export interface FindingRow {
  id: string
  groupId: string
  assetId: string
  hostname: string
  key: string
  title: string
  detail: string
  severity: 'info' | 'low' | 'medium' | 'high'
  status: 'open' | 'resolved' | 'ignored'
  firstSeen: string
  lastSeen: string
  sessionId: string | null
  resolvedAt: string | null
  resolvedBy: string | null
  note: string | null
}

export const fetchFindingsByID = (ids: string[]) => get<FindingRow[]>(`/api/findings?${new URLSearchParams({ ids: ids.join(',') })}`)
export const fetchFindingsPage = (params: { status?: string; assetId?: string; ids?: string; limit?: number; offset?: number } = {}) => {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) if (value !== undefined) query.set(key, String(value))
  return list<FindingRow>(`/api/findings?${query}`)
}
export const setFindingStatus = (id: string, status: string, note?: string) =>
  send('POST', `/api/findings/${id}/status`, { status, note })

// 报告是文件下载：拿到 blob 后用临时链接触发浏览器保存
export async function downloadReport(id: string, title: string | null): Promise<void> {
  const r = await fetch(`/api/incidents/${id}/report`)
  check(r)
  if (!r.ok) await fail(r)
  const url = URL.createObjectURL(await r.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `${(title ?? id).replace(/[/\\?%*:|"<>]/g, '-')}.md`
  a.click()
  URL.revokeObjectURL(url)
}

export interface CommandRow {
  id: string
  createdAt: string
  kind: string
  status: string
  assetId: string
  incidentId: string | null
  issuedBy: string
  detail: string | null
  completedAt: string | null
  cmd?: string
  stdout?: string
  stderr?: string
  exitCode?: number
  truncated?: boolean
  target?: string
  // 这条指令拉起的进程触发的检测（来源已知，不进事件）
  detections?: { ruleId: string; title?: string; author?: string; count: number }[]
}

export const fetchCommands = (filter: { incidentId?: string; assetId?: string }) =>
  get<CommandRow[]>(`/api/commands?${new URLSearchParams({ ...filter, view: 'summary' })}`)

export const fetchCommandsPage = (filter: { incidentId?: string; assetId?: string }, page: number, pageSize = 10) =>
  get<{ items: CommandRow[]; total: number }>(`/api/commands?${new URLSearchParams({ ...filter, view: 'summary', page: String(page), pageSize: String(pageSize) })}`)
export const fetchCommand = (id: string) => get<CommandRow>(`/api/commands/${id}`)

export async function issueCommand(body: {
  kind: string
  assetId: string
  incidentId?: string
  pid?: number
  // 封锁（IP、网段或域名）、隔离文件（绝对路径）、锁定账号（账号名）的目标
  target?: string
}): Promise<CommandRow> {
  const r = await post('/api/commands', body)
  if (!r.ok) await fail(r)
  return r.json()
}

export interface CommandVerificationInput {
  outcome: 'effective' | 'ineffective' | 'inconclusive'
  expected: string
  observed: string
  eventIds: string[]
}
export interface CommandVerification extends Omit<CommandVerificationInput, 'eventIds'> {
  id: string
  commandId: string
  groupId: string | null
  createdAt: string
  reviewer: string
  commandStatus: string
  evidence: { id: string; ts: string; source: string; classUid: number; raw?: unknown }[]
}
export const fetchCommandVerifications = (id: string) =>
  get<{ items: CommandVerification[]; truncated: boolean }>(`/api/commands/${id}/verifications`)
export const fetchCommandVerification = (id: string, verificationId: string) =>
  get<CommandVerification>(`/api/commands/${id}/verifications/${verificationId}`)
export async function recordCommandVerification(id: string, input: CommandVerificationInput): Promise<CommandVerification> {
  return (await send('POST', `/api/commands/${id}/verifications`, input)).json()
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
  // active 生效 / proposed AI 提议待组管理员批准 / rejected 已拒绝
  status: 'active' | 'proposed' | 'rejected'
  sessionId: string | null
  reviewedBy: string | null
  reviewedAt: string | null
  // 字段条件（AND）：只压字段对得上的命中；为空表示整条规则
  conditions: SuppressCondition[] | null
  // 误报统计草案（createdBy = fp-stats）的依据，其余为 null
  evidence: SuppressEvidence | null
}

export interface SuppressEvidence {
  // rule 整条规则（实体分散）/ entity 按实体收窄
  scope: 'rule' | 'entity'
  windowDays: number
  falsePositives: number
  truePositives: number
  pending: number
  ratioPercent: number
  // 不计入的：采纳 AI 结案建议、系统自动结案
  aiProposals: number
  autoClosed: number
  incidents: { id: string; title?: string; resolvedBy: string; resolvedAt: string; source?: string }[]
}

export interface SuppressCondition {
  field: string
  op: 'equals' | 'contains' | 'endswith'
  value: string
}

export const reviewSuppression = (id: string, decision: 'approve' | 'reject') =>
  send('POST', `/api/suppressions/${id}/review`, { decision })

// reason：agent 活性检测判定通道开着却持续收不到事件时给出（只跟着 degraded），文字由 agent 生成；
// rebuilds：本轮静默里已自动重建几次仍未恢复（只跟着 reason）；recoveries：静默后靠自动重建恢复的累计次数
export interface CollectorCapability { path: string; state: 'active' | 'degraded' | 'unavailable' | 'disabled' | 'unknown'; reason?: string; rebuilds?: number; recoveries?: number }
export interface CollectorHealthSnapshot {
  bootId: string; sequence: number; reportedUnixMs: number; receivedAt: string
  queueBytes: number; queueBatches: number; queueLimitBytes: number; droppedEvents: number; writeBlocked: boolean
  receipts?: { pending: number; incomplete: number }
  capabilities: Record<string, CollectorCapability>
}
export interface SensorHealthSnapshot {
  bootId: string; sequence: number; reportedUnixMs: number; receivedAt: string
  iface: string; backend: 'afpacket' | 'afxdp'; workers: number; workersAlive: number
  packets: number; flows: number; kernelDrops: number; queueDrops: number
  // 每秒包数、每分钟会话数，按上一次快照以来的增量算
  packetRate: number; flowRate: number
  capabilities: Record<string, CollectorCapability>
}
export interface Asset {
  id: string
  hostname: string
  os: string | null
  // 发行版与版本的显示名（如 Ubuntu 24.04.1 LTS、银河麒麟 V10）；agent 上线后为实测值
  osDisplay: string | null
  ipAddrs: string[] | null
  agentId: string | null
  firstSeen: string
  lastSeen: string
  groupId: string | null
  // 已发出失联通知的起始时刻，恢复后为 null
  silentSince: string | null
  agentVersion: string | null
  collectorHealth?: CollectorHealthSnapshot | null
  // 同机流量探针：版本、最近心跳与抓包状态，没有探针时为空
  sensorVersion?: string | null
  sensorSeen?: string | null
  sensorHealth?: SensorHealthSnapshot | null
}

export const fetchAssets = () => get<Asset[]>('/api/assets')

export interface TemporalGap {
  revision: string
  eventId: string
  assetId: string
  groupId: string
  reason: string
  candidateCountLowerBound: number
  windowFrom: string
  windowTo: string
  createdAt: string
}
export function fetchTemporalGaps(assetId: string, hours: number) {
  const to = new Date()
  const from = new Date(to.getTime() - hours * 3600000)
  const params = new URLSearchParams({ assetId, from: from.toISOString(), to: to.toISOString(), limit: '200' })
  return get<{ items: TemporalGap[]; truncated: boolean }>(`/api/temporal-gaps?${params}`)
}

// 告警命中时所用的时序规则版本：单事件告警或旧版本告警返回空列表
export interface TemporalRuleVersion { revision: string; createdAt: string; temporalRules: string[] }
export const fetchAlertTemporalRevisions = (alertId: string) =>
  get<{ items: TemporalRuleVersion[] }>(`/api/temporal-rule-snapshots?${new URLSearchParams({ alertId })}`)

export interface ArchivedTemporalRule {
  id: string
  title: string
  author?: string
  kind: 'event_count' | 'sequence' | 'temporal'
  groupBy: 'asset' | 'account'
  severity: number
  windowSeconds: number
  threshold?: number
  minAssets: number
  references: string[]
  source: string
  base: Record<string, string>
}
export const fetchArchivedTemporalRule = (revision: string, rule: string) =>
  get<{ revision: string; createdAt: string; rules: ArchivedTemporalRule[] }>(`/api/temporal-rule-snapshots/${encodeURIComponent(revision)}?${new URLSearchParams({ rule })}`)

export interface DirectorySource {
  id: string
  groupId: string
  kind: string
  authority: string
  lastStartedAt: string | null
  lastFinishedAt: string | null
  latestRunId: string | null
  latestStatus: string | null
  latestErrorCode: string | null
  latestStartedAt: string | null
  latestFinishedAt: string | null
}
export interface DirectoryAccount {
  windowsSid: string | null
  id: string
  sourceId: string
  externalId: string
  username: string
  enabled: boolean | null
  observedAt: string
}
export interface DirectoryRun {
  id: string
  sourceId: string
  startedAt: string
  finishedAt: string | null
  status: string
  errorCode: string
  accountCount: number
}
export const fetchDirectories = (groupId: string) => get<{ items: DirectorySource[]; truncated: boolean }>(`/api/identity-directories?${new URLSearchParams({ groupId, limit: '200' })}`)
export const fetchDirectoryAccounts = (sourceId: string, after = '') => get<{ items: DirectoryAccount[]; truncated: boolean; next: string | null }>(`/api/identity-directories/${encodeURIComponent(sourceId)}/accounts?${new URLSearchParams({ limit: '25', ...(after ? { after } : {}) })}`)
export const fetchDirectoryRuns = (sourceId: string) => get<{ items: DirectoryRun[]; truncated: boolean }>(`/api/identity-directories/${encodeURIComponent(sourceId)}/runs?limit=200`)

export interface IdentityObservation {
  eventId: string
  assetId: string
  groupId: string | null
  ts: string
  sid: string | null
  name: string | null
  domain: string | null
  logonId: string | null
  success: boolean | null
  state: string
  detail: string
}

export interface IdentityDirectoryCandidate {
  accountId: string
  sourceId: string
  authority: string
  username: string
  sid: string
  enabled: boolean | null
  observedAt: string
  lastSuccessfulSync: string | null
  seenInLatestSync: boolean
}
export const fetchIdentityCandidates = (eventId: string) => get<{ items: IdentityDirectoryCandidate[]; truncated: boolean; ambiguous: boolean }>(`/api/identity-observations/${encodeURIComponent(eventId)}/directory-accounts`)

export function fetchIdentityObservations(assetId: string, hours: number) {
  const to = new Date()
  const from = new Date(to.getTime() - hours * 3600000)
  const params = new URLSearchParams({ assetId, from: from.toISOString(), to: to.toISOString(), limit: '200' })
  return get<{ items: IdentityObservation[]; truncated: boolean }>(`/api/identity-observations?${params}`)
}

// 全局身份图：目录账号为锚点，强证据自动链接，其余人工确认
export interface LoginStat {
  success: number
  failure: number
  last: string | null
  sources: string[]
}
export interface IdentitySummary {
  id: string
  groupId: string
  kind: 'directory' | 'host'
  anchorKind: AccountKind
  name: string | null
  sid: string | null
  uid: number | null
  assetId: string | null
  hostname: string | null
  authority: string | null
  createdAt: string
  accounts: number
  hosts: number
  lastSeen: string | null
  manual: boolean
  // 系统账号（UID 在系统范围且没登录过），只在列表里给
  system?: boolean
}
export type AccountKind = 'directory' | 'windows' | 'linux'
export type LinkBasis = 'directory_anchor' | 'ad_sid' | 'host_local' | 'manual'
export interface IdentityAccount {
  id: string
  kind: AccountKind
  name: string | null
  domain: string | null
  sid: string | null
  uid: number | null
  assetId: string | null
  hostname: string | null
  authority: string | null
  firstSeen: string
  lastSeen: string
  linkId: string | null
  identityId: string | null
  basis: LinkBasis | null
  confidence: string | null
  evidence: Record<string, unknown> | null
  source: string | null
  linkedAt: string | null
  logins: LoginStat | null
}
export interface IdentityLinkHistory {
  id: string
  accountId: string
  accountKind: AccountKind
  accountName: string | null
  assetId: string | null
  basis: LinkBasis
  confidence: string
  evidence: Record<string, unknown>
  source: string
  createdAt: string
  revokedAt: string | null
  revokedBy: string | null
  revokeReason: string | null
}
export interface IdentityMergeCandidate {
  account: IdentityAccount
  fromIdentityId: string
  toIdentityId: string
  toName: string | null
  toKind: 'directory' | 'host'
  toHostname: string | null
  matchedAccountId: string
  matchedName: string | null
  matchedKind: AccountKind
  reason: 'same_name' | 'similar_name' | 'sid_ambiguous'
  direction: 'incoming' | 'outgoing'
  rejectionId: string | null
}
export interface UnmatchedLogin {
  name: string
  state: 'no_account' | 'no_snapshot' | 'snapshot_unavailable'
  success: number
  failure: number
  last: string
  sources: string[]
}
export const fetchIdentities = (groupId: string, q: string, kind: string, offset: number, includeSystem = false) =>
  get<{ items: IdentitySummary[]; truncated: boolean }>(`/api/identities?${new URLSearchParams({ groupId, q, kind, offset: String(offset), limit: '100', includeSystem: String(includeSystem) })}`)
export const fetchIdentity = (id: string, hours: number) =>
  get<{ identity: IdentitySummary; accounts: IdentityAccount[]; truncated: boolean; history: IdentityLinkHistory[] }>(`/api/identities/${encodeURIComponent(id)}?hours=${hours}`)
export const fetchIdentityMergeCandidates = (id: string) =>
  get<{ items: IdentityMergeCandidate[]; truncated: boolean }>(`/api/identities/${encodeURIComponent(id)}/candidates`)
export const confirmIdentityLink = async (identityId: string, accountId: string) => { await send('POST', `/api/identities/${encodeURIComponent(identityId)}/links`, { accountId }) }
export const rejectIdentityCandidate = async (identityId: string, accountId: string) => { await send('POST', `/api/identities/${encodeURIComponent(identityId)}/rejections`, { accountId }) }
export const revokeIdentityLink = async (linkId: string) => { await send('DELETE', `/api/identity-links/${encodeURIComponent(linkId)}`) }
export const revokeIdentityRejection = async (id: string) => { await send('DELETE', `/api/identity-rejections/${encodeURIComponent(id)}`) }
export const fetchAssetIdentityAccounts = (assetId: string, hours: number) =>
  get<{ accounts: IdentityAccount[]; unmatched: UnmatchedLogin[]; pending: number; truncated: boolean }>(`/api/assets/${encodeURIComponent(assetId)}/identity-accounts?hours=${hours}`)

export const fetchSuppressions = () => get<Suppression[]>('/api/suppressions')

// 运维自动化：运维脚本、AI 运维插件这类日常自动化的 SSH 登录身份。平台自动识别（origin=auto），
// 组管理员也可以手工添加；它们的告警保留可查，但不进事件与研判
export interface AutomationEvidence {
  windowDays: number
  days: number
  logins: number
  hosts: number
  addresses: string[]
  lastLogin: string
  humanBenign: number
  aiBenign: number
  alerts: number
  checkedAt: string
}

export interface TrustedSource {
  id: string
  createdAt: string
  groupId: string
  name: string
  reason: string | null
  createdBy: string
  expiresAt: string
  keyFingerprint: string | null
  sourceCidr: string | null
  loginUser: string | null
  matchedCount: number
  lastMatchedAt: string | null
  revokedAt: string | null
  revokedBy: string | null
  origin: 'auto' | 'manual'
  pinned: boolean
  evidence: AutomationEvidence | null
  // verdict：它的告警被判属实、恶意或可疑，系统停用
  revokeCause: string | null
  revokeIncidentId: string | null
}

// 组内近期 SSH 登录，按登录身份归并，说明为什么（没）被自动识别
export type CandidateReason = 'eligible' | 'no_key' | 'public' | 'scattered' | 'flagged' | 'irregular' | 'quiet' | 'pending'
  | 'few_verdicts' | 'covered' | 'declined' | 'disabled'
export interface TrustedCandidate {
  user: string
  addresses: string[]
  keyType: string | null
  keyFingerprint: string | null
  logins: number
  days: number
  hosts: number
  lastSeen: string
  alerts: number
  humanBenign: number
  aiBenign: number
  pending: number
  reason: CandidateReason
  trustedSourceIds: string[]
}

export const fetchTrustedSources = (groupId: string) => get<TrustedSource[]>(`/api/trusted-sources?groupId=${encodeURIComponent(groupId)}`)
export const fetchTrustedCandidates = (groupId: string) => get<TrustedCandidate[]>(`/api/trusted-sources/candidates?groupId=${encodeURIComponent(groupId)}`)
export async function createTrustedSource(body: {
  groupId: string
  name: string
  reason?: string
  keyFingerprint?: string
  sourceCidr?: string
  loginUser?: string
  expiresInDays: number
}): Promise<TrustedSource> {
  return (await send('POST', '/api/trusted-sources', body)).json()
}
export const updateTrustedSource = (id: string, body: {
  name?: string
  reason?: string
  expiresInDays?: number
  pinned?: boolean
  enabled?: boolean
}) => send('PATCH', `/api/trusted-sources/${encodeURIComponent(id)}`, body)
export const deleteTrustedSource = (id: string) => send('DELETE', `/api/trusted-sources/${encodeURIComponent(id)}`)

export async function createSuppression(body: {
  ruleId: string
  assetId?: string | null
  reason?: string
  expiresInDays?: number
  conditions?: SuppressCondition[]
}): Promise<Suppression> {
  const r = await post('/api/suppressions', body)
  if (!r.ok) await fail(r)
  return r.json()
}

export async function deleteSuppression(id: string): Promise<void> {
  const r = await fetch(`/api/suppressions/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
}

export interface Stats {
  events24h: number
  alerts24h: number
  openIncidents: number
  // 未结案里需要人看的：AI 非良性，或良性但高危及以上（与通知策略同一口径）
  reviewIncidents: number
  incidentsByStatus: Record<string, number>
  alertTrend: { hour: string; count: number }[]
  topRules: { ruleId: string; ruleTitle: string | null; ruleAuthor?: string; count: number }[]
  alertsBySeverity: Record<string, number>
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
  // 这条事件的告警来自已知自动化
  automation?: AutomationRef
}

// /api/events 的响应契约：items 是事件行，truncated 表示返回条数达到 limit（可能还有更早的），
// coverage 说明冷热两层的覆盖缺口（reason 非空 = 有缺口，与 scan_complete=false 同义）
export interface EventCoverage {
  hot_searched: boolean
  cold_searched: boolean
  scan_complete: boolean
  reason: '' | 'hot_keyword_degraded' | 'keyword_not_searched' | 'no_archive_schema' | 'scan_incomplete' | 'before_archive'
}

export interface EventsResult {
  items: EventRow[]
  truncated: boolean
  coverage: EventCoverage
}

// 问 AI 的数据来源边界：candidates_hot_only 恒为 true（关联候选只查热表，热目标的历史
// 关联也可能已归档）；target_from_archive 表示目标事件本身来自冷层（热表已无此行）
export interface EventAIArchive {
  target_from_archive: boolean
  candidates_hot_only: boolean
}

// 问 AI：related 是查库得出的确定关联（父进程链、同一进程、子进程、同一连接、同一远端、前后同主机）；
// explain 是模型读这条日志与候选后的解读，挑出的相关日志只会来自候选
export type Relation = 'ancestor' | 'process' | 'child' | 'connection' | 'peer' | 'nearby'
export interface RelatedGroup { relation: Relation; events: EventRow[] }
export interface RelatedEvents { groups: RelatedGroup[]; archive?: EventAIArchive }
export interface EventExplanation {
  verdict: 'benign' | 'suspicious' | 'malicious' | 'unknown'
  title: string; summary: string; points: string[]; next: string[]
  related: { id: string; why: string }[]
  // 候选边界说明（candidates_hot_only=true 表示候选未覆盖冷层，热目标也会带）
  archive?: EventAIArchive
}
export const fetchRelatedEvents = (id: string) => get<RelatedEvents>(`/api/events/${id}/related`)
// 后台 AI 任务：发起后立即返回，结果在服务端，前端轮询；换页、刷新都能接着看
export interface AIJob<T> { id?: string; status: 'none' | 'running' | 'done' | 'failed'; result?: T; error?: string; createdAt?: string; finishedAt?: string }
export const fetchExplain = (id: string, lang: string) => get<AIJob<EventExplanation>>(`/api/events/${id}/explain?lang=${lang}`)
export const startExplain = async (id: string, lang: string, refresh = false): Promise<AIJob<EventExplanation>> =>
  (await send('POST', `/api/events/${id}/explain?lang=${lang}${refresh ? '&refresh=1' : ''}`)).json()

export const searchEvents = async (params: {
  assetId?: string
  q?: string
  source?: string
  classUid?: number
  hours?: number
  // 给了精确时间窗就不看 hours（事件详情跳"日志上下文"用）
  from?: string
  to?: string
}) => {
  // /api/events 是对象契约 {items, truncated, coverage}：条数截断与覆盖缺口都在响应体里，
  // X-Truncated / X-Archive-Coverage 头只是调试摘要，前端不读
  const qs = new URLSearchParams()
  if (params.q) qs.set('q', params.q)
  if (params.assetId) qs.set('assetId', params.assetId)
  if (params.source) qs.set('source', params.source)
  if (params.classUid) qs.set('classUid', String(params.classUid))
  if (params.from) {
    qs.set('from', params.from)
    if (params.to) qs.set('to', params.to)
  } else if (params.hours)
    qs.set('from', new Date(Date.now() - params.hours * 3_600_000).toISOString())
  qs.set('limit', '200')
  const r = await fetch(`/api/events?${qs}`)
  check(r)
  if (!r.ok) await fail(r)
  return r.json() as Promise<EventsResult>
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

export interface RuleRow {
  kind?: 'event_count' | 'sequence' | 'temporal'
  windowSeconds?: number
  threshold?: number
  references?: string[]
  id: string
  title: string
  author?: string
  severity: number
  classUid: number
  product: string
  signal?: boolean
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

// 情报订阅：内置公开源的开关与同步状态，以及命中过的订阅情报
export interface IntelFeed {
  id: string
  name: string
  url: string
  severity: number
  enabled: boolean
  count: number
  hits: number
  syncedAt: string | null
  attemptedAt?: string | null
  error?: string
}
export interface IntelFeeds {
  feeds: IntelFeed[]
  hits: IntelRow[]
  intervalHours: number
}
export const fetchIntelFeeds = () => get<IntelFeeds>('/api/intel/feeds')
export const saveIntelFeeds = async (enabled: string[]): Promise<IntelFeeds> =>
  (await send('PUT', '/api/intel/feeds', { enabled })).json()
export const syncIntelFeeds = async (): Promise<IntelFeeds> => (await send('POST', '/api/intel/feeds/sync')).json()

export async function importIntel(body: {
  text: string
  source?: string
  severity?: number
  expiresInDays?: number
}): Promise<{ imported: number; skipped: number }> {
  const r = await post('/api/intel/import', body)
  if (!r.ok) await fail(r)
  return r.json()
}

export async function deleteIntel(id: string): Promise<void> {
  const r = await fetch(`/api/intel/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
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
  if (!r.ok) await fail(r)
  return r.json()
}

export async function deleteUser(id: string): Promise<void> {
  const r = await fetch(`/api/users/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
}

export async function resetUserPassword(id: string, password: string): Promise<void> {
  const r = await post(`/api/users/${id}/password`, { password })
  if (!r.ok) await fail(r)
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

// 关键词在后端匹配（用户、动作、对象、详情），最多返回最近 500 条
export const fetchAudit = (q?: string) => list<AuditRow>(`/api/audit${q ? `?q=${encodeURIComponent(q)}` : ''}`)

// 资产组：组是纳管与授权单位，role 为当前用户在组内的有效角色
export interface GroupRow {
  id: string
  createdAt: string
  name: string
  role: 'admin' | 'analyst' | 'viewer'
  assetCount: number
}

export interface MemberRow {
  userId: string
  username: string
  role: string
}

async function send(method: string, url: string, body?: unknown): Promise<Response> {
  const r = await fetch(url, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  check(r)
  if (!r.ok) await fail(r)
  return r
}

export interface MemoryRow {
  id: string
  groupId: string
  assetId: string | null
  hostname?: string
  content: string
  source: 'ai' | 'human'
  author: string
  sessionId: string | null
  createdAt: string
  updatedAt: string
}

// 组内长期记忆：AI 在会话里记下的环境知识，人可以补充、改正、删除
export const fetchMemories = () => get<MemoryRow[]>('/api/memories')
export const createMemory = (body: { groupId: string; assetId?: string; content: string }) => send('POST', '/api/memories', body)
export const updateMemory = (id: string, content: string) => send('PATCH', `/api/memories/${id}`, { content })
export const deleteMemory = (id: string) => send('DELETE', `/api/memories/${id}`)

// 安装初始化：管理员同意用户协议、走完（或跳过）首次引导
export interface SetupState {
  agreementVersion: string
  accepted: boolean
  acceptedBy: string
  acceptedAt: string | null
  onboarded: boolean
}
export const fetchSetup = () => get<SetupState>('/api/setup')
export const acceptAgreement = (version: string) => send('POST', '/api/setup/agreement', { version })
export const finishOnboarding = (skipped: string[]) => send('POST', '/api/setup/onboarded', { skipped })

export const fetchGroups = () => get<GroupRow[]>('/api/groups')
export const createGroup = async (name: string): Promise<GroupRow> =>
  (await send('POST', '/api/groups', { name })).json()
export const deleteGroup = (id: string) => send('DELETE', `/api/groups/${id}`)
export const fetchMembers = (groupId: string) => get<MemberRow[]>(`/api/groups/${groupId}/members`)
export const setMember = (groupId: string, userId: string, role: string) =>
  send('PUT', `/api/groups/${groupId}/members/${userId}`, { role })
export const removeMember = (groupId: string, userId: string) =>
  send('DELETE', `/api/groups/${groupId}/members/${userId}`)
// 通知配置：控制台保存的为准，未保存过时后端返回环境变量默认值
export interface NotifySettings {
  url: string
  format: 'generic' | 'dingtalk' | 'feishu' | 'wecom'
  linkBase: string
  minSeverity: number
}
export const fetchNotifySettings = () => get<NotifySettings>('/api/settings/notify')
export const saveNotifySettings = (s: NotifySettings) => send('PUT', '/api/settings/notify', s)
export const testNotifySettings = (s: NotifySettings) => send('POST', '/api/settings/notify/test', s)

// AI 与外部情报配置：密钥只回是否已设与末四位；source 标明每项来自控制台还是环境变量
export interface AISettings {
  baseUrl: string; model: string; piModel: string; ptr: boolean; vtAlertMin: number
  apiKeySet: boolean; apiKeyHint?: string; vtKeySet: boolean; vtKeyHint?: string; abuseCHKeySet: boolean; abuseCHKeyHint?: string
  source: Record<string, 'console' | 'env'>
  canSaveSecrets: boolean
}
// 只发改动的项；密钥传空串表示清空；reset 里的项回到环境变量
export interface AISettingsPatch {
  baseUrl?: string; model?: string; piModel?: string; ptr?: boolean; vtAlertMin?: number; apiKey?: string; vtKey?: string; abuseCHKey?: string; reset?: string[]
}
export const fetchAISettings = () => get<AISettings>('/api/settings/ai')
export const saveAISettings = async (p: AISettingsPatch): Promise<AISettings> => (await send('PUT', '/api/settings/ai', p)).json()
export const testAISettings = async (p: AISettingsPatch & { target: 'model' | 'piModel' | 'vt' }): Promise<{ ms: number; reply: string }> =>
  (await send('POST', '/api/settings/ai/test', p)).json()

// AI 用量：按天、用途、模型聚合；用途 chat AI 助手 / task 定时任务 / triage 事件研判 / annotate 资产标注
export interface AIUsageRow { day: string; feature: 'chat' | 'task' | 'triage' | 'annotate' | 'explain'; model: string; input: number; output: number; cacheRead: number; calls: number }
export interface AIUsageTop { id: string; title: string; kind: string; group: string; model: string; tokens: number; calls: number; lastAt: string }
// 研判准确度：只有人写理由的结案算独立判断，采纳 AI 与自动结案只计数
export interface AccuracyCounts { reviewed: number; aiBenign: number; missed: number; aiAlarm: number; falseAlarm: number; adopted: number; auto: number }
export interface AccuracyRow extends AccuracyCounts { key: string; title?: string }
export interface AccuracyCase { id: string; title: string; verdict: string; model: string; status: string; resolvedBy: string; resolvedAt: string }
export const fetchAIAccuracy = (days: number) =>
  get<{ days: number; total: AccuracyCounts; byModel: AccuracyRow[] | null; byRule: AccuracyRow[] | null; missed: AccuracyCase[] | null; falseAlarms: AccuracyCase[] | null }>(`/api/settings/ai/accuracy?days=${days}`)

export const fetchAIUsage = (days: number) =>
  get<{ rows: AIUsageRow[]; top: AIUsageTop[] }>(`/api/settings/ai/usage?days=${days}&tz=${encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone)}`)

// 主机接入：令牌按组签发，明文只在创建时返回一次
export interface EnrollStatus {
  enabled: boolean
  reason: string
  platforms: string[]
  // 流量探针：只看 sensor 安装包，与 agent 分开判断
  sensorEnabled?: boolean
  sensorReason?: string
  sensorPlatforms?: string[] | null
}
// agent 令牌接端点 agent；sensor 令牌接流量探针，只有平台管理员能签
export type EnrollKind = 'agent' | 'sensor'
export interface EnrollToken {
  id: string
  groupId: string
  kind?: EnrollKind
  createdBy: string
  createdAt: string
  expiresAt: string
  revoked: boolean
  uses: number
  token?: string
}
export const fetchEnrollStatus = () => get<EnrollStatus>('/api/enroll-tokens/status')
export const fetchEnrollTokens = (groupId: string) => get<EnrollToken[]>(`/api/enroll-tokens?groupId=${groupId}`)
export const createEnrollToken = async (groupId: string, days: number, kind: EnrollKind = 'agent'): Promise<EnrollToken> =>
  (await send('POST', '/api/enroll-tokens', { groupId, days, kind })).json()
export const revokeEnrollToken = (id: string) => send('DELETE', `/api/enroll-tokens/${id}`)

export const assignAsset = (groupId: string, assetId: string) =>
  send('PUT', `/api/groups/${groupId}/assets/${assetId}`)
export const unassignAsset = (groupId: string, assetId: string) =>
  send('DELETE', `/api/groups/${groupId}/assets/${assetId}`)

// Pi 会话。后端直接返回 ent 实体，字段是 snake_case
export interface AgentSession {
  id: string
  created_at: string
  kind: 'chat' | 'task'
  group_id: string
  initiator: string
  model: string
  title?: string
  status: 'running' | 'idle' | 'succeeded' | 'failed'
  error?: string
  // 「交给 AI」绑定的对象：incident:<id> / finding:<id>
  subjects?: string[]
}

// Pi 原生消息，原样存库、原样回放
export type ContentPart =
  | { type: 'text'; text: string }
  | { type: 'thinking'; thinking: string }
  | { type: 'toolCall'; id: string; name: string; arguments: Record<string, unknown> }
  | { type: 'image' }

export type PiMessage =
  | { role: 'user'; content: string | ContentPart[] }
  | { role: 'assistant'; content: ContentPart[]; stopReason?: string; errorMessage?: string }
  | { role: 'toolResult'; toolCallId: string; toolName: string; content: ContentPart[]; isError: boolean }

export interface SessionMessage {
  id: string
  created_at: string
  seq: number
  role: string
  content: PiMessage
}

export const fetchAgentSessions = (groupId: string) =>
  get<AgentSession[]>(`/api/agent-sessions?groupId=${groupId}`)

// 列表只有最近 100 个，深链接必须按 id 直接取
export const fetchAgentSession = (id: string) => get<AgentSession>(`/api/agent-sessions/${id}`)

export const createAgentSession = async (body: {
  groupId: string
  title?: string
  subjects?: string[]
}): Promise<AgentSession> => (await send('POST', '/api/agent-sessions', body)).json()

export const fetchSessionMessages = (id: string, afterSeq = 0) =>
  get<SessionMessage[]>(`/api/agent-sessions/${id}/messages${afterSeq ? `?afterSeq=${afterSeq}` : ''}`)

// 发消息只是让后台开跑：会话切到 running 就返回，运行不随页面走；进度靠轮询会话与消息
export const startSessionMessage = (id: string, prompt: string) =>
  send('POST', `/api/agent-sessions/${id}/messages`, { prompt })

// 停止：写一条停止请求，后台运行所在节点几秒内收手，会话回到空闲可以接着问
export const cancelSession = (id: string) => send('POST', `/api/agent-sessions/${id}/cancel`)

// 审批与命令名单（组 admin）。实体字段 snake_case
export interface Approval {
  id: string
  created_at: string
  group_id: string
  session_id?: string
  asset_id: string
  requested_by: string
  origin: 'ai' | 'human'
  cmd: string
  timeout_ms: number
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled' | 'consumed'
  expires_at: string
  decided_by?: string
  decided_at?: string
}

export interface CommandPolicy {
  id: string
  created_at: string
  group_id: string
  origin: 'ai' | 'human'
  mode: 'allow' | 'deny'
  pattern: string
}

export const fetchApprovals = (groupId: string) => get<Approval[]>(`/api/approvals?groupId=${groupId}`)
export const decideApproval = (id: string, approve: boolean) =>
  send('POST', `/api/approvals/${id}/decision`, { approve })
export const fetchPolicies = (groupId: string) =>
  get<CommandPolicy[]>(`/api/command-policies?groupId=${groupId}`)
export const createPolicy = (groupId: string, origin: 'ai' | 'human', pattern: string) =>
  send('POST', '/api/command-policies', { groupId, origin, pattern })
export const deletePolicy = (id: string) => send('DELETE', `/api/command-policies/${id}`)

// Pi 报告：库里只有 Markdown，HTML / PDF 由后端按需渲染
export interface AgentReport {
  id: string
  created_at: string
  session_id: string
  group_id: string
  title: string
  markdown: string
  // ok 无需处理（只存档不推送）/ attention 有需要人处理的事项 / urgent 需要立即处理
  level: 'ok' | 'attention' | 'urgent'
  // 一句话结论；旧报告为空
  summary?: string
  // 当前用户是否看过：打开预览、HTML 或 PDF 都算
  read?: boolean
}

export const fetchAgentReports = (groupId: string) =>
  get<AgentReport[]>(`/api/agent-reports?groupId=${groupId}`)
export const reportHtmlUrl = (id: string) => `/api/agent-reports/${id}/html`

export async function markReportRead(id: string): Promise<void> {
  const r = await post(`/api/agent-reports/${id}/read`)
  if (!r.ok) await fail(r)
}

export async function markAllReportsRead(groupId: string): Promise<void> {
  const r = await post(`/api/agent-reports/read?groupId=${groupId}`)
  if (!r.ok) await fail(r)
}

// 走 fetch 而不是直接跳转：没装 Chromium 时后端回 503，要能在界面上报错
export async function downloadAgentPdf(r: AgentReport): Promise<void> {
  const resp = await fetch(`/api/agent-reports/${r.id}/pdf`)
  check(resp)
  if (!resp.ok) await fail(resp)
  const url = URL.createObjectURL(await resp.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `${r.title.replace(/[/\\?%*:|"<>]/g, '-')}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

// 预设任务：定义在仓库 YAML，界面只能启停与改周期（admin）
export type TaskCategory = 'ops' | 'security' | 'report' | ''
export interface TaskRow {
  id: string
  name: string
  nameEn: string
  description: string
  descriptionEn: string
  category: TaskCategory
  schedule: string
  customSchedule: string | null
  // 全局默认：没有单独设置的组跟它走
  enabled: boolean
  // 按组开关：组 ID → 是否运行，只含自己看得到的组
  groupEnabled: Record<string, boolean>
  model: string
  targetGroup: string
  prompt: string
  // 每个看得到且启用的组下一次开跑时间（含按组错峰偏移）
  nextRuns: Record<string, string>
  // nextRuns 里最早的一个；没有启用的组时为空
  nextRun: string | null
}

export interface TaskRunRow {
  reportId: string | null
  reportTitle: string | null
  // 这一轮做了多少步（工具调用次数）
  steps: number
  id: string
  taskId: string
  groupId: string
  sessionId: string | null
  startedAt: string
  finishedAt: string | null
  // interrupted：被停机打断，接手的调度器稍后重跑；skipped：并发上限已满、排队超过一个周期没轮到
  status: 'running' | 'succeeded' | 'failed' | 'interrupted' | 'skipped'
  error: string | null
  // 模型没在时限内交报告，报告是平台整理的保底报告（status 仍为 succeeded）
  partial: boolean
}

export const fetchTasks = () => get<TaskRow[]>('/api/tasks')
export const updateTask = async (
  id: string,
  body: { enabled?: boolean; customSchedule?: string },
): Promise<TaskRow> => (await send('PATCH', `/api/tasks/${id}`, body)).json()
export const fetchTaskRuns = (id: string) => get<TaskRunRow[]>(`/api/tasks/${id}/runs`)
// 立即运行只是记下请求，调度器下一次检查（默认 30 秒内）拉起
export const runTask = (id: string) => send('POST', `/api/tasks/${id}/run`)
// 任务在某个组上的开关；null 恢复跟随全局默认
export const setTaskGroup = (id: string, groupId: string, enabled: boolean | null) => send('PUT', `/api/tasks/${id}/groups/${groupId}`, { enabled })

// 采集配置：随 Register 下发给 agent；字段缺省表示用 agent 内置默认
export interface AgentConfig {
  fileWatchDirs?: string[]
  collectFiles?: boolean
  collectAuth?: boolean
  collectPersist?: boolean
  collectNetwork?: boolean
  collectInventory?: boolean
  collapsePeriodic?: boolean
}

export const fetchAgentConfig = (assetId: string) => get<AgentConfig>(`/api/assets/${assetId}/config`)
export const saveAgentConfig = async (assetId: string, cfg: AgentConfig): Promise<AgentConfig> =>
  (await send('PUT', `/api/assets/${assetId}/config`, cfg)).json()

export interface ImportedHost {
  hostname: string; address: string; os: string; osDisplay?: string; port: number; username: string
  kind: 'none' | 'password' | 'private_key'; hostKey: string
}
export interface ReviewedHost extends ImportedHost { credentialToken?: string; images?: number[]; lines: number[]; needsReview: boolean; issues: string[]; reviewId?: string }
export interface HostImportPreview { hosts: ReviewedHost[] }
export interface HostCredential extends ImportedHost { id: string; assetId: string }
export const fetchHostImportStatus = () => get<{ credentialStorage: boolean; sshEnrollment: boolean; aiParsing: boolean }>('/api/host-import/status')
export const fetchHostCredentials = (groupId: string) => get<HostCredential[]>(`/api/host-import/credentials?groupId=${encodeURIComponent(groupId)}`)
export async function startHostImport(groupId: string, document: string, images: HostDocumentImage[] = []): Promise<AIJob<HostImportPreview>> {
  const r = await post('/api/host-import/analyze', { groupId, document, images })
  if (!r.ok) await fail(r)
  return r.json()
}
export const fetchHostImportJob = (groupId: string) => get<AIJob<HostImportPreview>>(`/api/host-import/analyze?groupId=${encodeURIComponent(groupId)}`)
export const discardHostImportJob = (groupId: string) => send('DELETE', `/api/host-import/analyze?groupId=${encodeURIComponent(groupId)}`)
export async function commitHostImport(groupId: string, hosts: ReviewedHost[]): Promise<{ assetIds: string[] }> {
  const r = await post('/api/host-import/confirm', { groupId, hosts, confirmed: true })
  if (!r.ok) await fail(r)
  return r.json()
}
export async function enrollHostCredential(id: string, fingerprint: string): Promise<{ status: string; message: string }> {
  const r = await post(`/api/host-import/credentials/${id}/enroll`, { fingerprint })
  if (!r.ok) await fail(r)
  return r.json()
}
export async function deleteHostCredential(id: string): Promise<void> {
  const r = await fetch(`/api/host-import/credentials/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
}

// 资产图谱与攻击面。区域 name 为空表示自动划分，按 kind 显示内置名称；云上自动划分时 name 是云厂商
export type ZoneKind = 'internal' | 'dmz' | 'external' | 'cloud'
export type ExposureLevel = 'internet' | 'dmz' | 'internal'
export interface ZoneRef { id?: string; name: string; kind: ZoneKind; source: 'manual' | 'cidr' | 'cloud' | 'auto' }
export interface ZoneRow { id: string; group_id: string; name: string; kind: ZoneKind; cidrs?: string[] }

export interface MapNode {
  id: string
  kind: 'asset' | 'discovered' | 'managed' | 'internet'
  label: string
  zone: ZoneRef
  exposure?: ExposureLevel
  role?: string
  criticality?: number
  os?: string
  online?: boolean
  listening?: number
  ports?: string[]
}
// 公网目的地址：按地址合并的外联明细，带反向解析、离线归属库、VirusTotal 信息与 AI 给的用途
export interface PeerStat {
  count: number
  lastSeen: string
}

export interface PublicDest {
  ip: string; ports: string[]; processes?: string[]; count: number; lastSeen: string
  ptr?: string; owner?: string; asn?: number; country?: string; malicious?: number; suspicious?: number; domains?: string[]; checked?: boolean; purpose?: string
  // 归属里用到了离线库（DB-IP Lite）的数据：按 CC BY 4.0 要署名
  ipdb?: boolean
  // 上机调查或人工给的结论，优先于 AI 推断的 purpose
  note?: ServiceNote
}
export interface MapEdge {
  from: string; to: string; ports: string[]; processes: string[]; count: number; lastSeen: string; note?: string; targets?: PublicDest[]
}
export interface AssetMap { nodes: MapNode[]; edges: MapEdge[] }

export interface PortService { name: string; category: string; risk: 'high' | 'medium' | 'low' }
export interface ExposedService {
  assetId: string; hostname: string; zone: ZoneRef; level: ExposureLevel; proto: string; addrs: string[]; port: number
  process?: string; service: PortService; criticality?: number; score: number; peers: string[] | null; peerCount: number; fromPublic: boolean
  note?: ServiceNote
  // 服务进程所属的包，用来对上这台资产的漏洞
  package?: string
}
// 服务说明：端口表认不出时靠它命名；来源优先级 human > investigation > ai
export interface ServiceNote { name: string; note?: string; risk?: 'high' | 'medium' | 'low'; source: 'ai' | 'investigation' | 'human'; by?: string; at: string }
export interface SurfacePeer { id: string; label: string; kind: 'asset' | 'discovered' | 'managed' | 'internet'; zone: ZoneRef }
export interface SurfacePath { from: string; assetId: string; service: string; count: number }
export interface BlindSpot { ip: string; zone: ZoneRef; ports: string[]; accessed: string[]; seenBy: string[]; count: number; lastSeen: string }
export interface AttackSurface {
  summary: { internet: number; dmz: number; internal: number; high: number; blind: number; noInventory: string[] }
  exposures: ExposedService[]
  blind: BlindSpot[]
  peers: SurfacePeer[]
  paths: SurfacePath[]
}

export interface Listener { proto: string; addr: string; port: number; pid?: number; process?: string; path?: string }
export interface CloudInfo { provider: string; instanceId: string; region?: string; publicIp?: string }
export interface AssetProfile {
  zone: ZoneRef
  exposure: ExposureLevel
  cloud?: CloudInfo | null
  listening: Listener[] | null
  inventoryAt?: string | null
  services?: Record<string, ServiceNote> | null
  outbound: string[] | null
  inbound: string[] | null
  // 按对端合计的连接次数与最近一次时间，键与 outbound / inbound 里的对端一致
  outboundStats?: Record<string, PeerStat> | null
  inboundStats?: Record<string, PeerStat> | null
  publicDestinations: number
  public?: PublicDest[] | null
  role?: string | null
  summary?: string | null
  criticality?: number | null
  reason?: string | null
  relationNotes?: Record<string, string> | null
  lockedFields?: string[] | null
  annotatedAt?: string | null
  annotateRequestedAt?: string | null
  aiEnabled: boolean
}
export type ProfileEdit = { role?: string; summary?: string; criticality?: number; unlock?: string[] }

export const fetchAssetMap = (groupId: string) => get<AssetMap>(`/api/asset-map?groupId=${groupId}`)
// 软件漏洞：按源码包归组，可升级修复与暂无修复分开
export interface VulnItem { id: string; aliases?: string[]; summary?: string; score: number; vector?: string; fixed?: string }
export interface VulnPackage { source: string; version: string; binaries: string[]; exposed: boolean; maxScore: number; fixedIn?: string; vulns: VulnItem[] }
export interface VulnReport {
  ecosystem: string; packages: number; fixable: VulnPackage[] | null; unfixed: VulnPackage[] | null
  softwareAt: string | null; sync: { at: string; records: number; error?: string } | null
}
export interface VulnSummary {
  assetId: string; fixable: number; high: number; exposed: number; unfixed: number; maxScore: number
  exposedPackages: { source: string; binaries: string[]; maxScore: number; vulns: number; fixedIn?: string }[] | null
}
export const fetchAssetVulns = (assetId: string) => get<VulnReport | null>(`/api/assets/${assetId}/vulns`)
export const fetchVulnSummary = () => get<VulnSummary[]>('/api/vulns/summary')

export const fetchAttackSurface = (groupId: string) => get<AttackSurface>(`/api/attack-surface?groupId=${groupId}`)
export const fetchZones = (groupId: string) => get<ZoneRow[]>(`/api/zones?groupId=${groupId}`)
export const createZone = async (z: { groupId: string; name: string; kind: ZoneKind; cidrs: string[] }) => { await send('POST', '/api/zones', z) }
export const updateZone = async (id: string, z: { name: string; kind: ZoneKind; cidrs: string[] }) => { await send('PUT', `/api/zones/${id}`, z) }
export const deleteZone = async (id: string) => { await send('DELETE', `/api/zones/${id}`) }
export const fetchAssetProfile = (id: string) => get<AssetProfile>(`/api/assets/${id}/profile`)
export const saveAssetProfile = async (id: string, edit: ProfileEdit) => { await send('PUT', `/api/assets/${id}/profile`, edit) }
export const assignAssetZone = async (id: string, zoneId: string | null) => { await send('PUT', `/api/assets/${id}/zone`, { zoneId }) }
export const saveServiceNote = async (id: string, body: { port: string; name: string; note?: string; risk?: string }) => {
  await send('PUT', `/api/assets/${id}/services`, body)
}
export const requestAnnotate = async (id: string) => { await send('POST', `/api/assets/${id}/annotate`) }

export interface LocalAccountSnapshot {
  eventId: string
  assetId: string
  groupId: string | null
  ts: string
  state: string
  source: string
  accountCount: number | null
}
export interface LocalAccount {
  name: string
  uid: number
  gid: number
  shell: string
}
export function fetchLocalAccountSnapshots(assetId: string, hours: number) {
  const to = new Date()
  const params = new URLSearchParams({ assetId, from: new Date(to.getTime() - hours * 3600000).toISOString(), to: to.toISOString(), limit: '200' })
  return get<{ items: LocalAccountSnapshot[]; truncated: boolean }>(`/api/local-account-snapshots?${params}`)
}
export const fetchLocalAccountSnapshot = (eventId: string) => get<LocalAccountSnapshot & { items: LocalAccount[] | null }>(`/api/local-account-snapshots/${encodeURIComponent(eventId)}`)

export interface LocalIdentityCandidate extends LocalAccount {
  eventId: string
  observedAt: string
}
export const fetchLocalIdentityCandidates = (eventId: string) => get<{ items: LocalIdentityCandidate[]; truncated: boolean }>(`/api/identity-observations/${encodeURIComponent(eventId)}/local-accounts`)
export interface HostDocumentImage { name: string; dataUrl: string }
export async function extractHostDocument(groupId: string, file: File): Promise<{ document: string; images: HostDocumentImage[] | null }> {
  const body = new FormData()
  body.append('groupId', groupId)
  body.append('file', file)
  const r = await fetch('/api/host-import/extract', { method: 'POST', body })
  check(r)
  if (!r.ok) await fail(r)
  return await r.json()
}

export type DecoyKind = 'ssh' | 'http' | 'file' | 'shell'
export interface DecoyProfile {
  kind: DecoyKind
  id: string
  name: string
  layer: string
  template: string
  evidence: string
}
export const fetchDecoyInstallStatus = () => get<{ enabled: boolean }>('/api/decoy-install/status')
export const installDecoy = (id: string, body: { fingerprint: string; arch: string; listenHost: string; fileRoot?: string }) => send('POST', `/api/decoy-install/${encodeURIComponent(id)}`, body)
export interface DecoyDeployment {
  runtime_pending?: number | null
  runtime_error?: string
  hosted?: boolean
  active_revision_id?: string | null
  stop_requested?: boolean
  remote_installable: boolean
  install_state: 'idle' | 'installing' | 'installed' | 'unconfirmed'
  install_started_at?: string
  runtime_status?: 'unreported' | 'starting' | 'running' | 'stopped' | 'failed' | 'stale' | 'stopping'
  runtime_seen_at?: string
  kind: DecoyKind
  resource: string
  id: string
  asset_id: string
  profile: string
  template: string
  port: number
  status: 'registered' | 'revoked'
  created_at: string
  created_by: string
  revoked_at?: string
  revoked_by?: string
}
export const fetchDecoyProfiles = () => get<DecoyProfile[]>('/api/decoy-profiles')
export const fetchDecoys = (groupId: string, offset: number) => get<{ items: DecoyDeployment[]; more: boolean }>(`/api/decoys?groupId=${encodeURIComponent(groupId)}&offset=${offset}`)
export const registerDecoy = (body: { assetId: string; profile: string; port: number; kind: DecoyKind; resource: string }) => send('POST', '/api/decoys', body)
export const revokeDecoy = (id: string) => send('POST', `/api/decoys/${encodeURIComponent(id)}/revoke`)

export async function issueDecoyToken(id: string): Promise<{ token: string; expiresAt: string }> {
  return (await send('POST', `/api/decoys/${encodeURIComponent(id)}/token`)).json()
}
export interface DecoyObservation { id: string; kind: string; received_at: string; occurred_at?: string | null; session_id?: string; revision_id?: string | null; incident_id?: string | null }
export const fetchDecoyObservations = (id: string) => get<{ items: DecoyObservation[]; more: boolean }>(`/api/decoys/${encodeURIComponent(id)}/observations`)

export async function reviewDecoyObservation(id: string, observation: string): Promise<{ incidentId: string }> {
  return (await send('POST', `/api/decoys/${encodeURIComponent(id)}/observations/${encodeURIComponent(observation)}/review`)).json()
}

export interface DeceptionReleaseInput { engine: 'native' | 'dygk'; version: string; digest: string; protocol: number; stateSchema: string }
export interface DeceptionRelease { id: string; engine: 'native' | 'dygk'; version: string; digest: string; protocol: number; state_schema: string; enabled: boolean }
export interface DeceptionConfig { hosted?: boolean; attachment: 'standalone' | 'gateway'; mode: 'observe' | 'block' | 'quarantine'; origin: string; upstream?: string; prefix: string; trustedProxies?: string[]; entries: number; branches: number; depth: number; maxNodes: number; requestLimit: number }
export interface DeceptionRevision { id: string; number: number; release_id: string; spec: DeceptionConfig; created_at: string }
export const fetchDeceptionReleases = () => get<DeceptionRelease[]>('/api/deception/releases')
export const fetchHostedDeceptionRelease = () => get<DeceptionRelease | null>('/api/deception/hosted-release')
export const admitDeceptionRelease = (body: DeceptionReleaseInput) => send('POST', '/api/deception/releases', body)
export const disableDeceptionRelease = (id: string) => send('POST', `/api/deception/releases/${encodeURIComponent(id)}/disable`)
export const fetchDeceptionRevisions = (id: string) => get<{ items: DeceptionRevision[]; more: boolean }>(`/api/decoys/${encodeURIComponent(id)}/revisions`)
export const selectDeceptionRevision = (id: string, body: { releaseId: string; config: DeceptionConfig; expectedRevision?: string | null }) => send('POST', `/api/decoys/${encodeURIComponent(id)}/revisions`, body)
export const stopDeceptionRuntime = (id: string) => send('POST', `/api/decoys/${encodeURIComponent(id)}/stop`)

export async function downloadAssets(format: 'csv' | 'json', selection: { mode: 'filter'; q: string; groupId: string } | { mode: 'ids'; ids: string[] }): Promise<void> {
  const r = await fetch('/api/assets/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ format, selection }) })
  check(r)
  if (!r.ok) await fail(r)
  const url = URL.createObjectURL(await r.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = r.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1] ?? `openxdr-assets.${format}`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export interface IntegrationInput {
  name: string; purpose: string; ownerId: string; enabled: boolean; scopes: string[]; groupIds: string[]
  resolutionEnabled?: boolean; allowedResolutions?: string[]; allowMaliciousFalsePositive?: boolean
}
export interface IntegrationRow extends IntegrationInput { id: string; permissionVersion: number; createdAt: string }
export interface IntegrationTokenRow {
  id: string; prefix: string; scopes: string[]; createdAt: string; expiresAt: string; revoked: boolean
  lastUsedAt: string | null; lastRemoteAddr: string; token?: string
}
export const fetchIntegrations = () => get<IntegrationRow[]>('/api/system-integrations')
export const saveIntegration = (body: IntegrationInput, id?: string) => send(id ? 'PUT' : 'POST', `/api/system-integrations${id ? `/${id}` : ''}`, body)
export const fetchIntegrationTokens = (id: string) => get<IntegrationTokenRow[]>(`/api/system-integrations/${id}/tokens`)
export const issueIntegrationToken = async (id: string, days: number, scopes: string[]): Promise<IntegrationTokenRow> =>
  (await send('POST', `/api/system-integrations/${id}/tokens`, { days, scopes })).json()
export const revokeIntegrationToken = (id: string, tokenId: string) => send('DELETE', `/api/system-integrations/${id}/tokens/${tokenId}`)
export interface OutboundAllow { entries: string[]; locked: boolean }
export const fetchOutboundAllow = () => get<OutboundAllow>('/api/system-integrations/outbound-allow')
export const saveOutboundAllow = async (entries: string[]): Promise<OutboundAllow> =>
  (await send('PUT', '/api/system-integrations/outbound-allow', { entries })).json()

export interface IntegrationSubscription {
  id: string; name: string; url: string; groupIds: string[]; kinds: string[]; enabled: boolean; version: number; keyId: string; secret?: string
}
export type SubscriptionInput = Pick<IntegrationSubscription, 'name' | 'url' | 'groupIds' | 'kinds' | 'enabled'> & { movePending?: boolean }
export interface IntegrationDelivery {
  id: string; subscriptionId: string; eventId: string; status: string; attempts: number; createdAt: string; nextAt: string; lastError: string; targetUrl: string; targetVersion: number; completedAt: string | null
}
const subscriptionPath = (id: string) => `/api/system-integrations/${id}/subscriptions`
export const fetchIntegrationSubscriptions = (id: string) => get<IntegrationSubscription[]>(subscriptionPath(id))
export const saveIntegrationSubscription = async (id: string, body: SubscriptionInput, subscriptionId?: string): Promise<IntegrationSubscription> =>
  (await send(subscriptionId ? 'PUT' : 'POST', `${subscriptionPath(id)}${subscriptionId ? `/${subscriptionId}` : ''}`, body)).json()
export const rotateIntegrationSecret = async (id: string, sid: string): Promise<IntegrationSubscription> => (await send('POST', `${subscriptionPath(id)}/${sid}/rotate`)).json()
export const testIntegrationSubscription = (id: string, sid: string) => send('POST', `${subscriptionPath(id)}/${sid}/test`)
export const deleteIntegrationSubscription = (id: string, sid: string) => send('DELETE', `${subscriptionPath(id)}/${sid}`)
export interface DeliveryFilters { status?: string; subscriptionId?: string; from?: string; to?: string; offset?: string }
export interface DeliveryPage { items: IntegrationDelivery[]; truncated: boolean; total: number; summary: { counts: Record<string, number>; oldestPendingAt: string | null } }
export const fetchIntegrationDeliveries = (id: string, filters: DeliveryFilters = {}) => get<DeliveryPage>(`/api/system-integrations/${id}/deliveries?${new URLSearchParams({ ...filters, limit: '50' })}`)
export interface DeliveryAttempt { startedAt: string; endedAt: string; httpStatus: number; result: string; leaseGeneration: number }
export const fetchIntegrationAttempts = (id: string, did: string) => get<DeliveryAttempt[]>(`/api/system-integrations/${id}/deliveries/${did}/attempts`)
export const retryIntegrationDelivery = (id: string, did: string) => send('POST', `/api/system-integrations/${id}/deliveries/${did}/retry`)
export interface ExternalTicket { id: string; integrationId: string; incidentId: string; externalId: string; title: string; status: string; url: string; updatedAt: string }
export const fetchIncidentTickets = (id: string) => get<ExternalTicket[]>(`/api/incidents/${id}/tickets`)

export const fetchHostedDeceptionStatus = () => get<{ online: boolean; seenAt: string | null }>('/api/deception/hosted-status')

export interface TriageRun {
  heartbeat_valid: boolean
  id: string
  started_at: string
  ready_at?: string
  finished_at?: string
  trigger: 'initial' | 'reopened' | 'urgent' | 'evidence'
  status: 'running' | 'succeeded' | 'failed' | 'interrupted'
  model: string
  error_code: string
  duration_ms?: number
  model_ms?: number
  tool_ms?: number
  model_calls?: number
  tool_calls?: number
  tool_errors?: number
  tool_details?: { tool: string; duration_ms: number; failed: boolean; returned?: number; truncated?: boolean }[]
  input_tokens?: number
  output_tokens?: number
}
export const fetchTriageRuns = (id: string, page: number) => get<{ items: TriageRun[]; more: boolean }>(`/api/incidents/${id}/triage-runs?page=${page}`)
