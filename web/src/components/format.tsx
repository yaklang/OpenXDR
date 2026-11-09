import { LoadingOutlined } from '@ant-design/icons'
import { Badge, Tag, Tooltip } from 'antd'
import { HttpError, type Asset } from '../api'
import { useI18n, type MsgKey } from '../i18n'

const pad = (n: number) => String(n).padStart(2, '0')

// 统一 YYYY-MM-DD HH:mm:ss（本地时区），不随浏览器语言变成 10/16/2026, 12:39 PM
export const fmtTime = (iso: string | null | undefined) => {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

const SEV: Record<number, { key: MsgKey; color: string }> = {
  1: { key: 'sev1', color: 'default' },
  2: { key: 'sev2', color: 'blue' },
  3: { key: 'sev3', color: 'gold' },
  4: { key: 'sev4', color: 'orange' },
  5: { key: 'sev5', color: 'red' },
}

export function SeverityTag({ value }: { value: number }) {
  const { t } = useI18n()
  const s = SEV[value]
  return s ? <Tag color={s.color}>{t(s.key)}</Tag> : <Tag>{value}</Tag>
}

const INCIDENT_STATUS: Record<string, { key: MsgKey; color: string }> = {
  open: { key: 'statusOpen', color: 'orange' },
  triaged: { key: 'statusTriaged', color: 'blue' },
  closed: { key: 'statusClosed', color: 'default' },
  false_positive: { key: 'statusFalsePositive', color: 'green' },
}

// 已研判之后又并入新证据：结论还没看过它们，状态旁另挂一个标
const RETRIAGE: Record<string, { key: MsgKey; hint: MsgKey; color: string }> = {
  pending: { key: 'retriagePending', hint: 'retriagePendingHint', color: 'cyan' },
  urgent: { key: 'retriageUrgent', hint: 'retriageUrgentHint', color: 'volcano' },
}

export function IncidentStatusTag({ value, retriage, triageStartedAt }: { value: string; retriage?: string; triageStartedAt?: string }) {
  const { t } = useI18n()
  const s = INCIDENT_STATUS[value]
  const r = retriage ? RETRIAGE[retriage] : undefined
  return (
    <>
      <Tag color={s?.color}>{s ? t(s.key) : value}</Tag>
      {triageStartedAt && <Tooltip title={t('triageStartedDetail', { at: fmtTime(triageStartedAt) })}><Tag color="processing" icon={<LoadingOutlined spin />}>{t('triageRunning')}</Tag></Tooltip>}
      {!triageStartedAt && r && <Tooltip title={t(r.hint)}><Tag color={r.color}>{t(r.key)}</Tag></Tooltip>}
    </>
  )
}

export const INCIDENT_STATUSES = Object.keys(INCIDENT_STATUS)
export const incidentStatusKey = (s: string) => INCIDENT_STATUS[s]?.key

const SESSION_STATUS: Record<string, { key: MsgKey; color: string }> = {
  running: { key: 'sessionRunning', color: 'processing' },
  idle: { key: 'sessionIdle', color: 'default' },
  succeeded: { key: 'sessionSucceeded', color: 'success' },
  failed: { key: 'sessionFailed', color: 'error' },
  // 只出现在定时任务运行记录上：并发上限已满、排队超过一个周期没轮到
  skipped: { key: 'sessionSkipped', color: 'warning' },
}

export function SessionStatusTag({ value }: { value: string }) {
  const { t } = useI18n()
  const s = SESSION_STATUS[value]
  return <Tag color={s?.color}>{s ? t(s.key) : value}</Tag>
}

export const ROLE_KEY: Record<string, MsgKey> = { admin: 'roleAdmin', analyst: 'roleAnalyst', viewer: 'roleViewer' }

export const CLASS_KEY: Record<number, MsgKey> = {
  1001: 'classFile',
  1005: 'classModule',
  1007: 'classProcess',
  2004: 'classDetection',
  3002: 'classAuth',
  201002: 'classRegistry',
  4001: 'classNetwork',
  4003: 'classDNS',
  100001: 'classLog',
}

// 报错转成给人看的话：权限、不存在、服务端故障用统一文案，参数类错误保留后端说明（它最具体）
export function errText(e: unknown, t: (k: MsgKey) => string): string {
  if (e instanceof HttpError) {
    if (e.status === 403) return t('err403')
    if (e.status === 404) return t('err404')
    if (e.status >= 500) return t('errServer')
    return e.message
  }
  if (e instanceof TypeError) return t('errNetwork')
  return e instanceof Error ? e.message : String(e)
}

// 主机状态：文档导入尚未纳管 / 已发失联通知 / 5 分钟内有心跳 / 心跳过期，三处页面共用一个口径
const STALE_MS = 5 * 60_000
export type HostState = 'imported' | 'silent' | 'online' | 'stale' | 'retired'
// 最近心跳：有 agent 看 agent；只有流量探针的主机看探针心跳
export const hostSeen = (a: Asset) => (!a.agentId && a.sensorSeen) || a.lastSeen

export function hostState(a: Asset): HostState {
  if (a.retiredAt) return 'retired'
  if (!a.agentId && !a.sensorSeen && Date.parse(a.lastSeen) === 0) return 'imported'
  if (a.silentSince) return 'silent'
  return Date.now() - Date.parse(hostSeen(a)) < STALE_MS ? 'online' : 'stale'
}

const HOST_STATE: Record<HostState, { key: MsgKey; status: 'default' | 'error' | 'success' | 'warning' }> = {
  imported: { key: 'hostNotEnrolled', status: 'default' },
  silent: { key: 'silent', status: 'error' },
  online: { key: 'online', status: 'success' },
  stale: { key: 'stale', status: 'warning' },
  retired: { key: 'hostRetired', status: 'default' },
}

export function HostStateBadge({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const s = HOST_STATE[hostState(asset)]
  const badge = <Badge status={s.status} text={t(s.key)} />
  if (asset.retiredAt) {
    return <Tooltip title={t('hostRetiredBy', { time: fmtTime(asset.retiredAt), who: asset.retiredBy ?? '-', reason: asset.retiredReason ?? '' })}>{badge}</Tooltip>
  }
  return asset.silentSince ? <Tooltip title={t('silentSince', { time: fmtTime(asset.silentSince) })}>{badge}</Tooltip> : badge
}

// 处置指令：动作与状态，处置面板与资产详情共用
const COMMAND_STATUS: Record<string, { key: MsgKey; color: string }> = {
  pending: { key: 'cmdPending', color: 'default' },
  sent: { key: 'cmdSent', color: 'processing' },
  succeeded: { key: 'cmdSucceeded', color: 'success' },
  failed: { key: 'cmdFailed', color: 'error' },
  unsupported: { key: 'cmdUnsupported', color: 'warning' },
  unknown: { key: 'cmdUnknown', color: 'warning' },
}

const COMMAND_KIND: Record<string, MsgKey> = {
  kill_process: 'killProcess',
  isolate_host: 'isolateHost',
  unisolate_host: 'unisolateHost',
  exec: 'execCommand',
  block_network: 'blockNetwork',
  unblock_network: 'unblockNetwork',
  quarantine_file: 'quarantineFile',
  restore_file: 'restoreFile',
  disable_account: 'disableAccount',
  enable_account: 'enableAccount',
  isolate_container: 'isolateContainer',
  unisolate_container: 'unisolateContainer',
  block_execution: 'blockExecution',
  unblock_execution: 'unblockExecution',
}

export const commandKind = (kind: string, t: (k: MsgKey) => string) => (COMMAND_KIND[kind] ? t(COMMAND_KIND[kind]) : kind)

export function CommandStatusTag({ value }: { value: string }) {
  const { t } = useI18n()
  const s = COMMAND_STATUS[value]
  return <Tag color={s?.color}>{s ? t(s.key) : value}</Tag>
}
