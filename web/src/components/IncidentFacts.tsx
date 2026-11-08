import { Space, Tag, Tooltip, Typography } from 'antd'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import type { AlertRow, IncidentDetail } from '../api'
import { useI18n, type T } from '../i18n'
import { Ago, ago } from './Ago'
import { IncidentStatusTag, SeverityTag, fmtTime } from './format'

// 最近一条告警在这个时间内就算「仍在发生」
const ONGOING_MS = 15 * 60_000
const MAX_HOSTS = 4

type HostCount = { id: string | null; name: string; count: number }

function hostsOf(alerts: AlertRow[]): HostCount[] {
  const by = new Map<string, HostCount>()
  for (const a of alerts) {
    const key = a.assetId ?? a.hostname ?? ''
    if (!key) continue
    const h = by.get(key) ?? { id: a.assetId ?? null, name: a.hostname || (a.assetId ?? '').slice(-8), count: 0 }
    h.count += a.count || 1
    by.set(key, h)
  }
  return [...by.values()].sort((a, b) => b.count - a.count)
}

function span(alerts: AlertRow[]): { first?: string; last?: string } {
  let first: string | undefined, last: string | undefined
  for (const a of alerts) {
    const end = a.lastTs ?? a.ts
    if (!first || a.ts < first) first = a.ts
    if (!last || end > last) last = end
  }
  return { first, last }
}

function duration(ms: number, t: T): string {
  const m = Math.round(ms / 60_000)
  if (m < 1) return t('factDurationMoment')
  if (m < 60) return t('factDurationMin', { n: m })
  if (m < 60 * 24) return t('factDurationHour', { n: Math.round(m / 6) / 10 })
  return t('factDurationDay', { n: Math.round(m / 144) / 10 })
}

function Fact({ label, children, foot }: { label: string; children: ReactNode; foot?: ReactNode }) {
  return (
    <div className="incident-fact">
      <div className="incident-fact-label">{label}</div>
      <div className="incident-fact-value">{children}</div>
      {foot && <div className="incident-fact-foot">{foot}</div>}
    </div>
  )
}

// 事件最要紧的四件事放在最上面、用大字：涉及哪几台主机、什么时候发生（还在不在发生）、规模多大、现在谁在处理
export function IncidentFacts({ inc }: { inc: IncidentDetail }) {
  const { t } = useI18n()
  const hosts = hostsOf(inc.alerts)
  const { first, last } = span(inc.alerts)
  const ongoing = !!last && Date.now() - Date.parse(last) < ONGOING_MS
  const rules = new Set(inc.alerts.map(a => a.ruleId)).size
  const hits = inc.alerts.reduce((n, a) => n + (a.count || 1), 0)
  const done = inc.status === 'closed' || inc.status === 'false_positive'
  const owner = inc.work?.owner
  return (
    <div className="incident-facts">
      <Fact label={t('factHosts', { n: hosts.length })}
        foot={hosts.length > MAX_HOSTS && t('factMoreHosts', { n: hosts.length - MAX_HOSTS })}>
        {hosts.length === 0 ? '-' : (
          <Space orientation="vertical" size={2}>
            {hosts.slice(0, MAX_HOSTS).map(h => (
              <span key={h.id ?? h.name} className="incident-fact-host">
                {h.id ? <Link to={`/assets/${h.id}`}>{h.name}</Link> : h.name}
                {hosts.length > 1 && <Typography.Text type="secondary" className="incident-fact-sub">{t('factHostAlerts', { n: h.count })}</Typography.Text>}
              </span>
            ))}
          </Space>
        )}
      </Fact>
      <Fact label={t('factTime')}
        foot={first && last && <>{fmtTime(first)} → {fmtTime(last)}</>}>
        {last ? (
          <Space size={8} wrap>
            <Tooltip title={fmtTime(last)}><span>{t('factLastSeen', { ago: ago(last, t) })}</span></Tooltip>
            {ongoing && !done && <Tag color="red" className="incident-fact-live">{t('factOngoing')}</Tag>}
          </Space>
        ) : '-'}
        {first && last && <div className="incident-fact-sub">{t('factLasted', { d: duration(Date.parse(last) - Date.parse(first), t) })}</div>}
      </Fact>
      <Fact label={t('factAlerts')} foot={t('factFirstCreated', { at: fmtTime(inc.createdAt) })}>
        <Space size={8} align="baseline" wrap>
          <span className="incident-fact-num">{hits}</span>
          <Typography.Text type="secondary" className="incident-fact-sub">{t('factAlertBreakdown', { n: inc.alerts.length, rules })}</Typography.Text>
          <SeverityTag value={inc.severity} />
        </Space>
      </Fact>
      <Fact label={t('factHandling')}
        foot={done ? inc.resolvedAt && <>{inc.resolvedBy} · <Ago iso={inc.resolvedAt} /></> : inc.workNextCheckAt && t('factNextCheck', { at: fmtTime(inc.workNextCheckAt) })}>
        <Space size={8} wrap>
          <IncidentStatusTag value={inc.status} retriage={inc.retriage} triageStartedAt={inc.triageStartedAt} />
          {!done && owner && <Tag color={owner === 'ai' ? 'purple' : 'orange'}>{t(owner === 'ai' ? 'factOwnerAI' : 'factOwnerHuman')}</Tag>}
        </Space>
      </Fact>
    </div>
  )
}
