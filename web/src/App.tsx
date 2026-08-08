import { Fragment, useCallback, useEffect, useState } from 'react'
import {
  Unauthorized, fetchIncident, fetchIncidents, fetchMe, logout, setIncidentStatus,
  type IncidentDetail, type IncidentSummary, type Me,
} from './api'
import { AssetList } from './AssetList'
import { AuditLogView } from './AuditLogView'
import { DashboardView } from './DashboardView'
import { EventSearchView } from './EventSearchView'
import { IncidentGraphView } from './IncidentGraphView'
import { IntelList } from './IntelList'
import { LoginPage } from './LoginPage'
import { ResponsePanel } from './ResponsePanel'
import { SuppressDialog } from './SuppressDialog'
import { SuppressionList } from './SuppressionList'
import { UserManagement } from './UserManagement'
import { VerdictCard } from './VerdictCard'
import { useI18n, type MsgKey } from './i18n'

const STATUS_KEY: Record<string, MsgKey> = {
  open: 'statusOpen',
  triaged: 'statusTriaged',
  closed: 'statusClosed',
  false_positive: 'statusFalsePositive',
}

const fmt = (iso: string) => new Date(iso).toLocaleString()

export default function App() {
  const { t, locale, setLocale } = useI18n()
  // undefined = 会话状态未知（首屏探测中），null = 未登录
  const [me, setMe] = useState<Me | null | undefined>(undefined)
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  // webhook 通知里的链接带 ?incident=<id>，进来直接定位到事件
  const [selectedId, setSelectedId] = useState<string | null>(
    () => new URLSearchParams(location.search).get('incident'),
  )
  const [detail, setDetail] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  // 标记误报后弹出抑制对话框，把分析师的判断反馈回检测链路
  const [suppressing, setSuppressing] = useState(false)
  const [showSuppressions, setShowSuppressions] = useState(false)
  const [showIntel, setShowIntel] = useState(false)
  const [showDashboard, setShowDashboard] = useState(false)
  const [showEventSearch, setShowEventSearch] = useState(false)
  const [showAssets, setShowAssets] = useState(false)
  const [showUsers, setShowUsers] = useState(false)
  const [showAudit, setShowAudit] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null)

  useEffect(() => {
    fetchMe().then(setMe).catch(() => setMe(null))
  }, [])

  const refresh = useCallback(async () => {
    try {
      setIncidents(await fetchIncidents(statusFilter || undefined))
      setError(null)
    } catch (e) {
      if (e instanceof Unauthorized) {
        setMe(null)
        return
      }
      setError(t('connectError', { e: String(e) }))
    }
  }, [statusFilter, t])

  useEffect(() => {
    if (!me) return
    refresh()
    const timer = setInterval(refresh, 10_000)
    return () => clearInterval(timer)
  }, [refresh, me])

  useEffect(() => {
    setExpandedAlert(null)
    if (!selectedId) { setDetail(null); return }
    let stale = false
    fetchIncident(selectedId).then(d => { if (!stale) setDetail(d) }).catch(() => {})
    return () => { stale = true }
  }, [selectedId, incidents])

  const changeStatus = async (status: string) => {
    if (!detail) return
    await setIncidentStatus(detail.id, status)
    await refresh()
    setDetail(await fetchIncident(detail.id))
    if (status === 'false_positive') setSuppressing(true)
  }

  const doLogout = async () => {
    await logout()
    setMe(null)
  }

  if (me === undefined) return null
  if (me === null) return <LoginPage onLogin={setMe} />

  const canWrite = me.role !== 'viewer'
  const isAdmin = me.role === 'admin'
  const sevLabel = (n: number) => (n >= 1 && n <= 5 ? t(`sev${n}` as MsgKey) : String(n))

  return (
    <div className="layout">
      <aside className="sidebar">
        <header>
          <h1>OpenXDR</h1>
          <div className="header-actions">
            <button className="link" onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}>
              {locale === 'zh' ? 'EN' : '中文'}
            </button>
            <span className="muted">{me.username}</span>
            <button className="link" onClick={doLogout}>{t('logout')}</button>
          </div>
        </header>
        <div className="header-actions subnav">
          <span className="muted">{t('events', { n: incidents.length })}</span>
          <button className="link" onClick={() => setShowDashboard(true)}>{t('dashboard')}</button>
          <button className="link" onClick={() => setShowEventSearch(true)}>{t('eventSearch')}</button>
          <button className="link" onClick={() => setShowAssets(true)}>{t('assets')}</button>
          <button className="link" onClick={() => setShowSuppressions(true)}>{t('suppressions')}</button>
          <button className="link" onClick={() => setShowIntel(true)}>{t('intel')}</button>
          {isAdmin && (
            <>
              <button className="link" onClick={() => setShowUsers(true)}>{t('users')}</button>
              <button className="link" onClick={() => setShowAudit(true)}>{t('audit')}</button>
            </>
          )}
        </div>
        <div className="filter-tabs">
          {[['', 'all'] as const, ...Object.entries(STATUS_KEY)].map(([value, key]) => (
            <button
              key={value}
              className={`filter-tab ${value === statusFilter ? 'active' : ''}`}
              onClick={() => setStatusFilter(value)}
            >
              {t(key as MsgKey)}
            </button>
          ))}
        </div>
        {error && <div className="error">{error}</div>}
        {incidents.map(inc => (
          <button
            key={inc.id}
            className={`incident-item ${inc.id === selectedId ? 'selected' : ''}`}
            onClick={() => setSelectedId(inc.id)}
          >
            <div className="incident-title">
              {inc.severity > 0 && <span className={`sev-${inc.severity}`}>●&nbsp;</span>}
              {inc.title ?? inc.id}
            </div>
            <div className="incident-meta">
              <span className={`status status-${inc.status}`}>
                {STATUS_KEY[inc.status] ? t(STATUS_KEY[inc.status]) : inc.status}
              </span>
              {inc.aiVerdict?.verdict && <span className={`dot dot-${inc.aiVerdict.verdict}`} />}
              <span className="muted">{t('alertCountAt', { n: inc.alertCount, time: fmt(inc.createdAt) })}</span>
            </div>
          </button>
        ))}
        {incidents.length === 0 && !error && <div className="muted empty">{t('noIncidents')}</div>}
      </aside>

      <main className="main">
        {!detail ? (
          <div className="muted empty">{t('pickIncident')}</div>
        ) : (
          <>
            <div className="detail-head">
              <h2>{detail.title ?? detail.id}</h2>
              <div className="actions">
                <span className={`status status-${detail.status}`}>
                  {STATUS_KEY[detail.status] ? t(STATUS_KEY[detail.status]) : detail.status}
                </span>
                {canWrite && (
                  <>
                    <button onClick={() => changeStatus('closed')}>{t('close')}</button>
                    <button onClick={() => changeStatus('false_positive')}>{t('markFp')}</button>
                    {(detail.status === 'closed' || detail.status === 'false_positive') && (
                      <button onClick={() => changeStatus('open')}>{t('reopen')}</button>
                    )}
                  </>
                )}
              </div>
            </div>

            <VerdictCard verdict={detail.aiVerdict} />

            <h3>{t('responseTitle')}</h3>
            <ResponsePanel incidentId={detail.id} assetId={detail.assetId} canAct={canWrite} />

            <h3>{t('graphTitle')}</h3>
            <IncidentGraphView graph={detail.graph} />

            <h3>{t('alertsTitle', { n: detail.alerts.length })}</h3>
            <table>
              <thead>
                <tr>
                  <th>{t('thFirst')}</th><th>{t('thLast')}</th><th>{t('thRule')}</th>
                  <th>{t('thSeverity')}</th><th>{t('thCount')}</th>
                </tr>
              </thead>
              <tbody>
                {detail.alerts.map(a => (
                  <Fragment key={a.id}>
                    <tr
                      className="alert-row"
                      onClick={() => setExpandedAlert(expandedAlert === a.id ? null : a.id)}
                    >
                      <td>{fmt(a.ts)}</td>
                      <td>{a.lastTs ? fmt(a.lastTs) : '-'}</td>
                      <td title={a.ruleId}>{a.ruleTitle ?? a.ruleId}</td>
                      <td><span className={`sev sev-${a.severity}`}>{sevLabel(a.severity)}</span></td>
                      <td>{a.count}</td>
                    </tr>
                    {expandedAlert === a.id && (
                      <tr>
                        <td colSpan={5}>
                          <pre className="event-json">
                            {a.event ? JSON.stringify(a.event, null, 2) : t('noRawEvent')}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </>
        )}
      </main>

      {suppressing && detail && (
        <SuppressDialog
          alerts={detail.alerts}
          assetId={detail.assetId}
          onClose={() => setSuppressing(false)}
        />
      )}
      {showSuppressions && (
        <SuppressionList canAct={canWrite} onClose={() => setShowSuppressions(false)} />
      )}
      {showDashboard && <DashboardView onClose={() => setShowDashboard(false)} />}
      {showEventSearch && <EventSearchView onClose={() => setShowEventSearch(false)} />}
      {showIntel && <IntelList canAct={canWrite} onClose={() => setShowIntel(false)} />}
      {showAssets && <AssetList onClose={() => setShowAssets(false)} />}
      {showUsers && <UserManagement self={me.username} onClose={() => setShowUsers(false)} />}
      {showAudit && <AuditLogView onClose={() => setShowAudit(false)} />}
    </div>
  )
}
