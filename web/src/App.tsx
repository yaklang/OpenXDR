import { useCallback, useEffect, useState } from 'react'
import {
  fetchIncident, fetchIncidents, setIncidentStatus,
  type IncidentDetail, type IncidentSummary,
} from './api'
import { IncidentGraphView } from './IncidentGraphView'
import { ResponsePanel } from './ResponsePanel'
import { SuppressDialog } from './SuppressDialog'
import { SuppressionList } from './SuppressionList'
import { VerdictCard } from './VerdictCard'

const STATUS_LABEL: Record<string, string> = {
  open: '待研判',
  triaged: '已研判',
  closed: '已关闭',
  false_positive: '误报',
}

const SEVERITY_LABEL = ['-', '信息', '低危', '中危', '高危', '严重']

const fmt = (iso: string) => new Date(iso).toLocaleString()

export default function App() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  // 标记误报后弹出抑制对话框，把分析师的判断反馈回检测链路
  const [suppressing, setSuppressing] = useState(false)
  const [showSuppressions, setShowSuppressions] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setIncidents(await fetchIncidents())
      setError(null)
    } catch (e) {
      setError(`无法连接 server：${e}`)
    }
  }, [])

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 10_000)
    return () => clearInterval(timer)
  }, [refresh])

  useEffect(() => {
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

  return (
    <div className="layout">
      <aside className="sidebar">
        <header>
          <h1>OpenXDR</h1>
          <div className="header-actions">
            <span className="muted">{incidents.length} 个事件</span>
            <button className="link" onClick={() => setShowSuppressions(true)}>抑制清单</button>
          </div>
        </header>
        {error && <div className="error">{error}</div>}
        {incidents.map(inc => (
          <button
            key={inc.id}
            className={`incident-item ${inc.id === selectedId ? 'selected' : ''}`}
            onClick={() => setSelectedId(inc.id)}
          >
            <div className="incident-title">{inc.title ?? inc.id}</div>
            <div className="incident-meta">
              <span className={`status status-${inc.status}`}>{STATUS_LABEL[inc.status] ?? inc.status}</span>
              {inc.aiVerdict?.verdict && <span className={`dot dot-${inc.aiVerdict.verdict}`} />}
              <span className="muted">{inc.alertCount} 告警 · {fmt(inc.createdAt)}</span>
            </div>
          </button>
        ))}
        {incidents.length === 0 && !error && <div className="muted empty">暂无事件，世界很安静</div>}
      </aside>

      <main className="main">
        {!detail ? (
          <div className="muted empty">← 选择一个事件</div>
        ) : (
          <>
            <div className="detail-head">
              <h2>{detail.title ?? detail.id}</h2>
              <div className="actions">
                <span className={`status status-${detail.status}`}>{STATUS_LABEL[detail.status] ?? detail.status}</span>
                <button onClick={() => changeStatus('closed')}>关闭</button>
                <button onClick={() => changeStatus('false_positive')}>标记误报</button>
                {(detail.status === 'closed' || detail.status === 'false_positive') && (
                  <button onClick={() => changeStatus('open')}>重开</button>
                )}
              </div>
            </div>

            <VerdictCard verdict={detail.aiVerdict} />

            <h3>响应处置</h3>
            <ResponsePanel incidentId={detail.id} assetId={detail.assetId} />

            <h3>实体关系图</h3>
            <IncidentGraphView graph={detail.graph} />

            <h3>告警明细（{detail.alerts.length}）</h3>
            <table>
              <thead>
                <tr><th>首次</th><th>最近</th><th>规则</th><th>级别</th><th>次数</th></tr>
              </thead>
              <tbody>
                {detail.alerts.map(a => (
                  <tr key={a.id}>
                    <td>{fmt(a.ts)}</td>
                    <td>{a.lastTs ? fmt(a.lastTs) : '-'}</td>
                    <td title={a.ruleId}>{a.ruleTitle ?? a.ruleId}</td>
                    <td><span className={`sev sev-${a.severity}`}>{SEVERITY_LABEL[a.severity] ?? a.severity}</span></td>
                    <td>{a.count}</td>
                  </tr>
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
      {showSuppressions && <SuppressionList onClose={() => setShowSuppressions(false)} />}
    </div>
  )
}
