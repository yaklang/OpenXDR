import { useEffect, useState } from 'react'
import { fetchStats, type Stats } from './api'
import { useI18n } from './i18n'

/// 概览面板。核心是降噪漏斗：原始事件 → 去重告警 → 待处理事件，
/// 三个数字直接回答"平台今天替我挡掉了多少噪声"。
export function DashboardView({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [stats, setStats] = useState<Stats | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchStats().then(setStats).catch(e => setError(String(e)))
  }, [])

  const maxTrend = stats ? Math.max(1, ...stats.alertTrend.map(b => b.count)) : 1

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('dashboard')}</h3>
        {error && <div className="error">{error}</div>}
        {stats && (
          <>
            <div className="funnel">
              <div className="funnel-stage">
                <div className="funnel-num">{stats.events24h.toLocaleString()}</div>
                <div className="muted">{t('funnelEvents')}</div>
              </div>
              <div className="funnel-arrow">→</div>
              <div className="funnel-stage">
                <div className="funnel-num">{stats.alerts24h.toLocaleString()}</div>
                <div className="muted">{t('funnelAlerts')}</div>
              </div>
              <div className="funnel-arrow">→</div>
              <div className="funnel-stage">
                <div className="funnel-num">{stats.openIncidents}</div>
                <div className="muted">{t('funnelIncidents')}</div>
              </div>
              <div className="funnel-stage funnel-assets">
                <div className="funnel-num">
                  {stats.assetsOnline}<span className="muted">/{stats.assetsTotal}</span>
                </div>
                <div className="muted">{t('assetsOnline')}</div>
              </div>
            </div>

            <h4>{t('alertTrend24h')}</h4>
            <div className="trend">
              {stats.alertTrend.map(b => (
                <div
                  key={b.hour}
                  className="trend-bar"
                  title={`${new Date(b.hour).getHours()}:00 — ${b.count}`}
                >
                  <div
                    className="trend-fill"
                    style={{ height: `${Math.round((b.count / maxTrend) * 100)}%` }}
                  />
                </div>
              ))}
            </div>

            <h4>{t('topRules')}</h4>
            {stats.topRules.length === 0 ? (
              <p className="muted">{t('noAlerts24h')}</p>
            ) : (
              <table>
                <thead>
                  <tr><th>{t('thRule')}</th><th>{t('thHits')}</th></tr>
                </thead>
                <tbody>
                  {stats.topRules.map(r => (
                    <tr key={r.ruleId}>
                      <td title={r.ruleId}>{r.ruleTitle ?? r.ruleId}</td>
                      <td>{r.count.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
