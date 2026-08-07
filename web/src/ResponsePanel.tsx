import { useCallback, useEffect, useState } from 'react'
import { fetchCommands, issueCommand, type CommandRow } from './api'
import { useI18n, type MsgKey } from './i18n'

const STATUS_KEY: Record<string, MsgKey> = {
  pending: 'cmdPending',
  sent: 'cmdSent',
  succeeded: 'cmdSucceeded',
  failed: 'cmdFailed',
  unsupported: 'cmdUnsupported',
}

const KIND_KEY: Record<string, MsgKey> = {
  kill_process: 'killProcess',
  isolate_host: 'isolateHost',
  unisolate_host: 'unisolateHost',
}

const fmt = (iso: string) => new Date(iso).toLocaleString()

export function ResponsePanel({
  incidentId,
  assetId,
  canAct,
}: {
  incidentId: string
  assetId: string | null
  canAct: boolean
}) {
  const { t } = useI18n()
  const [history, setHistory] = useState<CommandRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // 默认演练。要真执行必须先勾选，避免手滑隔离生产主机
  const [live, setLive] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setHistory(await fetchCommands(incidentId))
    } catch {
      /* 历史拉取失败不影响下发 */
    }
  }, [incidentId])

  useEffect(() => {
    refresh()
  }, [refresh])

  const issue = async (kind: string) => {
    if (!assetId) return
    if (live && !confirm(t('confirmLive', { kind: t(KIND_KEY[kind]) }))) return
    setBusy(true)
    setError(null)
    try {
      await issueCommand({ kind, assetId, incidentId, dryRun: !live })
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (!assetId) {
    return <div className="card muted">{t('noAssetForResponse')}</div>
  }

  return (
    <div className="card">
      {canAct && (
        <div className="response-head">
          <label className={`live-toggle ${live ? 'live-on' : ''}`}>
            <input type="checkbox" checked={live} onChange={e => setLive(e.target.checked)} />
            {live ? t('liveMode') : t('drillMode')}
          </label>
          <div className="actions">
            <button disabled={busy} onClick={() => issue('isolate_host')}>{t('isolateHost')}</button>
            <button disabled={busy} onClick={() => issue('unisolate_host')}>{t('unisolateHost')}</button>
          </div>
        </div>
      )}
      {canAct && !live && <p className="muted small">{t('drillNote')}</p>}
      {error && <div className="error">{error}</div>}

      {history.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>{t('thTime')}</th><th>{t('thAction')}</th><th>{t('thMode')}</th>
              <th>{t('thStatus')}</th><th>{t('thResult')}</th>
            </tr>
          </thead>
          <tbody>
            {history.map(c => (
              <tr key={c.id}>
                <td>{fmt(c.createdAt)}</td>
                <td>{KIND_KEY[c.kind] ? t(KIND_KEY[c.kind]) : c.kind}</td>
                <td>{c.dryRun ? t('drill') : <span className="sev-5">{t('live')}</span>}</td>
                <td className={`cmd-${c.status}`}>{STATUS_KEY[c.status] ? t(STATUS_KEY[c.status]) : c.status}</td>
                <td className="cmd-detail" title={c.detail ?? ''}>{c.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
