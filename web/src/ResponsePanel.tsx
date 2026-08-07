import { useCallback, useEffect, useState } from 'react'
import { fetchCommands, issueCommand, type CommandRow } from './api'

const STATUS_LABEL: Record<string, string> = {
  pending: '待下发',
  sent: '已下发',
  succeeded: '成功',
  failed: '失败',
  unsupported: '不支持',
}

const KIND_LABEL: Record<string, string> = {
  kill_process: '结束进程',
  isolate_host: '隔离主机',
  unisolate_host: '解除隔离',
}

const fmt = (iso: string) => new Date(iso).toLocaleString()

export function ResponsePanel({
  incidentId,
  assetId,
}: {
  incidentId: string
  assetId: string | null
}) {
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
    if (live && !confirm(`确认对该主机执行「${KIND_LABEL[kind]}」？这会立即生效。`)) return
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
    return <div className="card muted">该事件没有归属主机，无法下发响应指令</div>
  }

  return (
    <div className="card">
      <div className="response-head">
        <label className={`live-toggle ${live ? 'live-on' : ''}`}>
          <input type="checkbox" checked={live} onChange={e => setLive(e.target.checked)} />
          {live ? '真实执行' : '演练模式'}
        </label>
        <div className="actions">
          <button disabled={busy} onClick={() => issue('isolate_host')}>隔离主机</button>
          <button disabled={busy} onClick={() => issue('unisolate_host')}>解除隔离</button>
        </div>
      </div>
      {!live && <p className="muted small">演练模式只报告将要执行的动作，不产生任何实际影响。</p>}
      {error && <div className="error">{error}</div>}

      {history.length > 0 && (
        <table>
          <thead>
            <tr><th>时间</th><th>动作</th><th>模式</th><th>状态</th><th>结果</th></tr>
          </thead>
          <tbody>
            {history.map(c => (
              <tr key={c.id}>
                <td>{fmt(c.createdAt)}</td>
                <td>{KIND_LABEL[c.kind] ?? c.kind}</td>
                <td>{c.dryRun ? '演练' : <span className="sev-5">真实</span>}</td>
                <td className={`cmd-${c.status}`}>{STATUS_LABEL[c.status] ?? c.status}</td>
                <td className="cmd-detail" title={c.detail ?? ''}>{c.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
