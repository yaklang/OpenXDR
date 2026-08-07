import { useState } from 'react'
import { createSuppression, type AlertRow } from './api'

/// 标记误报后弹出：让分析师顺手把噪声源掐掉，而不是明天再看一遍同样的告警。
export function SuppressDialog({
  alerts,
  assetId,
  onClose,
}: {
  alerts: AlertRow[]
  assetId: string | null
  onClose: () => void
}) {
  // 同一事件可能由多条规则触发，逐条选择要抑制哪些
  const rules = Array.from(
    new Map(alerts.map(a => [a.ruleId, a.ruleTitle ?? a.ruleId])).entries(),
  )
  const [selected, setSelected] = useState<string[]>(rules.map(([id]) => id))
  const [scopeAsset, setScopeAsset] = useState(true)
  const [days, setDays] = useState(30)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      for (const ruleId of selected) {
        await createSuppression({
          ruleId,
          assetId: scopeAsset ? assetId : null,
          reason,
          expiresInDays: days,
        })
      }
      onClose()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h3>抑制这些规则？</h3>
        <p className="muted small">
          抑制后这些规则不再产生告警，但事件仍然入库。被压掉的次数会记录下来，
          可在抑制列表查看和撤销。
        </p>

        {rules.map(([id, title]) => (
          <label key={id} className="check-row">
            <input
              type="checkbox"
              checked={selected.includes(id)}
              onChange={e =>
                setSelected(prev =>
                  e.target.checked ? [...prev, id] : prev.filter(r => r !== id),
                )
              }
            />
            <span title={id}>{title}</span>
          </label>
        ))}

        <label className="check-row">
          <input
            type="checkbox"
            checked={scopeAsset}
            disabled={!assetId}
            onChange={e => setScopeAsset(e.target.checked)}
          />
          <span>
            仅对本主机生效
            {!scopeAsset && <strong className="sev-5">（将对所有主机生效）</strong>}
          </span>
        </label>

        <label className="field">
          有效期
          <select value={days} onChange={e => setDays(Number(e.target.value))}>
            <option value={7}>7 天</option>
            <option value={30}>30 天</option>
            <option value={90}>90 天</option>
            <option value={0}>长期</option>
          </select>
        </label>

        <label className="field">
          原因
          <input
            type="text"
            value={reason}
            placeholder="例如：运维扫描器已知噪声"
            onChange={e => setReason(e.target.value)}
          />
        </label>

        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button onClick={onClose}>跳过</button>
          <button disabled={busy || selected.length === 0} onClick={submit}>
            创建 {selected.length} 条抑制
          </button>
        </div>
      </div>
    </div>
  )
}
