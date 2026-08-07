import { useState } from 'react'
import { createSuppression, type AlertRow } from './api'
import { useI18n } from './i18n'

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
  const { t } = useI18n()
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
        <h3>{t('suppressTitle')}</h3>
        <p className="muted small">{t('suppressExplain')}</p>

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
            {t('scopeThisHost')}
            {!scopeAsset && <strong className="sev-5">{t('scopeAllWarning')}</strong>}
          </span>
        </label>

        <label className="field">
          {t('validity')}
          <select value={days} onChange={e => setDays(Number(e.target.value))}>
            <option value={7}>{t('days', { n: 7 })}</option>
            <option value={30}>{t('days', { n: 30 })}</option>
            <option value={90}>{t('days', { n: 90 })}</option>
            <option value={0}>{t('longTerm')}</option>
          </select>
        </label>

        <label className="field">
          {t('reason')}
          <input
            type="text"
            value={reason}
            placeholder={t('reasonPlaceholder')}
            onChange={e => setReason(e.target.value)}
          />
        </label>

        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('skip')}</button>
          <button disabled={busy || selected.length === 0} onClick={submit}>
            {t('createSuppressions', { n: selected.length })}
          </button>
        </div>
      </div>
    </div>
  )
}
