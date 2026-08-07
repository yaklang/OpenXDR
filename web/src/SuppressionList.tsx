import { useCallback, useEffect, useState } from 'react'
import { deleteSuppression, fetchSuppressions, type Suppression } from './api'
import { useI18n } from './i18n'

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '-')

/// 抑制清单。抑制最怕的是被遗忘——列出压掉的次数，让长期无人过问的
/// 抑制规则显形，而不是悄悄吃掉真实告警。
export function SuppressionList({ canAct, onClose }: { canAct: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<Suppression[]>([])

  const refresh = useCallback(async () => {
    try {
      setRows(await fetchSuppressions())
    } catch {
      /* 拉取失败时保持原列表 */
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const remove = async (id: string) => {
    await deleteSuppression(id)
    await refresh()
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('suppressionListTitle', { n: rows.length })}</h3>
        {rows.length === 0 ? (
          <p className="muted">{t('noSuppressions')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('thRule')}</th><th>{t('thScope')}</th><th>{t('thMatched')}</th>
                <th>{t('thLastMatched')}</th><th>{t('thExpires')}</th><th>{t('thCreatedBy')}</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map(s => (
                <tr key={s.id}>
                  <td title={`${s.ruleId}\n${s.reason ?? ''}`}>{s.ruleTitle ?? s.ruleId}</td>
                  <td>{s.assetId ? t('singleHost') : <span className="sev-3">{t('allHosts')}</span>}</td>
                  <td>{s.matchedCount}</td>
                  <td>{fmt(s.lastMatchedAt)}</td>
                  <td>{s.expiresAt ? fmt(s.expiresAt) : t('longTerm')}</td>
                  <td className="muted">{s.createdBy}</td>
                  <td>{canAct && <button onClick={() => remove(s.id)}>{t('revoke')}</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
