import { useCallback, useEffect, useState } from 'react'
import { deleteIntel, fetchIntel, importIntel, type IntelRow } from './api'
import { useI18n } from './i18n'

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '-')

/// 威胁情报清单。命中数一列让每条 IOC 的价值可见：
/// 长期零命中的陈年情报应该被清理，而不是永远躺在库里制造误报风险。
export function IntelList({ canAct, onClose }: { canAct: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<IntelRow[]>([])
  const [text, setText] = useState('')
  const [source, setSource] = useState('')
  const [expiresInDays, setExpiresInDays] = useState(0)
  const [notice, setNotice] = useState('')

  const refresh = useCallback(async () => {
    try {
      setRows(await fetchIntel())
    } catch {
      /* 拉取失败时保持原列表 */
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const doImport = async () => {
    if (!text.trim()) return
    try {
      const r = await importIntel({ text, source: source || undefined, expiresInDays })
      setNotice(t('intelImported', { n: r.imported, skipped: r.skipped }))
      setText('')
      await refresh()
    } catch (e) {
      setNotice(String(e))
    }
  }

  const remove = async (id: string) => {
    await deleteIntel(id)
    await refresh()
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('intelListTitle', { n: rows.length })}</h3>
        {canAct && (
          <div className="intel-import">
            <textarea
              rows={4}
              placeholder={t('intelImportHint')}
              value={text}
              onChange={e => setText(e.target.value)}
            />
            <div className="actions">
              <input
                placeholder={t('intelSource')}
                value={source}
                onChange={e => setSource(e.target.value)}
              />
              <label>
                {t('validity')}
                <input
                  type="number"
                  min={0}
                  value={expiresInDays}
                  onChange={e => setExpiresInDays(Number(e.target.value))}
                />
              </label>
              <button onClick={doImport}>{t('intelImport')}</button>
              {notice && <span className="muted">{notice}</span>}
            </div>
          </div>
        )}
        {rows.length === 0 ? (
          <p className="muted">{t('noIntel')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('thKind')}</th><th>{t('thValue')}</th><th>{t('thSource')}</th>
                <th>{t('thSeverity')}</th><th>{t('thHits')}</th>
                <th>{t('thLastMatched')}</th><th>{t('thExpires')}</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id}>
                  <td>{r.kind}</td>
                  <td title={r.note ?? ''}>{r.value}</td>
                  <td className="muted">{r.source}</td>
                  <td><span className={`sev-${r.severity}`}>{r.severity}</span></td>
                  <td>{r.matchedCount}</td>
                  <td>{fmt(r.lastMatchedAt)}</td>
                  <td>{r.expiresAt ? fmt(r.expiresAt) : t('longTerm')}</td>
                  <td>{canAct && <button onClick={() => remove(r.id)}>{t('revoke')}</button>}</td>
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
