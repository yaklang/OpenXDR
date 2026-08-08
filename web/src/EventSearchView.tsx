import { useEffect, useState } from 'react'
import { searchEvents, type EventRow } from './api'
import { useI18n, type MsgKey } from './i18n'

const CLASS_KEY: Record<number, MsgKey> = {
  1007: 'classProcess',
  4001: 'classNetwork',
  4003: 'classDNS',
  100001: 'classLog',
}

const fmt = (iso: string) => new Date(iso).toLocaleString()

/// 原始事件检索。告警只是线索，取证要能沿着一个 IP、一段命令行翻出原始遥测。
export function EventSearchView({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  const [source, setSource] = useState('')
  const [classUid, setClassUid] = useState(0)
  const [hours, setHours] = useState(24)
  const [rows, setRows] = useState<EventRow[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [error, setError] = useState('')

  const run = () => {
    searchEvents({ q, source, classUid, hours })
      .then(r => {
        setRows(r)
        setError('')
      })
      .catch(e => setError(String(e)))
  }

  // 打开即查一次，让页面不是空的
  useEffect(run, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('eventSearch')}</h3>
        <div className="actions search-bar">
          <input
            className="search-input"
            placeholder={t('eventSearchHint')}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && run()}
          />
          <select value={classUid} onChange={e => setClassUid(Number(e.target.value))}>
            <option value={0}>{t('allClasses')}</option>
            {Object.entries(CLASS_KEY).map(([uid, key]) => (
              <option key={uid} value={uid}>{t(key)}</option>
            ))}
          </select>
          <select value={source} onChange={e => setSource(e.target.value)}>
            <option value="">{t('allSources')}</option>
            <option value="agent">agent</option>
            <option value="sensor">sensor</option>
            <option value="syslog">syslog</option>
          </select>
          <select value={hours} onChange={e => setHours(Number(e.target.value))}>
            {[1, 6, 24, 72, 168].map(h => (
              <option key={h} value={h}>{t('lastHours', { n: h })}</option>
            ))}
          </select>
          <button onClick={run}>{t('search')}</button>
        </div>
        {error && <div className="error">{error}</div>}
        {rows.length === 0 ? (
          <p className="muted">{t('noEvents')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('thTime')}</th><th>{t('thClass')}</th><th>{t('thSource')}</th>
                <th>{t('thUser')}</th><th>{t('thConn')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <>
                  <tr
                    key={r.id}
                    className="row-expandable"
                    onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                  >
                    <td>{fmt(r.ts)}</td>
                    <td>{CLASS_KEY[r.classUid] ? t(CLASS_KEY[r.classUid]) : r.classUid}</td>
                    <td className="muted">{r.source}</td>
                    <td>{r.username ?? '-'}</td>
                    <td className="mono">{r.connTuple ?? '-'}</td>
                  </tr>
                  {expanded === r.id && (
                    <tr key={r.id + '-raw'}>
                      <td colSpan={5}>
                        <pre className="raw-json">{JSON.stringify(r.raw, null, 2)}</pre>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
        <div className="actions modal-actions">
          <span className="muted">{t('eventCount', { n: rows.length })}</span>
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
