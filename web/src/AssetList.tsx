import { useEffect, useState } from 'react'
import { fetchAssets, type Asset } from './api'
import { useI18n } from './i18n'

const fmt = (iso: string) => new Date(iso).toLocaleString()

// 心跳超过 5 分钟视为失联——agent 掉线本身就是值得注意的信号
const STALE_MS = 5 * 60_000

export function AssetList({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<Asset[]>([])

  useEffect(() => {
    fetchAssets().then(setRows).catch(() => {})
  }, [])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('assetListTitle', { n: rows.length })}</h3>
        {rows.length === 0 ? (
          <p className="muted">{t('noAssets')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th><th>{t('thHostname')}</th><th>OS</th><th>{t('thIP')}</th>
                <th>{t('thSource')}</th><th>{t('thLastSeen')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(a => (
                <tr key={a.id}>
                  <td>
                    <span
                      className={`dot ${Date.now() - Date.parse(a.lastSeen) < STALE_MS ? 'dot-benign' : 'dot-stale'}`}
                      title={Date.now() - Date.parse(a.lastSeen) < STALE_MS ? t('online') : t('stale')}
                    />
                  </td>
                  <td>{a.hostname}</td>
                  <td className="muted">{a.os ?? '-'}</td>
                  <td className="muted">{a.ipAddrs?.join(', ') ?? '-'}</td>
                  <td className="muted">{a.agentId ? t('sourceAgent') : t('sourceLog')}</td>
                  <td title={t('firstSeenAt', { time: fmt(a.firstSeen) })}>{fmt(a.lastSeen)}</td>
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
