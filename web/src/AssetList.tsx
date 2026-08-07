import { useEffect, useState } from 'react'
import { fetchAssets, type Asset } from './api'

const fmt = (iso: string) => new Date(iso).toLocaleString()

// 心跳超过 5 分钟视为失联——agent 掉线本身就是值得注意的信号
const STALE_MS = 5 * 60_000

export function AssetList({ onClose }: { onClose: () => void }) {
  const [rows, setRows] = useState<Asset[]>([])

  useEffect(() => {
    fetchAssets().then(setRows).catch(() => {})
  }, [])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>资产清单（{rows.length}）</h3>
        {rows.length === 0 ? (
          <p className="muted">还没有资产。agent 上线或日志接入后会自动登记。</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th><th>主机名</th><th>OS</th><th>IP</th>
                <th>来源</th><th>最近心跳</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(a => (
                <tr key={a.id}>
                  <td>
                    <span
                      className={`dot ${Date.now() - Date.parse(a.lastSeen) < STALE_MS ? 'dot-benign' : 'dot-stale'}`}
                      title={Date.now() - Date.parse(a.lastSeen) < STALE_MS ? '在线' : '失联'}
                    />
                  </td>
                  <td>{a.hostname}</td>
                  <td className="muted">{a.os ?? '-'}</td>
                  <td className="muted">{a.ipAddrs?.join(', ') ?? '-'}</td>
                  <td className="muted">{a.agentId ? 'agent' : '日志'}</td>
                  <td title={`首次发现 ${fmt(a.firstSeen)}`}>{fmt(a.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="actions modal-actions">
          <button onClick={onClose}>关闭</button>
        </div>
      </div>
    </div>
  )
}
