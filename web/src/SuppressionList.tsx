import { useCallback, useEffect, useState } from 'react'
import { deleteSuppression, fetchSuppressions, type Suppression } from './api'

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '-')

/// 抑制清单。抑制最怕的是被遗忘——列出压掉的次数，让长期无人过问的
/// 抑制规则显形，而不是悄悄吃掉真实告警。
export function SuppressionList({ onClose }: { onClose: () => void }) {
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
        <h3>误报抑制清单（{rows.length}）</h3>
        {rows.length === 0 ? (
          <p className="muted">还没有抑制规则。在事件详情里标记误报时可以顺手创建。</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>规则</th><th>范围</th><th>已压掉</th><th>最近命中</th>
                <th>到期</th><th>创建者</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map(s => (
                <tr key={s.id}>
                  <td title={`${s.ruleId}\n${s.reason ?? ''}`}>{s.ruleTitle ?? s.ruleId}</td>
                  <td>{s.assetId ? '单主机' : <span className="sev-3">全部主机</span>}</td>
                  <td>{s.matchedCount}</td>
                  <td>{fmt(s.lastMatchedAt)}</td>
                  <td>{s.expiresAt ? fmt(s.expiresAt) : '长期'}</td>
                  <td className="muted">{s.createdBy}</td>
                  <td><button onClick={() => remove(s.id)}>撤销</button></td>
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
