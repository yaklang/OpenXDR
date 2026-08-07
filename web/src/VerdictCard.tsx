import type { Verdict } from './api'

const VERDICT_META: Record<string, { label: string; className: string }> = {
  malicious: { label: '恶意', className: 'badge-malicious' },
  suspicious: { label: '可疑', className: 'badge-suspicious' },
  benign: { label: '良性', className: 'badge-benign' },
}

export function VerdictCard({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <div className="card muted">等待 AI 研判…</div>
  if (verdict.error)
    return <div className="card muted">研判输出无法解析：{verdict.raw ?? verdict.error}</div>

  const meta = VERDICT_META[verdict.verdict ?? ''] ?? { label: verdict.verdict ?? '未知', className: '' }

  return (
    <div className="card">
      <div className="verdict-head">
        <span className={`badge ${meta.className}`}>{meta.label}</span>
        {verdict.confidence != null && (
          <span className="confidence">
            置信度 {verdict.confidence}
            <span className="confidence-bar">
              <span style={{ width: `${Math.min(verdict.confidence, 100)}%` }} />
            </span>
          </span>
        )}
      </div>
      {verdict.summary && <p className="summary">{verdict.summary}</p>}
      {!!verdict.kill_chain?.length && (
        <>
          <h4>攻击链</h4>
          <ol>{verdict.kill_chain.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </>
      )}
      {!!verdict.actions?.length && (
        <>
          <h4>处置建议</h4>
          <ul>{verdict.actions.map((s, i) => <li key={i}>{s}</li>)}</ul>
        </>
      )}
    </div>
  )
}
