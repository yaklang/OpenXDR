import type { Verdict } from './api'
import { useI18n, type MsgKey } from './i18n'

const VERDICT_META: Record<string, { key: MsgKey; className: string }> = {
  malicious: { key: 'verdictMalicious', className: 'badge-malicious' },
  suspicious: { key: 'verdictSuspicious', className: 'badge-suspicious' },
  benign: { key: 'verdictBenign', className: 'badge-benign' },
}

export function VerdictCard({ verdict }: { verdict: Verdict | null }) {
  const { t } = useI18n()
  if (!verdict) return <div className="card muted">{t('waitingVerdict')}</div>
  if (verdict.error)
    return (
      <div className="card muted">{t('unparsableVerdict', { e: verdict.raw ?? verdict.error })}</div>
    )

  const meta = VERDICT_META[verdict.verdict ?? '']

  return (
    <div className="card">
      <div className="verdict-head">
        <span className={`badge ${meta?.className ?? ''}`}>
          {meta ? t(meta.key) : verdict.verdict}
        </span>
        {verdict.confidence != null && (
          <span className="confidence">
            {t('confidence')} {verdict.confidence}
            <span className="confidence-bar">
              <span style={{ width: `${Math.min(verdict.confidence, 100)}%` }} />
            </span>
          </span>
        )}
      </div>
      {verdict.summary && <p className="summary">{verdict.summary}</p>}
      {!!verdict.kill_chain?.length && (
        <>
          <h4>{t('killChain')}</h4>
          <ol>{verdict.kill_chain.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </>
      )}
      {!!verdict.actions?.length && (
        <>
          <h4>{t('suggestedActions')}</h4>
          <ul>{verdict.actions.map((s, i) => <li key={i}>{s}</li>)}</ul>
        </>
      )}
    </div>
  )
}
