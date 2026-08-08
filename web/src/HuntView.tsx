import { useState } from 'react'
import { hunt, type HuntStep } from './api'
import { useI18n } from './i18n'

interface Turn {
  question: string
  answer: string
  steps: HuntStep[]
}

const EXAMPLES: string[] = [
  'huntExample1',
  'huntExample2',
  'huntExample3',
]

/// 对话式狩猎。分析师问，系统用只读调查工具查数据后答。
/// 每次回答都附上调用过的工具与参数——无从复核的 AI 结论在安全场景里没有价值。
export function HuntView({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [question, setQuestion] = useState('')
  const [turns, setTurns] = useState<Turn[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const ask = async (q: string) => {
    const text = q.trim()
    if (!text || busy) return
    setBusy(true)
    setError('')
    try {
      const r = await hunt(text)
      setTurns(prev => [...prev, { question: text, answer: r.answer, steps: r.steps ?? [] }])
      setQuestion('')
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('hunt')}</h3>
        {turns.length === 0 && (
          <div className="hunt-examples">
            <p className="muted">{t('huntHint')}</p>
            {EXAMPLES.map(key => (
              <button key={key} className="link" onClick={() => ask(t(key as never))}>
                {t(key as never)}
              </button>
            ))}
          </div>
        )}
        {turns.map((turn, i) => (
          <div key={i} className="hunt-turn">
            <div className="hunt-question">{turn.question}</div>
            <div className="hunt-answer">{turn.answer}</div>
            {turn.steps.length > 0 && (
              <details className="hunt-steps">
                <summary className="muted">{t('huntSteps', { n: turn.steps.length })}</summary>
                {turn.steps.map((s, j) => (
                  <div key={j} className="mono">{s.tool}({s.args})</div>
                ))}
              </details>
            )}
          </div>
        ))}
        {error && <div className="error">{error}</div>}
        <div className="actions search-bar">
          <input
            className="search-input"
            placeholder={t('huntPlaceholder')}
            value={question}
            disabled={busy}
            onChange={e => setQuestion(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && ask(question)}
          />
          <button onClick={() => ask(question)} disabled={busy}>
            {busy ? t('huntThinking') : t('huntAsk')}
          </button>
        </div>
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
