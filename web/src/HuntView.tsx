import { useState } from 'react'
import { draftRule, hunt, saveRule, type HuntStep } from './api'
import { useI18n } from './i18n'

interface Turn {
  question: string
  answer: string
  steps: HuntStep[]
  // 规则草稿的三态：undefined 未起草，字符串是可编辑的 YAML，saved 后只留标题
  draft?: string
  savedTitle?: string
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

  const patchTurn = (i: number, patch: Partial<Turn>) =>
    setTurns(prev => prev.map((turn, j) => (j === i ? { ...turn, ...patch } : turn)))

  const draft = async (i: number, turn: Turn) => {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const r = await draftRule(turn.question, turn.answer)
      patchTurn(i, { draft: r.yaml })
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const save = async (i: number, yaml: string) => {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const r = await saveRule(yaml)
      patchTurn(i, { draft: undefined, savedTitle: r.title || r.id })
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

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
            {turn.savedTitle ? (
              <div className="muted">{t('huntRuleSaved', { title: turn.savedTitle })}</div>
            ) : turn.draft !== undefined ? (
              <div className="hunt-draft">
                <p className="muted">{t('huntDraftHint')}</p>
                <textarea
                  className="mono"
                  rows={14}
                  value={turn.draft}
                  onChange={e => patchTurn(i, { draft: e.target.value })}
                />
                <div className="actions">
                  <button onClick={() => save(i, turn.draft!)} disabled={busy}>
                    {t('huntSave')}
                  </button>
                  <button onClick={() => patchTurn(i, { draft: undefined })} disabled={busy}>
                    {t('huntCancel')}
                  </button>
                </div>
              </div>
            ) : (
              <button className="link" onClick={() => draft(i, turn)} disabled={busy}>
                {busy ? t('huntDrafting') : t('huntSaveRule')}
              </button>
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
