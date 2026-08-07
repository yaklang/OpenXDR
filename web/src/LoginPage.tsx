import { useState } from 'react'
import { login, type Me } from './api'
import { useI18n } from './i18n'

export function LoginPage({ onLogin }: { onLogin: (me: Me) => void }) {
  const { t } = useI18n()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onLogin(await login(username, password))
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="modal login-box" onSubmit={submit}>
        <h1>OpenXDR</h1>
        <label className="field">
          {t('username')}
          <input value={username} autoFocus onChange={e => setUsername(e.target.value)} />
        </label>
        <label className="field">
          {t('password')}
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} />
        </label>
        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button type="submit" disabled={busy || !username || !password}>{t('signIn')}</button>
        </div>
      </form>
    </div>
  )
}
