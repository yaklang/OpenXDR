import { useCallback, useEffect, useState } from 'react'
import { createUser, deleteUser, fetchUsers, resetUserPassword, type UserRow } from './api'
import { useI18n, type MsgKey } from './i18n'

const ROLE_KEY: Record<string, MsgKey> = {
  admin: 'roleAdmin',
  analyst: 'roleAnalyst',
  viewer: 'roleViewer',
}

export function UserManagement({ self, onClose }: { self: string; onClose: () => void }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<UserRow[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('analyst')
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      setRows(await fetchUsers())
    } catch {
      /* 拉取失败保持原列表 */
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const run = async (fn: () => Promise<unknown>) => {
    setError(null)
    try {
      await fn()
      await refresh()
    } catch (e) {
      setError(String(e))
    }
  }

  const create = () =>
    run(async () => {
      await createUser({ username, password, role })
      setUsername('')
      setPassword('')
    })

  const resetPw = (u: UserRow) => {
    const pw = prompt(t('newPasswordPrompt'))
    if (pw) run(() => resetUserPassword(u.id, pw))
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('userListTitle', { n: rows.length })}</h3>
        <table>
          <thead>
            <tr>
              <th>{t('username')}</th><th>{t('thRole')}</th><th>{t('thCreatedAt')}</th><th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map(u => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{t(ROLE_KEY[u.role] ?? 'thRole')}</td>
                <td className="muted">{new Date(u.createdAt).toLocaleString()}</td>
                <td>
                  <div className="actions">
                    <button onClick={() => resetPw(u)}>{t('resetPassword')}</button>
                    {u.username !== self && (
                      <button onClick={() => run(() => deleteUser(u.id))}>{t('del')}</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="field">
          <input
            placeholder={t('username')}
            value={username}
            onChange={e => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder={t('password')}
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
          <select value={role} onChange={e => setRole(e.target.value)}>
            <option value="admin">{t('roleAdmin')}</option>
            <option value="analyst">{t('roleAnalyst')}</option>
            <option value="viewer">{t('roleViewer')}</option>
          </select>
          <button disabled={!username || password.length < 8} onClick={create}>
            {t('create')}
          </button>
        </div>

        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
