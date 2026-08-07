import { useEffect, useState } from 'react'
import { fetchAudit, type AuditRow } from './api'
import { useI18n, type MsgKey } from './i18n'

const ACTION_KEY: Record<string, MsgKey> = {
  login: 'actLogin',
  login_failed: 'actLoginFailed',
  logout: 'actLogout',
  incident_status: 'actIncidentStatus',
  command_issued: 'actCommandIssued',
  suppression_created: 'actSuppressionCreated',
  suppression_deleted: 'actSuppressionDeleted',
  user_created: 'actUserCreated',
  user_deleted: 'actUserDeleted',
  user_password_reset: 'actUserPasswordReset',
}

export function AuditLogView({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<AuditRow[]>([])

  useEffect(() => {
    fetchAudit().then(setRows).catch(() => {})
  }, [])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('auditListTitle', { n: rows.length })}</h3>
        {rows.length === 0 ? (
          <p className="muted">{t('noAudit')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('thTime')}</th><th>{t('thUser')}</th><th>{t('thAction')}</th>
                <th>{t('thTarget')}</th><th>{t('thDetail')}</th><th>{t('thIP2')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(a => (
                <tr key={a.id} className={a.action === 'login_failed' ? 'sev-4' : ''}>
                  <td>{new Date(a.ts).toLocaleString()}</td>
                  <td>{a.username}</td>
                  <td>{ACTION_KEY[a.action] ? t(ACTION_KEY[a.action]) : a.action}</td>
                  <td className="muted cmd-detail" title={a.target ?? ''}>{a.target ?? '-'}</td>
                  <td className="muted">{a.detail ?? '-'}</td>
                  <td className="muted">{a.remoteAddr}</td>
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
