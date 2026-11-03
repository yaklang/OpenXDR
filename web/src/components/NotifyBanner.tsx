import { useQuery } from '@tanstack/react-query'
import { Alert } from 'antd'
import { Link } from 'react-router'
import { fetchNotifyHealth } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'

// 通知渠道断了而事件在积压时常驻提示：推送目标被清空或连续失败，不能静默几天没人知道
export function NotifyBanner() {
  const { t } = useI18n()
  const { isAdmin } = useSession()
  const { data } = useQuery({ queryKey: ['notify-health'], queryFn: fetchNotifyHealth, refetchInterval: 60_000 })
  if (!data || data.status === 'ok' || data.pendingIncidents === 0) return null
  const reason = data.status === 'unconfigured'
    ? t('notifyReasonUnconfigured')
    : t('notifyReasonFailing', { n: data.consecutiveFailures, error: data.lastError ?? '' })
  return (
    <Alert type="error" showIcon style={{ marginBottom: 16 }}
      title={t('notifyUndelivered', { n: data.pendingIncidents, reason })}
      action={isAdmin && <Link to="/settings">{t('notifyGoSettings')}</Link>} />
  )
}
