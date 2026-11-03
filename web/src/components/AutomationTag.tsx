import { Tag, Tooltip } from 'antd'
import { Link } from 'react-router'
import type { AutomationRef } from '../api'
import { useI18n } from '../i18n'

// 告警来自已知自动化：高危例外仍进研判，标成橙色
export function AutomationTag({ value }: { value?: AutomationRef }) {
  const { t } = useI18n()
  if (!value) return null
  return (
    <Tooltip title={t(value.watch ? 'automationWatchHint' : 'automationHint')}>
      <Link to="/trusted-sources" onClick={e => e.stopPropagation()}>
        <Tag color={value.watch ? 'orange' : 'cyan'} style={{ marginInlineEnd: 0 }}>
          {t(value.watch ? 'automationWatchTag' : 'automationTag', { name: value.name })}
        </Tag>
      </Link>
    </Tooltip>
  )
}

// 告警来自 docker 容器健康检查：能进 incident 的只有高危例外
export function HealthcheckTag({ value }: { value?: boolean }) {
  const { t } = useI18n()
  if (!value) return null
  return (
    <Tooltip title={t('healthcheckWatchHint')}>
      <Tag color="orange" style={{ marginInlineEnd: 0 }}>{t('healthcheckWatchTag')}</Tag>
    </Tooltip>
  )
}
