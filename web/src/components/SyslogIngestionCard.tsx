import { useQuery } from '@tanstack/react-query'
import { Alert, Descriptions, Space, Tag, Typography } from 'antd'
import { fetchSyslogStatus } from '../api'
import { useI18n } from '../i18n'
import { TableCard } from './Page'
import { LoadError } from './LoadError'
import { Refreshed } from './Ago'
import { fmtTime } from './format'

export function SyslogIngestionCard() {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['syslogStatus'], queryFn: fetchSyslogStatus, refetchInterval: 15_000 })
  const s = query.data
  return <TableCard>
    <Space style={{ marginBottom: 12 }} wrap>
      <Typography.Title level={4} style={{ margin: 0 }}>Syslog</Typography.Title>
      <Refreshed at={query.dataUpdatedAt} fetching={query.isFetching} onRefresh={() => query.refetch()} />
    </Space>
    <Typography.Paragraph type="secondary">{t('syslogNodeHint')}</Typography.Paragraph>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : s && <>
      {!s.address && <Alert type="info" showIcon title={t('syslogDisabledHint')} style={{ marginBottom: 12 }} />}
      {(s.udpError || s.tcpError) && <Alert type="error" showIcon title={[s.udpError, s.tcpError].filter(Boolean).join(' · ')} style={{ marginBottom: 12 }} />}
      <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 3 }} items={[
        { key: 'address', label: t('syslogAddress'), children: s.address || '—' },
        { key: 'udp', label: 'UDP', children: <Tag color={s.udpListening ? 'green' : 'default'}>{t(s.udpListening ? 'syslogListening' : 'syslogStopped')}</Tag> },
        { key: 'tcp', label: 'TCP', children: <Tag color={s.tcpListening ? 'green' : 'default'}>{t(s.tcpListening ? 'syslogListening' : 'syslogStopped')}</Tag> },
        { key: 'received', label: t('syslogReceived'), children: s.received },
        { key: 'published', label: t('syslogPublished'), children: s.published },
        { key: 'last', label: t('syslogLastReceived'), children: s.lastReceived ? fmtTime(s.lastReceived) : '—' },
        { key: 'dropped', label: t('syslogDropped'), children: s.dropped },
        { key: 'failed', label: t('syslogFailed'), children: s.failed },
        { key: 'unassigned', label: t('syslogUnassigned'), children: s.unassigned },
      ]} />
    </>}
  </TableCard>
}
