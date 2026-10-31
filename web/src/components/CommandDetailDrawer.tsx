import { useQuery } from '@tanstack/react-query'
import { Alert, Descriptions, Drawer, Space, Spin, Typography } from 'antd'
import { fetchCommand } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { CommandStatusTag, commandKind, fmtTime } from './format'

export function CommandDetailDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['command', id], queryFn: () => fetchCommand(id), refetchInterval: q => ['pending', 'sent'].includes(q.state.data?.status ?? '') ? 5000 : false })
  const row = query.data
  return <Drawer open title={t('commandViewDetail')} onClose={onClose} size="large">
    {query.isPending && <Spin />}
    {query.isError && <LoadError error={query.error} onRetry={() => query.refetch()} />}
    {row && <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Descriptions column={1} size="small" items={[
        { key: 'kind', label: t('thAction'), children: commandKind(row.kind, t) },
        { key: 'status', label: t('thStatus'), children: <CommandStatusTag value={row.status} /> },
        { key: 'time', label: t('thTime'), children: fmtTime(row.createdAt) },
        { key: 'detail', label: t('thResult'), children: row.detail || '—' },
        { key: 'exit', label: t('commandExitCode'), children: row.exitCode ?? '—' },
      ]} />
      {row.truncated && <Alert type="warning" showIcon title={t('commandOutputTruncated')} />}
      {([['cmd', row.cmd], ['stdout', row.stdout], ['stderr', row.stderr]] as const).map(([name, text]) => text != null && <div key={name}>
        <Typography.Title level={5} style={{ marginTop: 0, marginBottom: 8 }}>{name}</Typography.Title><pre className="json-block">{text}</pre>
      </div>)}
    </Space>}
  </Drawer>
}
