import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Space, Table, Tag, Typography } from 'antd'
import { fetchTriageRuns, type TriageRun } from '../api'
import { useI18n } from '../i18n'
import { fmtTime } from './format'
import { LoadError } from './LoadError'

export function TriageHistory({ id }: { id: string }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [page, setPage] = useState(1)
  const query = useQuery({ queryKey: ['triage-runs', id, page], queryFn: () => fetchTriageRuns(id, page), enabled: open, refetchInterval: open ? 10000 : false })
  const seconds = (ms = 0) => `${(ms / 1000).toFixed(1)} s`
  const statuses = { running: 'triageRunRunning', succeeded: 'triageRunSucceeded', failed: 'triageRunFailed', interrupted: 'triageRunInterrupted' } as const
  const triggers = { initial: 'triageRunInitial', reopened: 'triageRunReopened', urgent: 'triageRunUrgent', evidence: 'triageRunEvidence' } as const
  return <Card title={t('triageRunHistory')} extra={<Button type="link" onClick={() => setOpen(!open)}>{t(open ? 'triageRunHide' : 'triageRunShow')}</Button>}>
    <Typography.Text type="secondary">{t('triageRunHint')}</Typography.Text>
    {open && <div style={{ marginTop: 14 }}>
      {query.isError && <LoadError error={query.error} onRetry={() => query.refetch()} />}
      <Table<TriageRun> size="small" rowKey="id" loading={query.isPending} dataSource={query.data?.items ?? []} pagination={false} scroll={{ x: 1000 }} columns={[
        { title: t('thTime'), width: 170, render: (_, row) => fmtTime(row.started_at) },
        { title: t('thStatus'), width: 130, render: (_, row) => <Tag color={row.status === 'failed' ? 'error' : row.status === 'succeeded' ? 'success' : 'default'}>{row.status === 'running' && !row.heartbeat_valid ? t('triageRunUnknown') : t(statuses[row.status])}</Tag> },
        { title: t('triageRunTrigger'), width: 120, render: (_, row) => t(triggers[row.trigger]) },
        { title: t('triageRunWait'), width: 100, render: (_, row) => row.ready_at ? seconds(Math.max(0, Date.parse(row.started_at) - Date.parse(row.ready_at))) : '—' },
        { title: t('triageRunDuration'), width: 110, render: (_, row) => row.status === 'running' ? '—' : row.error_code === 'lease_replaced' ? t('triageRunUnknown') : seconds(row.duration_ms) },
        { title: t('triageRunModel'), width: 180, render: (_, row) => `${row.model || '—'} · ${row.model_calls ?? 0} / ${seconds(row.model_ms)}` },
        { title: t('triageRunTools'), width: 150, render: (_, row) => `${row.tool_calls ?? 0} / ${seconds(row.tool_ms)} (${row.tool_errors ?? 0})` },
        { title: 'Token', width: 120, render: (_, row) => (row.input_tokens ?? 0) + (row.output_tokens ?? 0) },
      ]} expandable={{ expandedRowRender: row => <Space orientation="vertical" style={{ width: '100%' }}>
        <Typography.Text>{t('triageRunError')}: {row.error_code || '—'}</Typography.Text>
        {(row.tool_details ?? []).map((tool, index) => <Typography.Text key={index}>
          {index + 1}. {tool.tool} · {seconds(tool.duration_ms)} · {t(tool.failed ? 'triageRunFailed' : 'triageRunSucceeded')}
          {tool.returned != null && ` · ${t('triageToolReturned')}: ${tool.returned}`}
          {tool.truncated && ` · ${t('triageToolTruncated')}`}
        </Typography.Text>)}
      </Space> }} />
      <Space style={{ marginTop: 12 }}>
        <Button size="small" disabled={page === 1} onClick={() => setPage(page - 1)}>{t('triageRunPrevious')}</Button>
        <span>{page}</span>
        <Button size="small" disabled={!query.data?.more} onClick={() => setPage(page + 1)}>{t('triageRunNext')}</Button>
      </Space>
    </div>}
  </Card>
}
