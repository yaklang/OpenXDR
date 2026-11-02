import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Space, Table, Typography } from 'antd'
import { useState } from 'react'
import { fetchLocalIdentityCandidates, type LocalIdentityCandidate } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

export function LocalIdentityCandidates({ eventId, scope }: { eventId: string; scope: string }) {
  const { t } = useI18n()
  const [opened, setOpened] = useState(false)
  const query = useQuery({ queryKey: ['localIdentityCandidates', scope, eventId], queryFn: () => fetchLocalIdentityCandidates(eventId), enabled: opened, gcTime: 0 })
  if (!opened) return <Button size="small" onClick={() => setOpened(true)}>{t('localCandidatesOpen')}</Button>
  return <Space orientation="vertical" style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('localCandidatesHint')}</Typography.Text>
    <Button size="small" loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {query.data?.truncated && <Alert showIcon type="info" title={t('identityCandidatesTruncated')} />}
      <Table<LocalIdentityCandidate> rowKey="eventId" size="small" loading={query.isPending} dataSource={query.data?.items ?? []}
        pagination={{ pageSize: 5, hideOnSinglePage: true, showSizeChanger: false }} scroll={{ x: 550 }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('localCandidatesEmpty')} /> }}
        columns={[
          { title: t('directoryObserved'), dataIndex: 'observedAt', width: 170, render: fmtTime },
          { title: t('username'), dataIndex: 'name', render: v => <span style={{ overflowWrap: 'anywhere' }}>{v}</span> },
          { title: 'UID', dataIndex: 'uid' }, { title: 'GID', dataIndex: 'gid' },
        ]} expandable={{ expandedRowRender: row => <div className="ev-expand"><Space orientation="vertical">
          <Typography.Text>{t('identitySourceEvent')}: <Typography.Text copyable>{row.eventId}</Typography.Text></Typography.Text>
          <Typography.Text style={{ overflowWrap: 'anywhere' }}>Shell: {row.shell || '—'}</Typography.Text>
        </Space></div> }} />
    </>}
  </Space>
}
