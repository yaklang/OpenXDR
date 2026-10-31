import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Space, Table, Typography } from 'antd'
import { useState } from 'react'
import { fetchIdentityCandidates, type IdentityDirectoryCandidate } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

export function IdentityCandidates({ eventId, scope }: { eventId: string; scope: string }) {
  const { t } = useI18n()
  const [opened, setOpened] = useState(false)
  const query = useQuery({ queryKey: ['identityCandidates', scope, eventId], queryFn: () => fetchIdentityCandidates(eventId), enabled: opened, gcTime: 0 })
  if (!opened) return <Button size="small" onClick={() => setOpened(true)}>{t('identityCandidatesOpen')}</Button>
  return <Space orientation="vertical" style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('identityCandidatesHint')}</Typography.Text>
    <Button size="small" loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {query.data?.ambiguous && <Alert showIcon type="warning" title={t('identityCandidatesAmbiguous')} />}
      {query.data?.truncated && <Alert showIcon type="info" title={t('identityCandidatesTruncated')} />}
      <Table<IdentityDirectoryCandidate> rowKey="accountId" size="small" loading={query.isPending} dataSource={query.data?.items ?? []}
        pagination={{ pageSize: 5, hideOnSinglePage: true, showSizeChanger: false }} scroll={{ x: 550 }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('identityCandidatesEmpty')} /> }}
        columns={[
          { title: t('directorySource'), dataIndex: 'authority', render: value => <span style={{ overflowWrap: 'anywhere' }}>{value}</span> },
          { title: t('username'), dataIndex: 'username' },
          { title: t('directoryObserved'), dataIndex: 'observedAt', width: 170, render: fmtTime },
          { title: t('identityCandidatesFreshness'), dataIndex: 'seenInLatestSync', width: 150, render: value => t(value ? 'identityCandidatesSeen' : 'identityCandidatesOld') },
        ]} expandable={{ expandedRowRender: row => <div className="ev-expand"><Space orientation="vertical">
          <Typography.Text copyable>{row.accountId}</Typography.Text>
          <Typography.Text copyable>{row.sid}</Typography.Text>
          <Typography.Text>{t('directoryLastSuccess')}: {row.lastSuccessfulSync ? fmtTime(row.lastSuccessfulSync) : '—'}</Typography.Text>
        </Space></div> }} />
    </>}
  </Space>
}
