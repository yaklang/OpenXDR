import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Divider, Empty, Select, Space, Table, Typography } from 'antd'
import { useState } from 'react'
import { fetchLocalAccountSnapshot, fetchLocalAccountSnapshots, type Asset, type LocalAccount, type LocalAccountSnapshot } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { AssetIdentityAccounts } from './AssetIdentityAccounts'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

function SnapshotAccounts({ eventId, scope }: { eventId: string; scope: string }) {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['localAccountSnapshot', scope, eventId], queryFn: () => fetchLocalAccountSnapshot(eventId), gcTime: 0 })
  if (query.isError) return <LoadError error={query.error} onRetry={() => query.refetch()} />
  if (query.data && query.data.state !== 'observed') return <Alert type="warning" showIcon title={t('localAccountsUnavailable')} />
  return <Table<LocalAccount> size="small" rowKey="name" loading={query.isPending} dataSource={query.data?.items ?? []}
    pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }} scroll={{ x: 500 }}
    locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('localAccountsEmptySnapshot')} /> }}
    columns={[
      { title: t('username'), dataIndex: 'name', render: v => <span style={{ overflowWrap: 'anywhere' }}>{v}</span> },
      { title: 'UID', dataIndex: 'uid' }, { title: 'GID', dataIndex: 'gid' },
      { title: 'Shell', dataIndex: 'shell', render: v => <span style={{ overflowWrap: 'anywhere' }}>{v || '—'}</span> },
    ]} />
}

export function LocalAccounts({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const { me, groups } = useSession()
  const [hours, setHours] = useState(24)
  const scope = `${me.username}:${me.role}:${groups.map(g => `${g.id}:${g.role}`).sort().join(',')}:${asset.id}:${asset.groupId}`
  const query = useQuery({ queryKey: ['localAccountSnapshots', scope, hours], queryFn: () => fetchLocalAccountSnapshots(asset.id, hours), gcTime: 0, refetchInterval: 15000 })
  return <Space orientation="vertical" size={16} style={{ width: '100%' }}>
    <AssetIdentityAccounts asset={asset} />
    <Divider style={{ margin: '8px 0' }} />
    <Typography.Title level={5} style={{ margin: 0 }}>{t('localAccountsSnapshots')}</Typography.Title>
    <Typography.Text type="secondary">{t('localAccountsHint')}</Typography.Text>
    <div className="filter-bar" style={{ padding: '10px 14px' }}>
      <Space wrap className="filter-controls">
        <Select aria-label={t('thTime')} value={hours} style={{ width: 170 }} onChange={setHours}
          options={[1, 6, 24, 72, 168].map(n => ({ value: n, label: t('lastHours', { n }) }))} />
        <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
      </Space>
    </div>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {query.data?.truncated && <Alert type="info" showIcon title={t('identityTruncated', { n: query.data.items.length })} />}
      <Table<LocalAccountSnapshot> key={`${scope}:${hours}`} size="small" rowKey="eventId" loading={query.isPending} dataSource={query.data?.items ?? []}
        scroll={{ x: 580 }} pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('localAccountsNoSnapshots')} /> }}
        columns={[
          { title: t('thTime'), dataIndex: 'ts', render: fmtTime },
          { title: t('identityState'), dataIndex: 'state', render: v => t(v === 'observed' ? 'identityObserved' : v === 'unavailable' ? 'localAccountsUnavailable' : v === 'invalid' ? 'identityInvalid' : 'identityUnknown') },
          { title: t('localAccountsCount'), dataIndex: 'accountCount', render: v => v ?? '—' },
          { title: t('identityHistoricalGroup'), dataIndex: 'groupId', render: v => v ? groups.find(g => g.id === v)?.name ?? v : t('ungrouped') },
        ]}
        expandable={{ expandedRowRender: row => <div className="ev-expand"><Space orientation="vertical" style={{ width: '100%' }}>
          <Typography.Text>{t('directorySource')}: {row.source}</Typography.Text>
          <Typography.Text copyable>{row.eventId}</Typography.Text>
          <SnapshotAccounts key={`${scope}:${row.eventId}`} eventId={row.eventId} scope={scope} />
        </Space></div> }} />
    </>}
  </Space>
}
