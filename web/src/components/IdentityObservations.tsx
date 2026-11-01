import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Empty, Select, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchIdentityObservations, type Asset, type IdentityObservation } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { LoadError } from './LoadError'
import { LocalIdentityCandidates } from './LocalIdentityCandidates'
import { IdentityCandidates } from './IdentityCandidates'
import { fmtTime } from './format'

const states: Record<string, MsgKey> = {
  missing_uid: 'identityMissingUID', observed: 'identityObserved', missing_sid: 'identityMissingSID', unscoped: 'identityUnscoped', invalid: 'identityInvalid',
}

export function IdentityObservations({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const { me, groups } = useSession()
  const [hours, setHours] = useState(24)
  const [page, setPage] = useState(1)
  // 换组或成员信息变化时不复用旧结果，关闭标签页后移除身份查询缓存。
  const membership = groups.map(g => `${g.id}:${g.role}`).sort().join(',')
  const query = useQuery({
    queryKey: ['identityObservations', me.username, me.role, membership, asset.id, asset.groupId, hours],
    queryFn: () => fetchIdentityObservations(asset.id, hours),
    gcTime: 0,
    refetchInterval: 15000,
  })
  const copy = (value: string | null) => value
    ? <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{value}</Typography.Text>
    : '—'
  const items = query.data?.items ?? []
  const currentPage = Math.min(page, Math.max(1, Math.ceil(items.length / 10)))

  return <Space orientation="vertical" size={16} style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('identityHint')}</Typography.Text>
    <div className="filter-bar" style={{ padding: '10px 14px' }}>
      <Space wrap className="filter-controls">
        <Select aria-label={t('thTime')} value={hours} style={{ width: 170 }}
          onChange={value => { setHours(value); setPage(1) }}
          options={[1, 6, 24, 72, 168].map(n => ({ value: n, label: t('lastHours', { n }) }))} />
        <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
      </Space>
    </div>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {query.data?.truncated && <Alert type="info" showIcon title={t('identityTruncated', { n: items.length })} />}
      <Table<IdentityObservation> size="small" rowKey="eventId" loading={query.isPending} dataSource={items}
        scroll={{ x: 620 }} pagination={{ current: currentPage, onChange: setPage, pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('identityEmpty')} /> }}
        columns={[
          { title: t('thTime'), dataIndex: 'ts', width: 170, render: fmtTime },
          { title: t('thUser'), dataIndex: 'name', render: (v: string | null) => <span style={{ overflowWrap: 'anywhere' }}>{v || '—'}</span> },
          { title: t('thResult'), dataIndex: 'success', width: 120, render: (value: boolean | null) => <Tag color={value === true ? 'blue' : value === false ? 'warning' : undefined}>{t(value === true ? 'identitySucceeded' : value === false ? 'identityFailed' : 'identityResultUnknown')}</Tag> },
          { title: t('identityState'), dataIndex: 'state', width: 140, render: (value: string) => <Tag color={value === 'invalid' ? 'warning' : undefined}>{t(states[value] ?? 'identityUnknown')}</Tag> },
        ]}
        expandable={{ expandedRowRender: row => <div className="ev-expand"><Descriptions column={1} size="small" items={[
          { key: 'sid', label: 'SID', children: copy(row.sid) },
          { key: 'domain', label: t('identityDomain'), children: copy(row.domain) },
          { key: 'logon', label: t('identityLogon'), children: copy(row.logonId) },
          { key: 'group', label: t('identityHistoricalGroup'), children: row.groupId ? groups.find(g => g.id === row.groupId)?.name ?? row.groupId : t('ungrouped') },
          { key: 'event', label: t('identitySourceEvent'), children: copy(row.eventId) },
          ...(row.sid ? [{ key: 'directory', label: t('directoryAccounts'), children: <IdentityCandidates key={`${me.username}:${me.role}:${membership}:${asset.groupId}:${row.eventId}`} eventId={row.eventId} scope={`${me.username}:${me.role}:${membership}:${asset.groupId}`} /> }] : []),
          ...(row.state === 'missing_uid' ? [{ key: 'local', label: t('collectorLocalAccounts'), children: <LocalIdentityCandidates key={`${me.username}:${me.role}:${membership}:${asset.groupId}:${row.eventId}`} eventId={row.eventId} scope={`${me.username}:${me.role}:${membership}:${asset.groupId}`} /> }] : []),
          ...(row.detail ? [{ key: 'detail', label: t('thDetail'), children: row.detail }] : []),
        ]} /></div> }} />
    </>}
  </Space>
}
