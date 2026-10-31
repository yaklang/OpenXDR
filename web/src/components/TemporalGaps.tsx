import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Empty, Select, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchTemporalGaps, type Asset, type TemporalGap } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

export function TemporalGaps({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const { me, groups } = useSession()
  const [hours, setHours] = useState(24)
  const [page, setPage] = useState(1)
  const membership = groups.map(g => `${g.id}:${g.role}`).sort().join(',')
  const query = useQuery({
    queryKey: ['temporalGaps', me.username, me.role, membership, asset.id, asset.groupId, hours],
    queryFn: () => fetchTemporalGaps(asset.id, hours),
    gcTime: 0,
    refetchInterval: 15000,
  })
  const rows = query.data?.items ?? []
  const currentPage = Math.min(page, Math.max(1, Math.ceil(rows.length / 10)))
  const copy = (value: string) => <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{value}</Typography.Text>

  return <Space orientation="vertical" size={16} style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('temporalGapsHint')}</Typography.Text>
    <div className="filter-bar" style={{ padding: '10px 14px' }}>
      <Space wrap className="filter-controls">
        <Select aria-label={t('temporalGapsRecorded')} style={{ width: 170 }} value={hours}
          options={[1, 6, 24, 72, 168].map(n => ({ value: n, label: t('lastHours', { n }) }))}
          onChange={value => { setHours(value); setPage(1) }} />
        <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
      </Space>
    </div>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {rows.length > 0 && <Alert type="warning" showIcon title={t('temporalGapsWarning')} />}
      {query.data?.truncated && <Alert type="info" showIcon title={t('temporalGapsTruncated', { n: rows.length })} />}
      <Table<TemporalGap> size="small" rowKey={r => `${r.revision}:${r.eventId}`} loading={query.isPending} dataSource={rows}
        scroll={{ x: 540 }} pagination={{ current: currentPage, onChange: setPage, pageSize: 10, showSizeChanger: false, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('temporalGapsEmpty')} /> }}
        columns={[
          { title: t('temporalGapsRecorded'), dataIndex: 'createdAt', width: 180, render: fmtTime },
          { title: t('temporalGapsReason'), dataIndex: 'reason', render: (value: string) => <Tag color="warning">{t(value === 'candidate_limit' ? 'temporalGapsLimit' : value === 'late' ? 'temporalGapsLate' : 'temporalGapsUnknown')}</Tag> },
          // 迟到缺口没有读取窗口，不存在候选数量下限
          { title: t('temporalGapsCount'), dataIndex: 'candidateCountLowerBound', width: 160, render: (value: number, row) => row.reason === 'late' ? '—' : `≥ ${value.toLocaleString()}` },
        ]}
        expandable={{ expandedRowRender: row => <div className="ev-expand"><Descriptions size="small" column={1} items={[
          { key: 'event', label: t('identitySourceEvent'), children: copy(row.eventId) },
          { key: 'revision', label: t('temporalGapsRevision'), children: copy(row.revision) },
          { key: 'window', label: t('temporalGapsWindow'), children: `${fmtTime(row.windowFrom)} — ${fmtTime(row.windowTo)}` },
          { key: 'group', label: t('identityHistoricalGroup'), children: groups.find(g => g.id === row.groupId)?.name ?? row.groupId },
        ]} /></div> }} />
    </>}
  </Space>
}
