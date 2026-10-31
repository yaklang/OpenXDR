import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Empty, Space, Table, Tabs, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchDirectories, fetchDirectoryAccounts, fetchDirectoryRuns, type DirectorySource, type DirectoryAccount, type DirectoryRun } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

const statuses: Record<string, MsgKey> = { running: 'directoryRunning', succeeded: 'directorySucceeded', failed: 'directoryFailed' }
const errors: Record<string, MsgKey> = {
  deadline_exceeded: 'directoryDeadlineExceeded', read_failed: 'directoryReadFailed', source_mismatch: 'directorySourceMismatch', invalid_result: 'directoryInvalidResult',
  stale_scan: 'directoryStaleScan', persist_failed: 'directoryPersistFailed', canceled: 'directoryCanceled',
}

export function DirectoryStatus({ groupId }: { groupId: string }) {
  const { me, groups } = useSession()
  const scope = [me.username, me.role, groupId, ...groups.map(g => `${g.id}:${g.role}`).sort()].join('|')
  return <DirectorySources key={scope} groupId={groupId} scope={scope} />
}

function DirectorySources({ groupId, scope }: { groupId: string; scope: string }) {
  const { t } = useI18n()
  const [selected, setSelected] = useState<string>()
  const query = useQuery({ queryKey: ['directories', scope], queryFn: () => fetchDirectories(groupId), gcTime: 0, refetchInterval: 15000 })
  const source = query.data?.items.find(s => s.id === selected)
  return <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('directoryHint')}</Typography.Text>
    <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {query.data?.truncated && <Alert showIcon type="info" title={t('directorySourceTruncated')} />}
      <Table<DirectorySource> rowKey="id" size="small" loading={query.isPending} dataSource={query.data?.items ?? []}
        scroll={{ x: 650 }} pagination={{ pageSize: 5, showSizeChanger: false, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('directoryEmpty')} /> }}
        columns={[
          { title: t('directorySource'), dataIndex: 'authority', render: (value, row) => <Space orientation="vertical" size={0}><Tag>{row.kind}</Tag><Button type="link" style={{ paddingInline: 0, height: 'auto', whiteSpace: 'normal', textAlign: 'start', overflowWrap: 'anywhere' }} onClick={() => setSelected(row.id)}>{value}</Button></Space> },
          { title: t('directoryLastSuccess'), dataIndex: 'lastFinishedAt', width: 170, render: value => value ? fmtTime(value) : t('directoryNever') },
          { title: t('directoryLatest'), dataIndex: 'latestStatus', width: 150, render: (value: string | null) => <Tag color={value === 'failed' ? 'error' : value === 'succeeded' ? 'success' : undefined}>{t(value ? statuses[value] ?? 'identityUnknown' : 'directoryNever')}</Tag> },
        ]} />
      {source && <DirectoryDetails key={`${scope}:${source.id}`} source={source} scope={scope} />}
    </>}
  </Space>
}

function DirectoryDetails({ source, scope }: { source: DirectorySource; scope: string }) {
  const { t } = useI18n()
  const [tab, setTab] = useState('accounts')
  return <Space orientation="vertical" style={{ width: '100%' }}>
    <Typography.Text strong style={{ overflowWrap: 'anywhere' }}>{source.authority}</Typography.Text>
    <Typography.Text copyable type="secondary">{source.id}</Typography.Text>
    {source.latestStatus === 'failed' && <Alert showIcon type="warning" title={t(errors[source.latestErrorCode ?? ''] ?? 'directoryUnknownError')} description={t('directoryFailureHint')} />}
    {source.latestStatus === 'running' && <Alert showIcon type="info" title={t('directoryRunningHint')} />}
    <Tabs activeKey={tab} onChange={setTab} items={[
      { key: 'accounts', label: t('directoryAccounts'), children: tab === 'accounts' && <DirectoryAccounts sourceId={source.id} scope={scope} /> },
      { key: 'runs', label: t('directoryRuns'), children: tab === 'runs' && <DirectoryRuns sourceId={source.id} scope={scope} /> },
    ]} />
  </Space>
}

function DirectoryAccounts({ sourceId, scope }: { sourceId: string; scope: string }) {
  const { t } = useI18n()
  const [cursors, setCursors] = useState<string[]>([])
  const after = cursors.at(-1) ?? ''
  const query = useQuery({ queryKey: ['directoryAccounts', scope, sourceId, after], queryFn: () => fetchDirectoryAccounts(sourceId, after), gcTime: 0 })
  return <Space orientation="vertical" style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('directoryAccountHint')}</Typography.Text>
    <Space wrap>
      <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
      <Button disabled={cursors.length === 0 || query.isFetching} onClick={() => setCursors([])}>{t('directoryFirstPage')}</Button>
      <Button disabled={cursors.length === 0 || query.isFetching} onClick={() => setCursors(c => c.slice(0, -1))}>{t('directoryPrevious')}</Button>
      <Button disabled={!query.data?.next || query.isFetching || query.isError} onClick={() => { if (query.data?.next) setCursors(c => [...c, query.data!.next!]) }}>{t('directoryNext')}</Button>
    </Space>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <Table<DirectoryAccount>
      size="small" rowKey="id" dataSource={query.data?.items ?? []} loading={query.isPending} pagination={false} scroll={{ x: 550 }}
      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('directoryAccountsEmpty')} /> }}
      columns={[
        { title: t('username'), dataIndex: 'username', render: value => <span style={{ overflowWrap: 'anywhere' }}>{value}</span> },
        { title: t('directoryAccountState'), dataIndex: 'enabled', width: 110, render: (value: boolean | null) => <Tag>{t(value === true ? 'directoryEnabled' : value === false ? 'directoryDisabled' : 'identityUnknown')}</Tag> },
        { title: t('directoryObserved'), dataIndex: 'observedAt', width: 170, render: fmtTime },
      ]} expandable={{ expandedRowRender: row => <div className="ev-expand"><Descriptions column={1} size="small" items={[
        { key: 'id', label: t('directoryExternalId'), children: <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{row.externalId}</Typography.Text> },
        { key: 'sid', label: 'SID', children: row.windowsSid ? <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{row.windowsSid}</Typography.Text> : '—' },
      ]} /></div> }} />}
  </Space>
}

function DirectoryRuns({ sourceId, scope }: { sourceId: string; scope: string }) {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['directoryRuns', scope, sourceId], queryFn: () => fetchDirectoryRuns(sourceId), gcTime: 0, refetchInterval: 15000 })
  return <Space orientation="vertical" style={{ width: '100%' }}>
    <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {query.data?.truncated && <Alert showIcon type="info" title={t('directoryRunsTruncated')} />}
      <Table<DirectoryRun> rowKey="id" size="small" dataSource={query.data?.items ?? []} loading={query.isPending} scroll={{ x: 650 }}
        pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('directoryRunsEmpty')} /> }}
        columns={[
          { title: t('directoryStarted'), dataIndex: 'startedAt', width: 170, render: fmtTime },
          { title: t('directoryFinished'), dataIndex: 'finishedAt', width: 170, render: value => value ? fmtTime(value) : '—' },
          { title: t('directoryLatest'), dataIndex: 'status', render: value => t(statuses[value] ?? 'identityUnknown') },
          { title: t('directoryCount'), dataIndex: 'accountCount', render: (value, row) => row.status === 'succeeded' ? value : '—' },
          { title: t('directoryError'), dataIndex: 'errorCode', render: value => value ? t(errors[value] ?? 'directoryUnknownError') : '—' },
        ]} />
    </>}
  </Space>
}
