import { TableActions } from '../components/TableActions'
import { RobotOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Descriptions, Input, Segmented, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { fetchFindingsPage, setFindingStatus, type FindingRow } from '../api'
import { useCanAct, useSession } from '../app/session'
import { useCanChat, useHandoff } from '../components/Handoff'
import { HostLink } from '../components/HostLink'
import { FilterCard, Page, STICKY_HEADER, useWideTable } from '../components/Page'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { LoadError } from '../components/LoadError'
import { ResolveModal } from '../components/ResolveModal'
import { CommandDetailDrawer } from '../components/CommandDetailDrawer'
import { errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const SEVERITY: Record<FindingRow['severity'], { key: MsgKey; color: string; rank: number }> = {
  info: { key: 'sev1', color: 'default', rank: 1 },
  low: { key: 'sev2', color: 'blue', rank: 2 },
  medium: { key: 'sev3', color: 'gold', rank: 3 },
  high: { key: 'sev4', color: 'orange', rank: 4 },
}

const STATUS: Record<FindingRow['status'], { key: MsgKey; color: string }> = {
  open: { key: 'findingOpen', color: 'orange' },
  resolved: { key: 'findingResolved', color: 'green' },
  ignored: { key: 'findingIgnored', color: 'default' },
}

function FindingWorkSummary({ finding: f }: { finding: FindingRow }) {
  const { t } = useI18n()
  const active = f.workSessionId && f.workLeaseUntil && Date.parse(f.workLeaseUntil) > Date.now()
  const stages: Record<string, string> = {
    investigating: active ? t('incidentWorkInvestigating') : t('findingWorkWaiting'),
    monitoring: t('incidentWorkMonitoring'),
    waiting: t('findingWorkWaiting'),
    blocked: t('findingWorkBlocked'),
    resolved: t('findingResolved'),
  }
  return <Space orientation="vertical" size={2}>
    <Space size={4} wrap>
      <Tag color={f.workOwner === 'ai' ? 'blue' : f.workOwner === 'human' ? 'orange' : 'default'}>{f.workOwner === 'ai' ? t('incidentWorkAI') : f.workOwner === 'human' ? t('incidentWorkHuman') : '—'}</Tag>
      {f.status === 'open' && f.work?.stage && <Typography.Text type="secondary">{stages[f.work.stage] ?? f.work.stage}</Typography.Text>}
    </Space>
    {f.status === 'open' && f.workNextCheckAt && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('incidentWorkNextCheck')}: {fmtTime(f.workNextCheckAt)}</Typography.Text>}
  </Space>
}

function FindingWorkDetails({ finding: f, onCommand }: { finding: FindingRow; onCommand: (id: string) => void }) {
  const { t } = useI18n()
  const w = f.work
  if (!w) return null
  const blockers: Record<string, string> = { permission: t('findingWorkPermission'), unsupported: t('findingWorkUnsupported') }
  const wake: Record<string, string> = { new_observation_or_next_check: t('findingWorkObservation'), recurrence: t('findingWorkRecurrence') }
  return <>
    <Descriptions column={1} size="small">
      {(w.original_problem && w.original_problem !== f.detail || w.original_title && w.original_title !== f.title) && <Descriptions.Item label={t('findingWorkOriginal')}><Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{w.original_title && `${w.original_title}\n`}{w.original_problem}</Typography.Paragraph></Descriptions.Item>}
      {w.plan && <Descriptions.Item label={t('findingWorkPlan')}>{w.plan}</Descriptions.Item>}
      <Descriptions.Item label={t('incidentWorkAttempts')}>{f.workAttempts ?? '—'}</Descriptions.Item>
      {w.blocker && <Descriptions.Item label={t('findingWorkBlocker')}>{blockers[w.blocker] ?? w.blocker}</Descriptions.Item>}
      {w.wake_on && <Descriptions.Item label={t('incidentWorkWake')}>{wake[w.wake_on] ?? w.wake_on}</Descriptions.Item>}
      {f.workSessionId && <Descriptions.Item label={t('findingWorkSession')}><Link to={`/chat/${f.workSessionId}`}>{t('openSession')}</Link></Descriptions.Item>}
      {!!w.evidence_commands?.length && <Descriptions.Item label={t('findingWorkEvidence')}><Space wrap>{w.evidence_commands.map((id, index) => <Button type="link" size="small" key={id} onClick={() => onCommand(id)}>{index + 1}. {t('commandViewDetail')}</Button>)}</Space></Descriptions.Item>}
    </Descriptions>
    <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>{t('findingWorkHint')}</Typography.Paragraph>
  </>
}

// 运维待办：展示平台跟进责任与复查计划，人工操作仍单独记录。
export function FindingsPage() {
  const wideTable = useWideTable()
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups } = useSession()
  const canAct = useCanAct()
  const [params, setParams] = useSearchParams()
  const ids = params.get('ids') ?? undefined
  const status = params.get('status') ?? (ids !== undefined ? 'all' : 'open')
  const requestedPage = Number(params.get('page'))
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1
  const ownerParam = params.get('workOwner')
  const workOwner = ownerParam === 'ai' || ownerParam === 'human' ? ownerParam : undefined
  const [commandId, setCommandId] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [sevFilter, setSevFilter] = useState<string>('')
  const [acting, setActing] = useState<{ row: FindingRow; next: 'resolved' | 'ignored' } | null>(null)
  const [selectedKeys, setSelected] = useState<string[]>([])
  const canChat = useCanChat()
  const handoff = useHandoff()
  const { data, isPending, isError, error, refetch, dataUpdatedAt, isFetching } = useQuery({
    queryKey: ['findings', 'list', status, workOwner, ids, page],
    queryFn: () => fetchFindingsPage({ ids, workOwner, status: status === 'all' ? undefined : status, limit: 20, offset: (page - 1) * 20 }),
    refetchInterval: 30_000,
  })
  useEffect(() => {
    if (isError || isFetching || data?.total === undefined) return
    const lastPage = Math.max(1, Math.ceil(data.total / 20))
    if (page > lastPage) setParams(prev => { const next = new URLSearchParams(prev); next.set('page', String(lastPage)); return next }, { replace: true })
  }, [data?.total, isError, isFetching, page, status, workOwner, setParams])

  const activeQ = q.trim().toLowerCase()
  const hasClientFilter = Boolean(activeQ || sevFilter)
  const rows = useMemo(() => (data?.items ?? []).filter(f =>
    (!sevFilter || f.severity === sevFilter) &&
    (!activeQ || f.title.toLowerCase().includes(activeQ) || f.key.toLowerCase().includes(activeQ) || (f.hostname ?? '').toLowerCase().includes(activeQ) || (f.detail ?? '').toLowerCase().includes(activeQ))
  ), [data?.items, sevFilter, activeQ])

  // 返回是否成功：弹窗靠它决定关不关、原因留不留
  const change = async (row: FindingRow, next: string, note?: string) => {
    try {
      await setFindingStatus(row.id, next, note)
    } catch (e) {
      message.error(errText(e, t))
      return false
    }
    setActing(null)
    client.invalidateQueries({ queryKey: ['findings'] })
    return true
  }

  useEffect(() => { setSelected([]); setActing(null); setCommandId(null) }, [status, workOwner, ids, page])
  const picked = rows.filter(f => selectedKeys.includes(f.id) && f.status === 'open' && canChat(f.groupId))
  const selected = picked.map(f => f.id)
  const sameGroup = picked.length > 0 && picked.every(f => f.groupId === picked[0].groupId)
  const handTo = (list: FindingRow[]) => handoff.start(list[0].groupId, list.map(f => `finding:${f.id}`),
    list.length === 1 ? t('handoffFindingTitle', { title: list[0].title }) : t('handoffFindingsTitle', { n: list.length }),
    t('handoffFindingPrompt'))

  return (
    <Page title={t('navFindings')} subtitle={t('findingsSubtitle')}>
      <FilterCard
        onReset={hasClientFilter || workOwner ? () => { setQ(''); setSevFilter(''); setParams(prev => { const next = new URLSearchParams(prev); next.delete('workOwner'); next.delete('page'); return next }) } : undefined}
        extra={(
          <Space wrap>
            {selected.length > 0 && (
              <Tooltip title={!sameGroup ? t('handoffSameGroup') : picked.length > 10 ? t('handoffMax') : undefined}>
                <Button size="small" type="primary" icon={<RobotOutlined />} loading={handoff.busy}
                  disabled={!sameGroup || picked.length > 10 || !canChat(picked[0]?.groupId)} onClick={() => handTo(picked)}>
                  {t('handoffToAI')}（{selected.length}）
                </Button>
              </Tooltip>
            )}
            <Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />
          </Space>
        )}
        filters={
          <Space wrap>
            <Segmented
              value={status}
              onChange={v => { setSelected([]); setParams(prev => { const next = new URLSearchParams(prev); next.set('status', String(v)); next.delete('page'); return next }) }}
              options={[
                ...(['open', 'resolved', 'ignored'] as const).map(s => ({ value: s, label: t(STATUS[s].key) })),
                { value: 'all', label: t('all') },
              ]}
            />
            <Select aria-label={t('incidentWorkOwner')} style={{ width: 155 }} value={workOwner ?? ''}
              onChange={value => setParams(prev => { const next = new URLSearchParams(prev); if (value) next.set('workOwner', value); else next.delete('workOwner'); next.delete('page'); return next })}
              options={[
                { value: '', label: t('findingWorkAllOwners') },
                { value: 'ai', label: t('incidentWorkAI') },
                { value: 'human', label: t('incidentWorkHuman') },
              ]}
            />
            <Input.Search allowClear style={{ width: 240 }} placeholder={t('searchFindings')} value={q} onChange={e => setQ(e.target.value)} />
            <Select aria-label={t('thSeverity')} style={{ width: 135 }} value={sevFilter} onChange={setSevFilter}
              options={[
                { value: '', label: t('allSeverities') },
                { value: 'high', label: t('sev4') },
                { value: 'medium', label: t('sev3') },
                { value: 'low', label: t('sev2') },
                { value: 'info', label: t('sev1') },
              ]}
            />
            {ids !== undefined && <><Tag>{t('findingLinkedFilter')}</Tag><Button size="small" onClick={() => setParams({ status: 'open' })}>{t('resetFilters')}</Button></>}
          </Space>
        }
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<FindingRow>
          sticky={STICKY_HEADER}
          scroll={{ x: 1590 }}
          tableLayout="fixed"
          rowKey="id"
          rowSelection={{ selectedRowKeys: selected, onChange: keys => setSelected(keys as string[]), getCheckboxProps: f => ({ disabled: f.status !== 'open' || !canChat(f.groupId) }) }}
          loading={isPending}
          dataSource={rows}
          pagination={{ current: page, pageSize: 20, total: hasClientFilter ? rows.length : data?.total, showSizeChanger: false, hideOnSinglePage: true, onChange: p => { setSelected([]); setParams(prev => { const next = new URLSearchParams(prev); next.set('page', String(p)); return next }) } }}
          locale={{ emptyText: <EmptyHint title={t(hasClientFilter ? 'noMatch' : 'noFindings')} hint={hasClientFilter ? undefined : t('noFindingsHint')} action={hasClientFilter ? undefined : <Link to="/tasks">{t('goTasks')}</Link>} /> }}
          expandable={{ expandedRowRender: f => <div className="ev-expand">
            <pre className="json-block" style={{ whiteSpace: 'pre-wrap' }}>{f.detail || '-'}</pre>
            <FindingWorkDetails finding={f} onCommand={setCommandId} />
          </div> }}
          columns={[
            { title: t('thSeverity'), dataIndex: 'severity', width: 95, sorter: (a, b) => SEVERITY[a.severity].rank - SEVERITY[b.severity].rank, render: (v: FindingRow['severity']) => <Tag color={SEVERITY[v]?.color}>{t(SEVERITY[v]?.key ?? 'sev1')}</Tag> },
            { title: t('thTitle'), dataIndex: 'title', sorter: (a, b) => a.title.localeCompare(b.title), render: (v, f) => <Space orientation="vertical" size={0} style={{ width: '100%', overflowWrap: 'anywhere' }}><span>{v}</span><Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{f.key}</Typography.Text></Space> },
            { title: t('findingWorkColumn'), width: 190, render: (_, f) => <FindingWorkSummary finding={f} /> },
            { title: t('thHostname'), dataIndex: 'assetId', width: 140, sorter: (a, b) => (a.hostname ?? '').localeCompare(b.hostname ?? ''), render: (v, f) => <HostLink id={v} fallback={f.hostname} /> },
            { title: t('group'), dataIndex: 'groupId', width: 120, sorter: (a, b) => (groups.find(g => g.id === a.groupId)?.name ?? '').localeCompare(groups.find(g => g.id === b.groupId)?.name ?? ''), render: v => groups.find(g => g.id === v)?.name ?? v.slice(0, 8) },
            { title: t('thFirstSeen'), dataIndex: 'firstSeen', width: 115, sorter: (a, b) => a.firstSeen.localeCompare(b.firstSeen), render: v => <Ago iso={v} /> },
            { title: t('thLastConfirmed'), dataIndex: 'lastSeen', width: 115, sorter: (a, b) => a.lastSeen.localeCompare(b.lastSeen), render: v => <Ago iso={v} /> },
            {
              title: t('thStatus'), dataIndex: 'status', width: 110,
              sorter: (a, b) => a.status.localeCompare(b.status),
              render: (v: FindingRow['status'], f) => (
                <Tooltip title={f.note && t('noteBy', { who: f.resolvedBy ?? '', note: f.note })}>
                  <Tag color={STATUS[v].color}>{t(STATUS[v].key)}</Tag>
                </Tooltip>
              ),
            },
            {
              title: t('actions'), width: 300, fixed: wideTable ? 'right' : undefined,
              render: (_, f) => (
                <TableActions>
                  {f.sessionId && <Link to={`/chat/${f.sessionId}`}>{t('openSession')}</Link>}
                  {canChat(f.groupId) && f.status === 'open' && <Button size="small" icon={<RobotOutlined />} onClick={() => handTo([f])}>AI</Button>}
                  {canAct(f.groupId) && f.status === 'open' && <Button size="small" onClick={() => setActing({ row: f, next: 'resolved' })}>{t('markResolved')}</Button>}
                  {canAct(f.groupId) && f.status === 'open' && <Button size="small" onClick={() => setActing({ row: f, next: 'ignored' })}>{t('markIgnored')}</Button>}
                  {canAct(f.groupId) && f.status !== 'open' && <Button size="small" onClick={() => change(f, 'open')}>{t('reopen')}</Button>}
                </TableActions>
              ),
            },
          ]}
        />}
      </FilterCard>
      {commandId && <CommandDetailDrawer id={commandId} onClose={() => setCommandId(null)} />}
      <ResolveModal
        open={!!acting}
        title={`${t(acting?.next === 'ignored' ? 'findingIgnoreTitle' : 'findingResolveTitle')} · ${acting?.row.title ?? ''}`}
        hint={t(acting?.next === 'ignored' ? 'findingIgnoreHint' : 'findingResolveHint')}
        onCancel={() => setActing(null)}
        onSubmit={async note => { if (!await change(acting!.row, acting!.next, note)) throw new Error() }}
      />
    </Page>
  )
}
