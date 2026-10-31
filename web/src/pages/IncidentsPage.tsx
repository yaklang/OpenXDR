import { TableActions } from '../components/TableActions'
import { RobotOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Input, Segmented, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { fetchIncidentGroups, fetchIncidents, resolveIncidents, type IncidentSummary } from '../api'
import { useCanAct, useSession } from '../app/session'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { useCanChat, useHandoff } from '../components/Handoff'
import { IncidentGroupTable, VerdictBadge } from '../components/IncidentGroupTable'
import { saveQueue } from '../components/incidentQueue'
import { useRowLink } from '../components/rowLink'
import { useFlash } from '../components/useFlash'
import { LoadError } from '../components/LoadError'
import { ResolveModal } from '../components/ResolveModal'
import { agreesWithAI, proposalNote, verdictStatus } from '../components/verdict'
import { INCIDENT_STATUSES, IncidentStatusTag, SeverityTag, errText, incidentStatusKey } from '../components/format'
import { FilterCard, Page, STICKY_HEADER, WIDE_ONLY, useWideTable } from '../components/Page'
import { useI18n } from '../i18n'

const PAGE_SIZE = 50
const done = (r: IncidentSummary) => r.status === 'closed' || r.status === 'false_positive'
const malicious = (r: IncidentSummary) => r.aiVerdict?.verdict === 'malicious'
// 归并视图只看未结案的两种口径
const GROUPABLE = ['review', 'unresolved']

type Resolving = { status: 'closed' | 'false_positive'; rows: IncidentSummary[] }

// 安全事件：告警经去重与关联后的产物，"一万条进三个出"的那三个。默认看未结案的，后端分页；
// 「按规则归并」把同规则同主机反复出现的事件归成一组，整组结案
export function IncidentsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups } = useSession()
  const canAct = useCanAct()
  const [params, setParams] = useSearchParams()
  const view = params.get('view') === 'groups' ? 'groups' : 'list'
  const rawStatus = params.get('status') ?? 'review'
  const status = view === 'groups' && !GROUPABLE.includes(rawStatus) ? 'review' : rawStatus
  const requestedPage = Number(params.get('page') ?? 1)
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 && requestedPage <= Math.floor(Number.MAX_SAFE_INTEGER / PAGE_SIZE) ? requestedPage : 1
  const [q, setQ] = useState('')
  const [sevFilter, setSevFilter] = useState(0)
  const [verdictFilter, setVerdictFilter] = useState('')
  const [selectedKeys, setSelected] = useState<string[]>([])
  const [resolving, setResolving] = useState<Resolving | null>(null)
  const [confirmMalicious, setConfirmMalicious] = useState(false)
  const query = useQuery({
    queryKey: ['incidents', status, page],
    queryFn: () => fetchIncidents({ status: status === 'all' ? undefined : status, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
    refetchInterval: 10_000,
    enabled: view === 'list',
  })
  const grouped = useQuery({
    queryKey: ['incidents', 'groups', status],
    queryFn: () => fetchIncidentGroups(status),
    refetchInterval: 10_000,
    enabled: view === 'groups',
  })
  useEffect(() => {
    if (view !== 'list' || !query.isSuccess || query.isFetching || query.data.total === undefined) return
    const lastPage = Math.max(1, Math.ceil(query.data.total / PAGE_SIZE))
    if (page > lastPage) setParams(prev => {
      const next = new URLSearchParams(prev)
      next.set('page', String(lastPage))
      return next
    }, { replace: true })
  }, [view, query.data?.total, query.isSuccess, query.isFetching, page, setParams])

  const activeQ = q.trim().toLowerCase()
  const hasClientFilter = Boolean(activeQ || sevFilter || verdictFilter)
  const allRows = query.data?.items ?? []
  const rows = useMemo(() => allRows.filter(r =>
    (!sevFilter || r.severity === sevFilter) &&
    (!verdictFilter || (verdictFilter === 'none' ? !r.aiVerdict?.verdict : r.aiVerdict?.verdict === verdictFilter)) &&
    (!activeQ || (r.title ?? '').toLowerCase().includes(activeQ) || r.id.toLowerCase().includes(activeQ))
  ), [allRows, sevFilter, verdictFilter, activeQ])

  const filteredGroups = useMemo(() => (grouped.data?.items ?? []).filter(g =>
    (!sevFilter || g.severity === sevFilter) &&
    (!activeQ || (g.ruleTitle ?? '').toLowerCase().includes(activeQ) || g.ruleId.toLowerCase().includes(activeQ) || (g.hostname ?? '').toLowerCase().includes(activeQ))
  ), [grouped.data?.items, sevFilter, activeQ])

  const actable = (r: IncidentSummary) => !done(r) && canAct(r.groupId)
  const selected = rows.filter(r => selectedKeys.includes(r.id) && actable(r)).map(r => r.id)
  useEffect(() => { setSelected([]); setResolving(null) }, [status, page, view])
  useEffect(() => { if (query.data) saveQueue(query.data.items) }, [query.data])
  const canChat = useCanChat()
  const wideTable = useWideTable()
  const rowLink = useRowLink<IncidentSummary>(r => `/incidents/${r.id}`)
  const flash = useFlash(query.data?.items, r => r.id, r => `${r.status}|${r.aiVerdict?.verdict}|${r.alertCount}|${r.severity}`, `${status}|${page}`)
  const handoff = useHandoff()
  // 多选交给 AI：一个会话属于一个组，选中的必须同组
  const picked = rows.filter(r => selected.includes(r.id))
  const pickedGroup = picked[0]?.groupId
  const sameGroup = picked.length > 0 && picked.every(r => r.groupId === pickedGroup)
  const handTo = (list: IncidentSummary[]) => handoff.start(list[0].groupId!, list.map(r => `incident:${r.id}`),
    list.length === 1 ? t('handoffIncidentTitle', { title: list[0].title ?? list[0].id }) : t('handoffIncidentsTitle', { n: list.length }),
    t('handoffIncidentPrompt'))
  const anyActable = rows.some(actable)

  // 换筛选、视图或翻页就清掉勾选，批量操作只作用于看得见的行
  const go = (next: { status?: string; page?: number; view?: string }) => {
    setSelected([])
    const v = next.view ?? view
    let s = next.status ?? status
    if (v === 'groups' && !GROUPABLE.includes(s)) s = 'review'
    setParams({ ...(v === 'groups' && { view: v }), ...(s !== 'review' && { status: s }), ...((next.page ?? 1) > 1 && { page: String(next.page) }) })
  }

  // 按 AI 研判结案：每条按自己的研判结论关（良性 → 误报，恶意或可疑 → 属实），不写理由、不弹窗；没研判的不动。
  // 按结论分成至多两批走批量接口，每批整批成功或整批不动
  const adoptable = picked.filter(r => verdictStatus(r.aiVerdict))
  const [adopting, setAdopting] = useState(false)
  const adoptVerdicts = async () => {
    setAdopting(true)
    const parts = (['false_positive', 'closed'] as const)
      .map(s => ({ s, ids: adoptable.filter(r => verdictStatus(r.aiVerdict) === s).map(r => r.id) }))
      .filter(p => p.ids.length)
    const results = await Promise.allSettled(parts.map(p => resolveIncidents(p.ids, p.s, '')))
    setAdopting(false)
    const failed = parts.filter((_, i) => results[i].status === 'rejected').flatMap(p => p.ids)
    client.invalidateQueries({ queryKey: ['incidents'] })
    const closed = results.reduce((n, r) => n + (r.status === 'fulfilled' ? r.value : 0), 0)
    if (closed) message.success(t('batchDone', { n: closed }))
    setSelected(failed)
    if (failed.length) {
      const reason = (results.find(r => r.status === 'rejected') as PromiseRejectedResult).reason
      message.error(t('batchFailed', { n: failed.length, err: errText(reason, t) }))
    }
  }

  const startResolve = (next: Resolving['status'], list: IncidentSummary[]) => {
    setConfirmMalicious(false)
    setResolving({ status: next, rows: list })
  }
  // 批量按误报结案时，AI 判恶意的默认留下不关，勾选确认才一起关；单条是人点名的，照常处理
  const maliciousRows = resolving?.status === 'false_positive' && resolving.rows.length > 1 ? resolving.rows.filter(malicious) : []
  const targets = resolving?.rows.filter(r => confirmMalicious || !maliciousRows.includes(r)) ?? []
  const prefill = proposalNote(resolving?.rows ?? [], resolving?.status)

  // 一次请求整批结案：组内权限、逐条审计与人工案例回喂照旧。失败时弹窗不关，备注不丢
  const batch = async (note: string) => {
    if (!resolving) return
    if (!targets.length) {
      message.warning(t('batchNothingLeft'))
      throw new Error('nothing left')
    }
    try {
      const n = await resolveIncidents(targets.map(r => r.id), resolving.status, note, resolving.rows.length === 1 || confirmMalicious)
      message.success(t('batchDone', { n }))
    } catch (e) {
      message.error(t('batchFailed', { n: targets.length, err: errText(e, t) }))
      throw e
    } finally {
      client.invalidateQueries({ queryKey: ['incidents'] })
    }
    setSelected(keys => keys.filter(id => !targets.some(r => r.id === id)))
    setResolving(null)
  }

  return (
    <Page title={t('navIncidents')} subtitle={t('incidentsSubtitle')}>
      <FilterCard
        onReset={hasClientFilter ? () => { setQ(''); setSevFilter(0); setVerdictFilter('') } : undefined}
        extra={(
          <Space wrap>
            {view === 'groups'
              ? <Refreshed at={grouped.dataUpdatedAt} fetching={grouped.isFetching} onRefresh={() => grouped.refetch()} />
              : <Refreshed at={query.dataUpdatedAt} fetching={query.isFetching} onRefresh={() => query.refetch()} />}
            {view === 'list' && anyActable && <Button size="small" onClick={() => setSelected(rows.filter(r => actable(r) && r.aiVerdict?.verdict === 'benign').map(r => r.id))}>{t('selectBenign')}</Button>}
            {view === 'list' && selected.length > 0 && (
              <>
                <Typography.Text type="secondary">{t('batchSelected', { n: selected.length })}</Typography.Text>
                <Tooltip title={!sameGroup ? t('handoffSameGroup') : picked.length > 10 ? t('handoffMax') : undefined}>
                  <Button size="small" type="primary" icon={<RobotOutlined />} loading={handoff.busy}
                    disabled={!sameGroup || picked.length > 10 || !canChat(pickedGroup)} onClick={() => handTo(picked)}>{t('handoffToAI')}</Button>
                </Tooltip>
                {adoptable.length > 0 && (
                  <Button size="small" type="primary" ghost loading={adopting} onClick={adoptVerdicts}>{t('adoptVerdicts', { n: adoptable.length })}</Button>
                )}
                <Button size="small" onClick={() => startResolve('closed', picked)}>{t('markTrue')}</Button>
                <Button size="small" danger onClick={() => startResolve('false_positive', picked)}>{t('markFp')}</Button>
              </>
            )}
          </Space>
        )}
        filters={
          <Space wrap>
            <Segmented
              value={view}
              onChange={v => go({ view: String(v) })}
              options={[{ value: 'list', label: t('viewList') }, { value: 'groups', label: t('viewGroups') }]}
            />
            <Segmented
              value={status}
              onChange={v => go({ status: String(v) })}
              options={[
                { value: 'review', label: t('statusReview') },
                { value: 'unresolved', label: t('statusUnresolved') },
                ...(view === 'list' ? [
                  ...INCIDENT_STATUSES.map(s => ({ value: s, label: t(incidentStatusKey(s)!) })),
                  { value: 'all', label: t('all') },
                ] : []),
              ]}
            />
            <Input.Search allowClear style={{ width: 220 }} placeholder={t('searchIncidents')} value={q} onChange={e => setQ(e.target.value)} />
            <Select aria-label={t('thSeverity')} style={{ width: 130 }} value={sevFilter} onChange={setSevFilter}
              options={[{ value: 0, label: t('allSeverities') }, ...[5, 4, 3, 2, 1].map(n => ({ value: n, label: t(`sev${n}` as 'sev1') }))]} />
            {view === 'list' && (
              <Select aria-label={t('thVerdict')} style={{ width: 135 }} value={verdictFilter} onChange={setVerdictFilter}
                options={[
                  { value: '', label: t('allVerdicts') },
                  { value: 'malicious', label: t('verdictMalicious') },
                  { value: 'suspicious', label: t('verdictSuspicious') },
                  { value: 'benign', label: t('verdictBenign') },
                  { value: 'none', label: t('verdictNone') },
                ]}
              />
            )}
          </Space>
        }
      >
        {view === 'groups' ? (grouped.isError ? <LoadError error={grouped.error} onRetry={() => grouped.refetch()} /> : (
          <>
            {grouped.data?.truncated && <Alert type="info" showIcon title={t('groupsTruncated', { n: grouped.data.total ?? 0 })} style={{ margin: 12 }} />}
            <IncidentGroupTable
              groups={filteredGroups}
              loading={grouped.isPending}
              emptyText={<EmptyHint title={t(hasClientFilter ? 'noMatch' : status === 'review' ? 'noReview' : 'noUnresolved')} hint={hasClientFilter ? undefined : t('noUnresolvedHint')} />}
              actable={actable}
              onResolve={startResolve}
            />
          </>
        )) : query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : (
          <Table<IncidentSummary>
            sticky={STICKY_HEADER}
            scroll={wideTable ? { x: 1100 } : undefined}
            rowKey="id"
            rowClassName={r => (flash.has(r.id) ? 'row-link row-flash' : 'row-link')}
            onRow={rowLink}
            loading={query.isPending}
            dataSource={rows}
            locale={{ emptyText: <EmptyHint title={t(hasClientFilter ? 'noMatch' : status === 'review' ? 'noReview' : status === 'unresolved' ? 'noUnresolved' : 'noIncidents')} hint={!hasClientFilter && (status === 'review' || status === 'unresolved') ? t('noUnresolvedHint') : undefined} /> }}
            pagination={{
              current: page, pageSize: PAGE_SIZE, total: hasClientFilter ? rows.length : (query.data?.total ?? rows.length),
              hideOnSinglePage: true, showSizeChanger: false, onChange: p => go({ page: p }),
              showTotal: n => t('totalCount', { n }),
            }}
            rowSelection={anyActable ? {
              selectedRowKeys: selected,
              onChange: keys => setSelected(keys as string[]),
              getCheckboxProps: r => ({ disabled: !actable(r) }),
            } : undefined}
            columns={[
              { title: t('thSeverity'), dataIndex: 'severity', width: 95, sorter: (a, b) => a.severity - b.severity, render: v => <SeverityTag value={v} /> },
              { title: t('thTitle'), dataIndex: 'title', ellipsis: wideTable, sorter: (a, b) => (a.title ?? a.id).localeCompare(b.title ?? b.id), render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
              {
                responsive: WIDE_ONLY, title: t('group'), dataIndex: 'groupId', width: 140, ellipsis: true,
                sorter: (a, b) => (groups.find(g => g.id === a.groupId)?.name ?? '').localeCompare(groups.find(g => g.id === b.groupId)?.name ?? ''),
                render: v => groups.find(g => g.id === v)?.name ?? '-',
              },
              {
                title: t('thStatus'), dataIndex: 'status', width: 130,
                sorter: (a, b) => a.status.localeCompare(b.status),
                render: (v, r) => <Space size={4} wrap><IncidentStatusTag value={v} retriage={r.retriage} triageStartedAt={r.triageStartedAt} />{r.closureProposal && <Tag color="purple" variant="filled">{t('proposalTag')}</Tag>}</Space>,
              },
              {
                responsive: WIDE_ONLY, title: t('thVerdict'), width: 150,
                sorter: (a, b) => (a.aiVerdict?.verdict ?? '').localeCompare(b.aiVerdict?.verdict ?? ''),
                render: (_, r) => <VerdictBadge row={r} />,
              },
              { responsive: WIDE_ONLY, title: t('thAlerts'), dataIndex: 'alertCount', width: 85, align: 'right', sorter: (a, b) => a.alertCount - b.alertCount },
              { responsive: WIDE_ONLY, title: t('thCreatedAt'), dataIndex: 'createdAt', width: 115, sorter: (a, b) => a.createdAt.localeCompare(b.createdAt), render: v => <Ago iso={v} /> },
              ...(anyActable ? [{
                // 三个链接按钮（AI、确认属实、误报）带内边距约 220px，给少了最后一个会被裁掉
                responsive: WIDE_ONLY, title: '', width: 230,
                // 单条处理不用先勾选：直接点，弹窗写结论
                render: (_: unknown, r: IncidentSummary) => actable(r) && (
                  <TableActions className="row-actions">
                    {canChat(r.groupId) && <Button type="link" size="small" icon={<RobotOutlined />} onClick={() => handTo([r])}>AI</Button>}
                    <Button type="link" size="small" onClick={() => startResolve('closed', [r])}>{t('markTrue')}</Button>
                    <Button type="link" size="small" danger onClick={() => startResolve('false_positive', [r])}>{t('markFpShort')}</Button>
                  </TableActions>
                ),
              }] : []),
            ]}
          />
        )}
      </FilterCard>
      <ResolveModal
        open={!!resolving}
        title={`${t(resolving?.status === 'closed' ? 'resolveClosedTitle' : 'resolveFpTitle')} · ${t('batchSelected', { n: targets.length })}`}
        hint={t('resolveHint')}
        initialNote={prefill}
        optional={targets.length > 0 && targets.every(r => agreesWithAI(r.aiVerdict, resolving?.status ?? null))}
        contradicts={targets.some(r => verdictStatus(r.aiVerdict) && !agreesWithAI(r.aiVerdict, resolving?.status ?? null))}
        onCancel={() => setResolving(null)}
        onSubmit={batch}
      >
        {maliciousRows.length > 0 && (
          <Alert type="error" showIcon style={{ marginBottom: 16 }} title={t('batchMalicious', { n: maliciousRows.length })}
            description={<Checkbox checked={confirmMalicious} onChange={e => setConfirmMalicious(e.target.checked)}>{t('batchMaliciousConfirm', { n: maliciousRows.length })}</Checkbox>} />
        )}
        {prefill && (resolving?.rows.length ?? 0) > 1 && <Alert type="info" showIcon style={{ marginBottom: 16 }} title={t('batchProposalPrefilled')} />}
      </ResolveModal>
    </Page>
  )
}
