import { useQuery, useQueryClient } from '@tanstack/react-query'
import { DownloadOutlined, ImportOutlined, PlusOutlined, RobotOutlined } from '@ant-design/icons'
import { App, Button, Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { assignAsset, fetchAssets, unassignAsset, type Asset } from '../api'
import { useSession } from '../app/session'
import { useCanChat, useHandoff } from '../components/Handoff'
import { ExportAssetsModal } from '../components/ExportAssetsModal'
import { ImportHostsModal } from '../components/ImportHostsModal'
import { LoadError } from '../components/LoadError'
import { AddHostModal } from '../components/AddHostModal'
import { errText, HostStateBadge, hostSeen, hostState } from '../components/format'
import { FilterCard, Page, STICKY_HEADER, WIDE_ONLY, useWideTable } from '../components/Page'
import { useRowLink } from '../components/rowLink'
import { useI18n } from '../i18n'

// 心跳超过 5 分钟视为失联——agent 掉线本身就是值得注意的信号
const UNGROUPED = '__none__'
const STATE_ORDER: Record<ReturnType<typeof hostState>, number> = { silent: 1, stale: 2, imported: 3, online: 4 }

function assetSource(a: Asset): 'agent' | 'sensor' | 'imported' | 'log' {
  if (a.agentId) return 'agent'
  if (a.sensorSeen) return 'sensor'
  if (hostState(a) === 'imported') return 'imported'
  return 'log'
}

export function AssetsPage() {
  const { t } = useI18n()
  const { message, modal } = App.useApp()
  const client = useQueryClient()
  const { groups, isAdmin } = useSession()
  // 搜索与组、状态、来源筛选放 URL：从详情页返回、刷新都还在
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const [draft, setDraft] = useState(q)
  useEffect(() => setDraft(q), [q])
  const groupFilter = params.get('group') ?? ''
  const statusFilter = params.get('status') ?? ''
  const sourceFilter = params.get('source') ?? ''
  const setFilter = (patch: { q?: string; group?: string; status?: string; source?: string }) =>
    setParams(Object.fromEntries(Object.entries({ q, group: groupFilter, status: statusFilter, source: sourceFilter, ...patch }).filter(([, v]) => v)), { replace: true })
  const [adding, setAdding] = useState(false)
  const [importing, setImporting] = useState(false)
  const [exporting, setExporting] = useState(false)
  // 组 admin 才能为本组签发接入令牌
  const canAdd = groups.some(g => g.role === 'admin')
  const { data, isPending, isFetching, isError, error, dataUpdatedAt, refetch } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 30_000 })

  const wideTable = useWideTable()
  const rowLink = useRowLink<Asset>(a => `/assets/${a.id}`)
  // 批量：多台同组主机一起交给 AI 巡检；管理员可以一起移组
  const [selected, setSelected] = useState<string[]>([])
  const canChat = useCanChat()
  const handoff = useHandoff()
  const imported = (a: Asset) => hostState(a) === 'imported'
  const activeQ = (draft || q).trim().toLowerCase()
  const hasFilters = Boolean(activeQ || groupFilter || statusFilter || sourceFilter)
  const rows = (data ?? []).filter(a =>
    (!activeQ || a.hostname.toLowerCase().includes(activeQ) || (a.osDisplay ?? a.os ?? '').toLowerCase().includes(activeQ) || a.ipAddrs?.some(ip => ip.toLowerCase().includes(activeQ))) &&
    (!groupFilter || (groupFilter === UNGROUPED ? !a.groupId : a.groupId === groupFilter)) &&
    (!statusFilter || hostState(a) === statusFilter) &&
    (!sourceFilter || (sourceFilter === 'agent' ? Boolean(a.agentId) : sourceFilter === 'sensor' ? Boolean(a.sensorSeen) : assetSource(a) === sourceFilter)),
  )

  // 归组只有全局 admin 能改：一台主机只属于一个组，选新组即离开旧组，原组成员当场失去权限，先确认
  const move = (a: Asset, target: string) => modal.confirm({
    title: t('regroupConfirm', { host: a.hostname }),
    content: a.groupId ? t('regroupLeave', { from: groups.find(g => g.id === a.groupId)?.name ?? '-' }) : undefined,
    onOk: () => doMove(a, target),
  })
  const doMove = async (a: Asset, target: string) => {
    try {
      if (target === UNGROUPED) await unassignAsset(a.groupId!, a.id)
      else await assignAsset(target, a.id)
      await client.invalidateQueries({ queryKey: ['assets'] })
      client.invalidateQueries({ queryKey: ['groups'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const picked = (data ?? []).filter(a => selected.includes(a.id))
  const pickedGroup = picked[0]?.groupId
  const sameGroup = picked.length > 0 && picked.every(a => a.groupId && a.groupId === pickedGroup)
  const handTo = () => handoff.start(pickedGroup!, [], t('handoffHostsTitle', { n: picked.length }),
    t('handoffHostsPrompt', { hosts: picked.map(a => `${a.hostname} (${a.id})`).join(', ') }))
  const moveMany = (target: string) => modal.confirm({
    title: t('regroupManyConfirm', { n: picked.length }),
    content: picked.some(a => a.groupId) ? t('regroupLeaveMany') : undefined,
    onOk: async () => {
      for (const a of picked) if ((a.groupId ?? UNGROUPED) !== target) await doMove(a, target)
      setSelected([])
    },
  })

  const groupOptions = [{ value: UNGROUPED, label: t('ungrouped') }, ...groups.map(g => ({ value: g.id, label: g.name }))]
  const total = data?.length ?? 0
  const up = (data ?? []).filter(a => hostState(a) === 'online').length

  return (
    <Page title={t('navAssets')} subtitle={t('assetsSummary', { total, online: up })}
      extra={<Space wrap><Button icon={<DownloadOutlined />} onClick={() => setExporting(true)}>{t('exportAssets')}</Button>{canAdd && <><Button icon={<ImportOutlined aria-hidden />} onClick={() => setImporting(true)}>{t('hostImport')}</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding(true)}>{t('addHost')}</Button></>}</Space>}>
      <ExportAssetsModal open={exporting} onClose={() => setExporting(false)} ids={selected} q={q}
        groupId={groupFilter === UNGROUPED ? 'ungrouped' : groupFilter}
        groupName={groupFilter ? groupOptions.find(g => g.value === groupFilter)?.label ?? groupFilter : t('allGroups')} />
      <ImportHostsModal open={importing} onClose={() => setImporting(false)} />
      <AddHostModal open={adding} onClose={() => setAdding(false)} />
      <FilterCard
        onReset={hasFilters ? () => { setDraft(''); setParams({}, { replace: true }) } : undefined}
        extra={(
          <Space wrap>
            {hasFilters && <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total })}</Typography.Text>}
            <Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />
            {selected.length > 0 && (
              <>
                <Typography.Text type="secondary">{t('batchSelected', { n: selected.length })}</Typography.Text>
                <Tooltip title={!sameGroup ? t('handoffSameGroup') : picked.length > 10 ? t('handoffMax') : undefined}>
                  <Button size="small" type="primary" icon={<RobotOutlined />} loading={handoff.busy}
                    disabled={!sameGroup || picked.length > 10 || !canChat(pickedGroup)} onClick={handTo}>{t('handoffToAI')}</Button>
                </Tooltip>
                {isAdmin && <Select size="small" style={{ width: 160 }} placeholder={t('moveToGroup')} value={null} options={groupOptions} onChange={moveMany} />}
              </>
            )}
          </Space>
        )}
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 250 }} placeholder={t('assetSearchHint')} value={draft} onSearch={v => setFilter({ q: v })} onChange={e => { setDraft(e.target.value); if (!e.target.value) setFilter({ q: '' }) }} />
            <Select showSearch optionFilterProp="label" aria-label={t('group')} style={{ width: 170 }} value={groupFilter} onChange={v => setFilter({ group: v })} options={[{ value: '', label: t('allGroups') }, ...groupOptions]} />
            <Select aria-label={t('thStatus')} style={{ width: 140 }} value={statusFilter} onChange={v => setFilter({ status: v })}
              options={[
                { value: '', label: t('allStatuses') },
                { value: 'online', label: t('online') },
                { value: 'stale', label: t('stale') },
                { value: 'silent', label: t('silent') },
                { value: 'imported', label: t('hostNotEnrolled') },
              ]}
            />
            <Select aria-label={t('thSource')} style={{ width: 140 }} value={sourceFilter} onChange={v => setFilter({ source: v })}
              options={[
                { value: '', label: t('allSources') },
                { value: 'agent', label: 'Agent' },
                { value: 'sensor', label: 'Sensor' },
                { value: 'imported', label: t('hostImportedSource') },
                { value: 'log', label: t('sourceLog') },
              ]}
            />
          </Space>
        }
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<Asset>
          sticky={STICKY_HEADER}
          scroll={wideTable ? { x: 1100 } : undefined}
          locale={{ emptyText: <EmptyHint title={t(hasFilters ? 'noMatch' : 'noAssets')} hint={hasFilters ? undefined : t('noAssetsHint')} /> }}
          rowKey="id"
          rowClassName="row-link"
          onRow={rowLink}
          rowSelection={{ selectedRowKeys: selected, onChange: keys => setSelected(keys as string[]) }}
          loading={isPending}
          dataSource={rows}
          pagination={{ defaultPageSize: 20, showSizeChanger: true, hideOnSinglePage: true }}
          columns={[
            {
              title: t('thStatus'), width: 110,
              sorter: (a, b) => STATE_ORDER[hostState(a)] - STATE_ORDER[hostState(b)],
              // 已发过失联通知的标红：这是要人去处理的，不只是暂时没数据
              render: (_, a) => <HostStateBadge asset={a} />,
            },
            { title: t('thHostname'), dataIndex: 'hostname', sorter: (a, b) => a.hostname.localeCompare(b.hostname), render: (v, a) => <Link to={`/assets/${a.id}`}>{v}</Link> },
            {
              responsive: WIDE_ONLY, title: 'OS', dataIndex: 'os', width: 150,
              sorter: (a, b) => (a.osDisplay ?? a.os ?? '').localeCompare(b.osDisplay ?? b.os ?? ''),
              render: (_: unknown, a: Asset) => a.osDisplay ?? a.os ?? '-',
            },
            {
              responsive: WIDE_ONLY, title: t('thIP'), dataIndex: 'ipAddrs',
              sorter: (a, b) => (a.ipAddrs?.[0] ?? '').localeCompare(b.ipAddrs?.[0] ?? ''),
              render: v => v?.length ? <Typography.Text className="mono" copyable={{ text: v.join(', ') }}>{v.join(', ')}</Typography.Text> : '-',
            },
            {
              responsive: WIDE_ONLY, title: t('group'), dataIndex: 'groupId', width: 200,
              sorter: (a, b) => (groups.find(g => g.id === a.groupId)?.name ?? '').localeCompare(groups.find(g => g.id === b.groupId)?.name ?? ''),
              render: (v, a) => isAdmin
                ? <Select size="small" style={{ width: 170 }} value={v ?? UNGROUPED} options={groupOptions} onChange={g => move(a, g)} />
                : groups.find(g => g.id === v)?.name ?? <Tag>{t('ungrouped')}</Tag>,
            },
            {
              responsive: WIDE_ONLY, title: t('thSource'), dataIndex: 'agentId', width: 140,
              sorter: (a, b) => assetSource(a).localeCompare(assetSource(b)),
              render: (v, a) => v || a.sensorSeen ? <Space size={4}>{v && <Tag>agent</Tag>}{a.sensorSeen && <Tag>sensor</Tag>}</Space> : <Tag>{t(imported(a) ? 'hostImportedSource' : 'sourceLog')}</Tag>,
            },
            { title: t('thLastSeen'), dataIndex: 'lastSeen', width: wideTable ? 180 : 120, render: (_, a) => imported(a) ? '—' : <Ago iso={hostSeen(a)} />, sorter: (a, b) => hostSeen(a).localeCompare(hostSeen(b)) },
          ]}
        />}
      </FilterCard>
    </Page>
  )
}
