import { useQuery } from '@tanstack/react-query'
import { Input, Select, Space, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'
import { fetchRules, type RuleRow } from '../api'
import { LoadError } from '../components/LoadError'
import { AttackMatrix } from '../components/AttackMatrix'
import { CLASS_KEY, SeverityTag } from '../components/format'
import { FilterCard, Page, STICKY_HEADER } from '../components/Page'
import { useI18n } from '../i18n'

// 检测规则：规则库热重载，这里看到的就是引擎里正在跑的版本；
// "无数据源"提醒运营：规则加载了，但没有采集面供数，纯摆设。
// ATT&CK 矩阵是同一份规则按战术排开，作为第二个标签放在这里
export function RulesPage() {
  const { t } = useI18n()
  const [params, setParams] = useSearchParams()
  // 搜索词放 URL：事件详情里点规则名会带着规则 ID 跳过来
  const q = params.get('q') ?? ''
  const setQ = (v: string) => setParams(p => {
    const next = new URLSearchParams(p)
    if (v) next.set('q', v)
    else next.delete('q')
    return next
  }, { replace: true })
  const [draft, setDraft] = useState(q)
  useEffect(() => setDraft(q), [q])
  const [sev, setSev] = useState(0)
  const [classFilter, setClassFilter] = useState<number>(0)
  const [platformFilter, setPlatformFilter] = useState<string>('')
  const [dataSourceFilter, setDataSourceFilter] = useState<string>('')
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['rules'], queryFn: fetchRules })

  const platforms = useMemo(() => {
    const set = new Set<string>()
    for (const r of data ?? []) if (r.product) set.add(r.product)
    return Array.from(set).sort()
  }, [data])

  const activeQ = (draft || q).trim().toLowerCase()
  const hasFilters = Boolean(activeQ || sev || classFilter || platformFilter || dataSourceFilter)
  const rows = (data ?? []).filter(r =>
    (!activeQ || (r.title + ' ' + r.id + ' ' + (r.author ?? '') + ' ' + (r.source ?? '')).toLowerCase().includes(activeQ)) &&
    (!sev || r.severity === sev) &&
    (!classFilter || r.classUid === classFilter) &&
    (!platformFilter || r.product === platformFilter) &&
    (!dataSourceFilter || (dataSourceFilter === 'ready' ? r.ingested : !r.ingested)),
  )
  const noData = (data ?? []).filter(r => !r.ingested).length

  const list = (
    <FilterCard
      onReset={hasFilters ? () => { setDraft(''); setQ(''); setSev(0); setClassFilter(0); setPlatformFilter(''); setDataSourceFilter('') } : undefined}
      extra={hasFilters && data ? <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total: data.length })}</Typography.Text> : undefined}
      filters={
        <Space wrap>
          <Input.Search allowClear style={{ width: 260, maxWidth: '100%' }} aria-label={t('ruleSearchHint')} value={draft} placeholder={t('ruleSearchHint')} onSearch={v => setQ(v.trim())} onChange={e => { setDraft(e.target.value); if (!e.target.value) setQ('') }} />
          <Select aria-label={t('thSeverity')} style={{ width: 135 }} value={sev} onChange={setSev} options={[{ value: 0, label: t('allSeverities') }, ...[5, 4, 3, 2, 1].map(n => ({ value: n, label: t(`sev${n}` as 'sev1') }))]} />
          <Select aria-label={t('thClass')} style={{ width: 140 }} value={classFilter} onChange={setClassFilter}
            options={[{ value: 0, label: t('allClasses') }, ...Object.entries(CLASS_KEY).map(([k, label]) => ({ value: Number(k), label: t(label) }))]} />
          <Select aria-label={t('thPlatform')} style={{ width: 135 }} value={platformFilter} onChange={setPlatformFilter}
            options={[{ value: '', label: t('allPlatforms') }, ...platforms.map(p => ({ value: p, label: p }))]} />
          <Select aria-label={t('thDataSource')} style={{ width: 155 }} value={dataSourceFilter} onChange={setDataSourceFilter}
            options={[
              { value: '', label: t('allDataSources') },
              { value: 'ready', label: t('dataSourceReady') },
              { value: 'nodata', label: t('noDataSource') },
            ]} />
        </Space>
      }
    >
      {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<RuleRow>
        sticky={STICKY_HEADER}
        scroll={{ x: 900 }}
        size="small"
        rowKey="id"
        loading={isPending}
        dataSource={rows}
        pagination={{ defaultPageSize: 30, showSizeChanger: true, hideOnSinglePage: true }}
        columns={[
          {
            title: t('thRule'), dataIndex: 'title',
            sorter: (a, b) => (a.title || a.id).localeCompare(b.title || b.id),
            render: (v, r) => <><Tooltip title={r.id}><Typography.Text copyable={{ text: r.id, tooltips: [r.id, t('copied')] }}>{v || r.id}</Typography.Text></Tooltip>{r.signal && <Tooltip title={t('ruleSignalHint')}><Tag style={{ marginLeft: 8 }}>{t('ruleSignal')}</Tag></Tooltip>}{r.kind && <Space size={4} wrap style={{ display: 'flex', marginTop: 4 }}><Tag>{t(r.kind === 'event_count' ? 'temporalCount' : r.kind === 'temporal' ? 'temporalUnordered' : 'temporalSequence')}</Tag><Typography.Text type="secondary">{t('temporalRuleWindow', { seconds: r.windowSeconds ?? 0 })}{r.threshold ? ` · ${t('temporalRuleThreshold', { count: r.threshold })}` : ''}</Typography.Text></Space>}{r.author && <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12 }}>{t('ruleBy', { author: r.author })}</Typography.Text>}</>,
          },
          { title: t('thSeverity'), dataIndex: 'severity', width: 95, render: v => <SeverityTag value={v} />, sorter: (a, b) => a.severity - b.severity },
          { title: t('thClass'), dataIndex: 'classUid', width: 115, sorter: (a, b) => a.classUid - b.classUid, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v || t('allClasses')) },
          { title: t('thPlatform'), dataIndex: 'product', width: 115, sorter: (a, b) => (a.product ?? '').localeCompare(b.product ?? ''), render: v => v || '-' },
          { title: t('thDataSource'), width: 190, sorter: (a, b) => Number(a.ingested) - Number(b.ingested), render: (_, r) => (r.ingested ? <Tag>{r.kind ? t('temporalRuleSource') : r.source}</Tag> : <Tag color="warning">{t('noDataSource')}</Tag>) },
        ]}
      />}
    </FilterCard>
  )

  return (
    <Page title={t('navRules')} subtitle={t('rulesSummary', { n: data?.length ?? 0, nodata: noData })}>
      <Tabs
        activeKey={params.get('tab') === 'attack' ? 'attack' : 'list'}
        onChange={k => setParams(k === 'attack' ? { tab: 'attack' } : {}, { replace: true })}
        items={[
          { key: 'list', label: t('rulesList'), children: list },
          { key: 'attack', label: t('navAttack'), children: <AttackMatrix /> },
        ]}
      />
    </Page>
  )
}
