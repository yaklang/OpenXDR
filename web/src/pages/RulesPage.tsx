import { ExperimentOutlined, ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Drawer, Empty, Input, Segmented, Select, Space, Spin, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { backtestRule, fetchRules, type RuleRow } from '../api'
import { AttackMatrix } from '../components/AttackMatrix'
import { EventKind } from '../components/EventKind'
import { eventSummary } from '../components/eventSummary'
import { CLASS_KEY, fmtTime, SeverityTag } from '../components/format'
import { HostLink } from '../components/HostLink'
import { LoadError } from '../components/LoadError'
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
  const [btRule, setBtRule] = useState<RuleRow | null>(null)
  const [btHours, setBtHours] = useState<number>(24)
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['rules'], queryFn: fetchRules })
  const btQuery = useQuery({
    queryKey: ['rule-backtest', btRule?.id, btHours],
    queryFn: () => backtestRule(btRule!.id, btHours),
    enabled: Boolean(btRule && !btRule.kind),
  })

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
          {
            title: '', width: 92, align: 'right',
            render: (_, r) => r.kind ? (
              <Tooltip title={t('ruleBacktestTemporalUnsupported')}>
                <Button size="small" type="text" disabled icon={<ExperimentOutlined />}>{t('ruleBacktestBtn')}</Button>
              </Tooltip>
            ) : (
              <Button size="small" icon={<ExperimentOutlined />} onClick={() => setBtRule(r)}>{t('ruleBacktestBtn')}</Button>
            ),
          },
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
      <Drawer
        open={Boolean(btRule)}
        onClose={() => setBtRule(null)}
        size="large"
        title={btRule ? <Space><ExperimentOutlined /><span>{t('ruleBacktestTitle')}</span><SeverityTag value={btRule.severity} /></Space> : t('ruleBacktestTitle')}
        extra={btRule && (
          <Space>
            <Segmented
              size="small"
              value={btHours}
              onChange={v => setBtHours(Number(v))}
              options={[
                { value: 24, label: t('lastHours', { n: 24 }) },
                { value: 72, label: t('lastHours', { n: 72 }) },
                { value: 168, label: t('lastHours', { n: 168 }) },
              ]}
            />
            <Button size="small" icon={<ReloadOutlined spin={btQuery.isFetching} />} onClick={() => btQuery.refetch()} />
          </Space>
        )}
      >
        {btRule && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(138,180,248,0.06)', border: '1px solid rgba(138,180,248,0.16)' }}>
              <Typography.Text strong style={{ display: 'block', fontSize: 14 }}>{btRule.title || btRule.id}</Typography.Text>
              <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{btRule.id}</Typography.Text>
              <Typography.Paragraph type="secondary" style={{ margin: '6px 0 0', fontSize: 12.5 }}>
                {t('ruleBacktestHint')}
              </Typography.Paragraph>
            </div>

            {btQuery.isPending ? (
              <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>
            ) : btQuery.isError ? (
              <LoadError error={btQuery.error} onRetry={() => btQuery.refetch()} />
            ) : btQuery.data ? (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
                  <div className="stat-tile" style={{ padding: '12px 14px' }}>
                    <div className="label">{t('ruleBacktestScanned')}</div>
                    <div className="num" style={{ fontSize: 22 }}>{btQuery.data.scannedEvents}{btQuery.data.truncated ? '+' : ''}</div>
                  </div>
                  <div className="stat-tile" style={{ padding: '12px 14px' }}>
                    <div className="label">{t('ruleBacktestMatched')}</div>
                    <div className="num" style={{ fontSize: 22, color: btQuery.data.matchedCount > 0 ? '#fdd663' : '#81c995' }}>{btQuery.data.matchedCount}</div>
                  </div>
                  <div className="stat-tile" style={{ padding: '12px 14px' }}>
                    <div className="label">{t('ruleBacktestHosts')}</div>
                    <div className="num" style={{ fontSize: 22 }}>{btQuery.data.hosts.length}</div>
                  </div>
                </div>

                {btQuery.data.truncated && (
                  <Alert type="info" showIcon title={t('ruleBacktestTruncated', { n: btQuery.data.scannedEvents })} />
                )}

                {btQuery.data.hosts.length > 0 && (
                  <div>
                    <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600 }}>
                      {t('ruleBacktestHostDist')}
                    </Typography.Text>
                    <Space size={[6, 6]} wrap>
                      {btQuery.data.hosts.map(h => (
                        <Tag key={h.hostname} variant="filled" color="gold">
                          {h.assetId ? <Link to={`/assets/${h.assetId}`}>{h.hostname}</Link> : h.hostname}
                          <span className="mono" style={{ marginLeft: 6, opacity: 0.85 }}>×{h.count}</span>
                        </Tag>
                      ))}
                    </Space>
                  </div>
                )}

                <div>
                  <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600 }}>
                    {t('ruleBacktestSamples')}
                  </Typography.Text>
                  {btQuery.data.samples.length === 0 ? (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('ruleBacktestZeroHits')} />
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {btQuery.data.samples.map(s => (
                        <div key={s.id} style={{ padding: '10px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <Space size={8} wrap style={{ marginBottom: 4, width: '100%', justifyContent: 'space-between' }}>
                            <Space size={6} wrap>
                              <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{fmtTime(s.ts)}</Typography.Text>
                              <HostLink id={s.assetId ?? null} fallback={s.hostname} />
                              <EventKind classUid={s.classUid} />
                            </Space>
                            {s.assetId && (
                              <Link to={`/events?assetId=${s.assetId}&classUid=${s.classUid}&hours=${btHours}`} style={{ fontSize: 12 }}>
                                {t('pivotEvents')} →
                              </Link>
                            )}
                          </Space>
                          <Typography.Text className="mono" style={{ fontSize: 12.5, wordBreak: 'break-all' }}>
                            {eventSummary(s.classUid, s.raw, t, false) || JSON.stringify(s.raw).slice(0, 180)}
                          </Typography.Text>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            ) : null}
          </div>
        )}
      </Drawer>
    </Page>
  )
}
