import { ApartmentOutlined, FieldTimeOutlined, FilterOutlined, RobotOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'
import { fetchAssets, searchEvents, type EventRow } from '../api'
import { Refreshed } from '../components/Ago'
import { AutomationTag } from '../components/AutomationTag'
import { EventFacts } from '../components/EventFacts'
import { HostLink } from '../components/HostLink'
import { LoadError } from '../components/LoadError'
import { EventAIDrawer } from '../components/EventAIDrawer'
import { EventKind } from '../components/EventKind'
import { eventAction, eventSummary } from '../components/eventSummary'
import { CLASS_KEY, fmtTime } from '../components/format'
import { FilterCard, Page, STICKY_HEADER, WIDE_ONLY, useWideTable } from '../components/Page'
import { useI18n, type MsgKey } from '../i18n'

// 覆盖缺口的人话说明：reason 是后端 eventsCoverage.Reason 的取值
function coverageMessage(reason: string, t: (k: MsgKey) => string): string {
  const key: MsgKey = ({
    hot_keyword_degraded: 'eventsCoverageHotKeyword',
    keyword_not_searched: 'eventsCoverageKeyword',
    no_archive_schema: 'eventsCoverageNoSchema',
    scan_incomplete: 'eventsCoverageScanBudget',
    before_archive: 'eventsCoverageBeforeArchive',
  } as Record<string, MsgKey>)[reason] ?? 'eventsCoverageUnknown'
  return t(key)
}

// 日志检索：告警只是线索，取证要能沿着一个 IP、一段命令行翻出原始遥测
export function EventsPage() {
  const { t } = useI18n()
  // 筛选条件放在 URL 里：刷新不丢，链接发给别人能看到同一份结果
  const [params, setParams] = useSearchParams()
  const filter = {
    q: params.get('q') ?? '',
    source: params.get('source') ?? '',
    classUid: Number(params.get('classUid') ?? 0),
    hours: Number(params.get('hours') ?? 24),
    assetId: params.get('assetId') ?? '',
    from: params.get('from') ?? '',
    to: params.get('to') ?? '',
  }
  const setFilter = (patch: Partial<typeof filter>) => {
    const next = { ...filter, ...patch }
    setParams(Object.fromEntries(Object.entries(next).filter(([k, v]) => v && !(k === 'hours' && v === 24)).map(([k, v]) => [k, String(v)])))
  }
  const [draft, setDraft] = useState(filter.q)
  useEffect(() => setDraft(filter.q), [filter.q])
  const { data, isFetching, isError, error, refetch, dataUpdatedAt } = useQuery({ queryKey: ['events', filter], queryFn: () => searchEvents(filter) })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })
  const wideTable = useWideTable()
  const [asking, setAsking] = useState<EventRow | null>(null)
  // 当前结果里各类别的条数：点一下就只看这一类
  const classCounts = Object.entries((data?.items ?? []).reduce<Record<number, number>>((m, r) => ({ ...m, [r.classUid]: (m[r.classUid] ?? 0) + 1 }), {}))
    .map(([k, n]) => [Number(k), n] as const).sort((a, b) => b[1] - a[1])

  return (
    <Page title={t('navEvents')} subtitle={t('eventsSubtitle')}>
      <FilterCard
        onReset={params.size || draft ? () => { setDraft(''); setParams({}) } : undefined}
        filters={
          <Space wrap>
            <Input.Search
              allowClear
              style={{ width: 360 }}
              placeholder={t('eventSearchHint')}
              value={draft}
              onChange={e => { setDraft(e.target.value); if (!e.target.value) setFilter({ q: '' }) }}
              onSearch={q => setFilter({ q })}
            />
            <Select
              aria-label={t('thHostname')}
              style={{ width: 160 }}
              showSearch
              optionFilterProp="label"
              value={filter.assetId}
              onChange={assetId => setFilter({ assetId })}
              options={[{ value: '', label: t('allHosts') }, ...(assets.data ?? []).map(a => ({ value: a.id, label: a.hostname }))]}
            />
            <Select
              aria-label={t('thClass')}
              style={{ width: 140 }}
              value={filter.classUid}
              onChange={classUid => setFilter({ classUid })}
              options={[{ value: 0, label: t('allClasses') }, ...Object.entries(CLASS_KEY).map(([uid, key]) => ({ value: Number(uid), label: t(key) }))]}
            />
            <Select
              aria-label={t('thSource')}
              style={{ width: 130 }}
              value={filter.source}
              onChange={source => setFilter({ source })}
              options={[{ value: '', label: t('allSources') }, ...['agent', 'sensor', 'syslog', 'suricata'].map(s => ({ value: s, label: s }))]}
            />
            {filter.from ? (
              <Tag closable color="blue" onClose={() => setFilter({ from: '', to: '' })} style={{ padding: '4px 8px' }}>
                {fmtTime(filter.from)} ~ {filter.to ? fmtTime(filter.to).slice(11) : t('now')}
              </Tag>
            ) : <Select
              aria-label={t('thTime')}
              style={{ width: 140 }}
              value={filter.hours}
              onChange={hours => setFilter({ hours })}
              options={[1, 6, 24, 72, 168].map(n => ({ value: n, label: t('lastHours', { n }) }))}
            />}
          </Space>
        }
        extra={<Space wrap><Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} /><Typography.Text type="secondary">{t('eventCount', { n: data ? `${data.items.length}${data.truncated ? '+' : ''}` : 0 })}</Typography.Text></Space>}
      >
        {data?.truncated && <Alert type="info" banner showIcon title={t('listTruncated', { n: data.items.length })} />}
        {/* 覆盖缺口必须说清：零结果时它区分「没有」与「没搜到」；有结果时也如实标注。
            关键词查询不搜冷归档是常态缺口——提示这条历史可在恢复归档后重新搜索，不会自动恢复 */}
        {data?.coverage.reason && (
          <Alert
            type={data.items.length ? 'info' : 'warning'}
            banner
            showIcon
            title={coverageMessage(data.coverage.reason, t)}
            description={data.coverage.reason === 'keyword_not_searched' && data.items.length === 0 ? t('eventsCoverageRestoreHint') : undefined}
          />
        )}
        {(classCounts.length > 1 || filter.classUid !== 0) && (
          <div className="class-chips">
            <button type="button" className={`class-chip${filter.classUid === 0 ? ' active' : ''}`} onClick={() => setFilter({ classUid: 0 })}>{t('allClasses')}</button>
            {classCounts.map(([uid, n]) => (
              <button key={uid} type="button" className={`class-chip${filter.classUid === uid ? ' active' : ''}`} onClick={() => setFilter({ classUid: filter.classUid === uid ? 0 : uid })}>
                <EventKind classUid={uid} /><span className="class-chip-n">{n}</span>
              </button>
            ))}
          </div>
        )}
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<EventRow>
          sticky={STICKY_HEADER}
          scroll={wideTable ? { x: 950 } : undefined}
          size="small"
          rowKey="id"
          loading={isFetching}
          dataSource={data?.items ?? []}
          pagination={{ pageSize: 50, hideOnSinglePage: true }}
          // 点整行展开；展开后可以顺着这条往外翻：只看这台主机，或看同主机前后 5 分钟的全部日志
          // 窄屏省掉展开列与问 AI 列，把宽度留给摘要；点整行展开后两者都在
          expandable={{
            expandRowByClick: true,
            showExpandColumn: wideTable,
            expandedRowRender: r => {
              // 进程 GUID 出现在它自己的启停、子进程、连接与 DNS 事件里：按它全文检索就是这个进程的全部活动
              const guid: string | undefined = (r.raw as { process?: { uid?: string } } | null)?.process?.uid
              return (
                <div className="ev-expand">
                  <Space size={8} wrap>
                    <Button size="small" type="primary" ghost icon={<RobotOutlined />} onClick={() => setAsking(r)}>{t('askAI')}</Button>
                    {r.assetId && r.assetId !== filter.assetId && (
                      <Button size="small" icon={<FilterOutlined />} onClick={() => setFilter({ assetId: r.assetId! })}>{t('pivotHost')}</Button>
                    )}
                    {guid && guid !== filter.q && (
                      <Button size="small" icon={<ApartmentOutlined />} onClick={() => setFilter({ q: guid, classUid: 0, source: '', from: '', to: '', hours: 168 })}>{t('pivotProcess')}</Button>
                    )}
                    <Button size="small" icon={<FieldTimeOutlined />} onClick={() => setFilter({
                      assetId: r.assetId ?? '', q: '', classUid: 0, source: '',
                      from: new Date(Date.parse(r.ts) - 300_000).toISOString(),
                      to: new Date(Date.parse(r.ts) + 300_000).toISOString(),
                    })}>{t('pivotAround')}</Button>
                  </Space>
                  <EventFacts classUid={r.classUid} raw={r.raw} username={r.username} />
                  <details className="ev-raw">
                    <summary>{t('rawEvent')}<Typography.Text copyable={{ text: JSON.stringify(r.raw, null, 2) }} style={{ marginLeft: 8 }} /></summary>
                    <pre className="json-block">{JSON.stringify(r.raw, null, 2)}</pre>
                  </details>
                </div>
              )
            },
          }}
          columns={[
            { title: t('thTime'), dataIndex: 'ts', render: v => (wideTable ? fmtTime(v) : fmtTime(v).slice(11)), width: wideTable ? 170 : 84 },
            { responsive: WIDE_ONLY, title: t('thClass'), dataIndex: 'classUid', width: 110, render: v => <EventKind classUid={v} /> },
            { responsive: WIDE_ONLY, title: t('thHostname'), dataIndex: 'assetId', width: 130, render: v => <HostLink id={v} /> },
            {
              title: t('thSummary'), key: 'summary', ellipsis: { showTitle: false },
              // 动作单独成标签（失败、删除标红），后面是对象；窄屏没有类别列，图标挪到这里
              render: (_, r) => {
                const act = eventAction(r.classUid, r.raw, t)
                const text = eventSummary(r.classUid, r.raw, t, false) || r.connTuple || '-'
                return (
                  <span className="ev-summary">
                    {!wideTable && <EventKind classUid={r.classUid} compact />}
                    {act && <span className={`ev-act ev-act-${act.tone}`}>{act.label}</span>}
                    <AutomationTag value={r.automation} />
                    <Typography.Text className="mono ev-copy" copyable={wideTable && { text, onCopy: e => e?.stopPropagation() }} ellipsis={{ tooltip: { title: text, placement: 'topLeft' } }} style={{ flex: 1, minWidth: 0 }}>
                      {text}
                    </Typography.Text>
                  </span>
                )
              },
            },
            {
              responsive: WIDE_ONLY, title: t('thUser'), dataIndex: 'username', width: 110,
              // 纯数字是宿主机上查不到用户名的 UID，多是容器的映射 UID；不按某个偏移去猜容器里是谁
              render: (v: string | null) => v && /^\d+$/.test(v)
                ? <Tooltip title={t('numericUserHint')}><Typography.Text type="secondary">uid {v}</Typography.Text></Tooltip>
                : v || '-',
            },
            {
              responsive: WIDE_ONLY, title: '', key: 'ask', width: 44,
              render: (_, r) => (
                <Tooltip title={t('askAI')}>
                  <Button type="text" size="small" className="row-actions" aria-label={t('askAI')} icon={<RobotOutlined />}
                    onClick={e => { e.stopPropagation(); setAsking(r) }} />
                </Tooltip>
              ),
            },
          ]}
        />}
      </FilterCard>
      <EventAIDrawer event={asking} onClose={() => setAsking(null)} onAsk={setAsking} />
    </Page>
  )
}
