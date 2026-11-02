import { TableCard } from './Page'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, Empty, Flex, Row, Segmented, Skeleton, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { fetchAIUsage, type AIUsageRow, type AIUsageTop } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { Ago } from './Ago'
import { BarList, StackedColumnChart, compact, useCategorical } from './charts'
import { LoadError } from './LoadError'

// 用途固定顺序，颜色跟着用途走，不随筛选重排
const FEATURES: { key: AIUsageRow['feature']; label: MsgKey }[] = [
  { key: 'chat', label: 'usageChat' },
  { key: 'task', label: 'usageTask' },
  { key: 'triage', label: 'usageTriage' },
  { key: 'annotate', label: 'usageAnnotate' },
  { key: 'explain', label: 'usageExplain' },
]

const tokens = (r: { input: number; output: number }) => r.input + r.output

interface Sum { input: number; output: number; cacheRead: number; calls: number }
const add = (a: Sum, r: Sum): Sum => ({ input: a.input + r.input, output: a.output + r.output, cacheRead: a.cacheRead + r.cacheRead, calls: a.calls + r.calls })
const zero: Sum = { input: 0, output: 0, cacheRead: 0, calls: 0 }

// 最近 n 天的日期列表（本地时区），没有用量的日子也占一根柱子
function lastDays(n: number) {
  const out: string[] = []
  const d = new Date()
  for (let i = n - 1; i >= 0; i--) {
    const x = new Date(d.getFullYear(), d.getMonth(), d.getDate() - i)
    out.push(`${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`)
  }
  return out
}

// AI 用量概览：先回答「一共用了多少、花在哪」，再看每天的走势和最费 token 的会话
export function AIUsageOverview() {
  const { t } = useI18n()
  const colors = useCategorical()
  const [days, setDays] = useState(30)
  const [view, setView] = useState<'chart' | 'table'>('chart')
  const query = useQuery({ queryKey: ['ai-usage', days], queryFn: () => fetchAIUsage(days), refetchInterval: 60_000 })

  if (query.isError) return <LoadError error={query.error} onRetry={() => query.refetch()} />
  const rows = query.data?.rows ?? []
  const total = rows.reduce(add, zero)
  const byFeature = FEATURES.map(f => ({ ...f, sum: rows.filter(r => r.feature === f.key).reduce(add, zero) }))
  const models = Object.values(rows.reduce<Record<string, Sum & { model: string }>>((m, r) => {
    m[r.model] = { model: r.model, ...add(m[r.model] ?? zero, r) }
    return m
  }, {})).sort((a, b) => tokens(b) - tokens(a))
  const dayKeys = lastDays(days)
  const daily = dayKeys.map(day => ({ key: day, values: FEATURES.map(f => rows.filter(r => r.day === day && r.feature === f.key).reduce((s, r) => s + tokens(r), 0)) }))
  const series = FEATURES.map((f, i) => ({ name: t(f.label), color: colors[i] }))
  const step = Math.max(1, Math.ceil(days / 8))

  const tiles = [
    { label: t('usageTotal'), value: compact(tokens(total)) },
    { label: t('usageInput'), value: compact(total.input) },
    { label: t('usageOutput'), value: compact(total.output) },
    { label: t('usageCalls'), value: compact(total.calls) },
  ]

  return (
    <Flex vertical gap={20}>
      <Flex justify="space-between" align="center" wrap gap={8}>
        <Typography.Text type="secondary">{t('usageHint')}</Typography.Text>
        <Segmented value={days} onChange={v => setDays(v as number)} options={[7, 30, 90].map(n => ({ value: n, label: t('lastDays', { n }) }))} />
      </Flex>
      {!query.data ? <Card><Skeleton active /></Card> : (
        <>
          <Row gutter={[20, 20]}>
            {tiles.map(x => (
              <Col key={x.label} xs={12} lg={6}>
                <Card styles={{ body: { padding: '18px 22px' } }}>
                  <Typography.Text type="secondary">{x.label}</Typography.Text>
                  <div className="usage-value">{x.value}</div>
                </Card>
              </Col>
            ))}
          </Row>
          <Row gutter={[20, 20]}>
            <Col xs={24} xl={16}>
              <Card title={t('usageDaily')} style={{ height: '100%' }}
                extra={<Segmented size="small" value={view} onChange={v => setView(v as 'chart' | 'table')} options={[{ value: 'chart', label: t('viewChart') }, { value: 'table', label: t('viewTable') }]} />}>
                {total.calls === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('usageEmpty')} /> : view === 'chart' ? (
                  <StackedColumnChart data={daily} series={series}
                    xLabel={i => (i % step === 0 ? dayKeys[i].slice(5) : null)}
                    tip={i => (
                      <div>
                        <div>{dayKeys[i]}</div>
                        {FEATURES.map((f, j) => daily[i].values[j] > 0 && <div key={f.key}>{t(f.label)}：{daily[i].values[j].toLocaleString()}</div>)}
                      </div>
                    )} />
                ) : (
                  <Table size="small" rowKey="key" pagination={false} scroll={{ x: 640, y: 260 }}
                    dataSource={daily.filter(d => d.values.some(v => v > 0)).reverse()}
                    columns={[
                      { title: t('thDate'), dataIndex: 'key' },
                      ...FEATURES.map((f, j) => ({ title: t(f.label), align: 'right' as const, render: (_: unknown, d: { values: number[] }) => d.values[j].toLocaleString() })),
                    ]} />
                )}
              </Card>
            </Col>
            <Col xs={24} xl={8}>
              <Card title={t('usageByFeature')} style={{ height: '100%' }}>
                <BarList labelWidth="88px" items={byFeature.map((f, i) => ({ key: f.key, label: t(f.label), value: tokens(f.sum), color: colors[i] }))} />
                <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: '16px 0 0' }}>{t('usageFeatureHint')}</Typography.Paragraph>
              </Card>
            </Col>
            <Col xs={24} xl={12}>
              <TableCard title={t('usageByModel')} style={{ height: '100%' }}>
                <Table size="small" scroll={{ x: 520 }} rowKey="model" pagination={false} dataSource={models}
                  locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
                  columns={[
                    { title: t('thModel'), dataIndex: 'model', ellipsis: true, render: v => <span className="mono">{v || '-'}</span> },
                    { title: t('usageCalls'), dataIndex: 'calls', width: 90, align: 'right', render: (v: number) => v.toLocaleString() },
                    { title: t('usageInput'), dataIndex: 'input', width: 80, align: 'right', render: (v: number) => compact(v) },
                    { title: t('usageOutput'), dataIndex: 'output', width: 80, align: 'right', render: (v: number) => compact(v) },
                    { title: t('usageCacheRead'), dataIndex: 'cacheRead', width: 90, align: 'right', render: (v: number) => (v ? compact(v) : '-') },
                  ]} />
              </TableCard>
            </Col>
            <Col xs={24} xl={12}>
              <TableCard title={t('usageTopSessions')} style={{ height: '100%' }}>
                <Table<AIUsageTop> size="small" scroll={{ x: 520 }} rowKey="id" pagination={false} dataSource={query.data.top}
                  locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
                  columns={[
                    {
                      title: t('chatSession'), ellipsis: true,
                      render: (_, s) => <><Link to={`/chat/${s.id}`}>{s.title || t(s.kind === 'task' ? 'taskSession' : 'chatSession')}</Link>{s.kind === 'task' && <Tag style={{ marginLeft: 6 }}>{t('taskSession')}</Tag>}</>,
                    },
                    { title: t('group'), dataIndex: 'group', width: 110, ellipsis: true },
                    { title: t('usageTotal'), dataIndex: 'tokens', width: 90, align: 'right', render: (v: number) => compact(v) },
                    { title: t('thLastActive'), dataIndex: 'lastAt', width: 100, render: v => <Ago iso={v} /> },
                  ]} />
              </TableCard>
            </Col>
          </Row>
        </>
      )}
    </Flex>
  )
}
