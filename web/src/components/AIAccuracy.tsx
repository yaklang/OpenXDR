import { TableCard } from './Page'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, Empty, Flex, Row, Segmented, Skeleton, Table, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { fetchAIAccuracy, type AccuracyCase, type AccuracyRow } from '../api'
import { useI18n } from '../i18n'
import { fmtTime } from './format'
import { LoadError } from './LoadError'

// 样本少于这个数时比例只作参考
const FEW = 20

// 比例连同分子分母一起给：样本只有个位数时，单看百分比会误导
function Rate({ n, d, bad, big }: { n: number; d: number; bad?: boolean; big?: boolean }) {
  if (!d) return <Typography.Text type="secondary" style={big ? { fontSize: 'inherit' } : undefined}>—</Typography.Text>
  return (
    <span>
      <Typography.Text type={bad && n > 0 ? 'danger' : undefined} strong style={big ? { fontSize: 'inherit' } : undefined}>{Math.round((n / d) * 100)}%</Typography.Text>
      <Typography.Text type="secondary" style={{ marginLeft: 6, fontSize: big ? 14 : 12, fontWeight: 400 }}>{n}/{d}</Typography.Text>
    </span>
  )
}

// 研判准确度：拿人工结案衡量 AI 研判，回答「AI 说良性时能不能信」与「AI 报警有多少是白报」
export function AIAccuracy() {
  const { t } = useI18n()
  const [days, setDays] = useState(90)
  const query = useQuery({ queryKey: ['ai-accuracy', days], queryFn: () => fetchAIAccuracy(days) })
  if (query.isError) return <LoadError error={query.error} onRetry={() => query.refetch()} />
  const data = query.data
  const total = data?.total

  const columns = (keyTitle: string, label: (r: AccuracyRow) => React.ReactNode) => [
    { title: keyTitle, key: 'key', ellipsis: true, render: (_: unknown, r: AccuracyRow) => label(r) },
    { title: t('accReviewed'), dataIndex: 'reviewed', width: 90, align: 'right' as const },
    { title: t('accMissRate'), key: 'miss', width: 120, align: 'right' as const, render: (_: unknown, r: AccuracyRow) => <Rate n={r.missed} d={r.aiBenign} bad /> },
    { title: t('accFalseRate'), key: 'false', width: 120, align: 'right' as const, render: (_: unknown, r: AccuracyRow) => <Rate n={r.falseAlarm} d={r.aiAlarm} /> },
    { title: t('accAdopted'), dataIndex: 'adopted', width: 100, align: 'right' as const },
    { title: t('accAuto'), dataIndex: 'auto', width: 90, align: 'right' as const },
  ]
  const cases = (rows: AccuracyCase[] | null | undefined, empty: string) => (
    <Table<AccuracyCase> size="small" scroll={{ x: 640 }} rowKey="id" pagination={false} dataSource={rows ?? []}
      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={empty} /> }}
      columns={[
        { title: t('thTitle'), dataIndex: 'title', ellipsis: true, render: (v, c) => <Link to={`/incidents/${c.id}`}>{v || c.id}</Link> },
        { title: t('thModel'), dataIndex: 'model', width: 150, ellipsis: true, render: v => <span className="mono">{v || '-'}</span> },
        { title: t('thResolvedBy'), dataIndex: 'resolvedBy', width: 100 },
        { title: t('thTime'), dataIndex: 'resolvedAt', width: 170, render: fmtTime },
      ]} />
  )

  return (
    <Flex vertical gap={20}>
      <Flex justify="space-between" align="center" wrap gap={8}>
        <Typography.Text type="secondary" style={{ maxWidth: 820 }}>{t('accHint')}</Typography.Text>
        <Segmented value={days} onChange={v => setDays(v as number)} options={[30, 90, 365].map(n => ({ value: n, label: t('lastDays', { n }) }))} />
      </Flex>
      {!data || !total ? <Card><Skeleton active /></Card> : (
        <>
          {total.reviewed === 0
            ? <Alert type="info" showIcon title={t('accNoSamples')} />
            : total.reviewed < FEW && <Alert type="warning" showIcon title={t('accFewSamples', { n: total.reviewed })} />}
          <Row gutter={[20, 20]}>
            {[
              { label: t('accReviewed'), value: <div className="usage-value">{total.reviewed}</div> },
              { label: t('accMissRate'), hint: t('accMissHint'), value: <div className="usage-value"><Rate n={total.missed} d={total.aiBenign} bad big /></div> },
              { label: t('accFalseRate'), hint: t('accFalseHint'), value: <div className="usage-value"><Rate n={total.falseAlarm} d={total.aiAlarm} big /></div> },
              { label: `${t('accAdopted')} / ${t('accAuto')}`, value: <div className="usage-value">{total.adopted} / {total.auto}</div> },
            ].map(x => (
              <Col key={x.label} xs={12} lg={6}>
                <Card styles={{ body: { padding: '20px 24px' } }} style={{ height: '100%' }}>
                  <Typography.Text type="secondary">{x.label}</Typography.Text>
                  {x.value}
                  {x.hint && <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12, marginTop: 4 }}>{x.hint}</Typography.Text>}
                </Card>
              </Col>
            ))}
          </Row>
          <TableCard title={t('accByModel')}>
            <Table<AccuracyRow> size="small" scroll={{ x: 760 }} rowKey="key" pagination={false} dataSource={data.byModel ?? []}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
              columns={columns(t('thModel'), r => (r.key ? <span className="mono">{r.key}</span> : <Typography.Text type="secondary">{t('accNoModel')}</Typography.Text>))} />
          </TableCard>
          <TableCard title={t('accByRule')}>
            <Table<AccuracyRow> size="small" scroll={{ x: 760 }} rowKey="key" pagination={{ pageSize: 10, hideOnSinglePage: true }} dataSource={data.byRule ?? []}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
              columns={columns(t('thRule'), r => r.title || <span className="mono">{r.key}</span>)} />
          </TableCard>
          <Row gutter={[20, 20]}>
            <Col xs={24} xl={12}><TableCard title={t('accMissed')} style={{ height: '100%' }}>{cases(data.missed, t('accMissedEmpty'))}</TableCard></Col>
            <Col xs={24} xl={12}><TableCard title={t('accFalseAlarms')} style={{ height: '100%' }}>{cases(data.falseAlarms, t('accFalseEmpty'))}</TableCard></Col>
          </Row>
        </>
      )}
    </Flex>
  )
}
