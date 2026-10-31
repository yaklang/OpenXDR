import { TriageHistory } from '../components/TriageHistory'
import { ArrowLeftOutlined, DownOutlined, DownloadOutlined, EllipsisOutlined, RobotOutlined, UpOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Col, Descriptions, Dropdown, Result, Row, Segmented, Skeleton, Space, Table, Timeline, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { HttpError, dismissClosureProposal, downloadReport, fetchIncident, setIncidentStatus, type AlertRow } from '../api'
import { useCanActIn, useSession } from '../app/session'
import { useRemember } from '../app/recent'
import { useKeys } from '../app/shortcuts'
import { AutomationTag } from '../components/AutomationTag'
import { useCanChat, useHandoff } from '../components/Handoff'
import { HostLink } from '../components/HostLink'
import { IncidentGraph } from '../components/IncidentGraph'
import { neighbors, type QueueItem } from '../components/incidentQueue'
import { LoadError } from '../components/LoadError'
import { Page, useWideTable } from '../components/Page'
import { ResponsePanel } from '../components/ResponsePanel'
import { ResolveModal } from '../components/ResolveModal'
import { agreesWithAI, verdictStatus } from '../components/verdict'
import { SuppressModal } from '../components/SuppressModal'
import { TemporalRuleAtAlert } from '../components/TemporalRuleAtAlert'
import { VerdictCard } from '../components/VerdictCard'
import { IncidentStatusTag, SeverityTag, fmtTime, errText } from '../components/format'
import { ExternalTickets } from '../components/ExternalTickets'
import { useI18n } from '../i18n'

// 告警里最能说明发生了什么的那一项：命令行 / 文件路径 / 连接目标
function evidence(raw: unknown): string {
  const r = (raw ?? {}) as Record<string, any>
  const dst = r.dst_endpoint?.ip ? `→ ${r.dst_endpoint.ip}${r.dst_endpoint.port ? ':' + r.dst_endpoint.port : ''}` : ''
  return r.process?.cmd_line || r.file?.path || dst || r.message || ''
}

// 告警按时间排开：每条带级别、规则与关键证据，读起来就是一条攻击经过
function AlertTimeline({ alerts }: { alerts: AlertRow[] }) {
  const { t } = useI18n()
  const sevColor = ['', 'gray', 'blue', 'gold', 'orange', 'red']
  return (
    <Timeline
      items={[...alerts].sort((a, b) => a.ts.localeCompare(b.ts)).map(a => ({
        key: a.id,
        color: sevColor[a.severity] ?? 'gray',
        content: (
          <div style={{ paddingBottom: 4 }}>
            <Space size={8} wrap>
              <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{fmtTime(a.ts).slice(11)}</Typography.Text>
              <SeverityTag value={a.severity} />
              <Link to={`/rules?q=${encodeURIComponent(a.ruleId)}`}><Typography.Text strong>{a.ruleTitle ?? a.ruleId}</Typography.Text></Link>
              {a.count > 1 && <Typography.Text type="secondary">×{a.count}</Typography.Text>}
              {a.ruleAuthor && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('ruleBy', { author: a.ruleAuthor })}</Typography.Text>}
              <AutomationTag value={a.automation} />
            </Space>
            {a.detail && <Typography.Paragraph type="secondary" style={{ margin: '4px 0 0', fontSize: 13 }}>{a.detail}</Typography.Paragraph>}
            {evidence(a.event) && <div className="mono timeline-evidence">{evidence(a.event)}</div>}
          </div>
        ),
      }))}
    />
  )
}

// 侧栏队列：来时列表里的前后几条，当前这条高亮，点一下切过去；和 J / K 是同一份顺序
function QueueCard({ items, index }: { items: QueueItem[]; index: number }) {
  const { t } = useI18n()
  const from = Math.max(0, Math.min(index - 3, items.length - 7))
  return (
    <Card title={t('queueTitle')} size="small" extra={<Typography.Text type="secondary">{index + 1} / {items.length}</Typography.Text>}
      styles={{ body: { padding: '12px 16px' } }}>
      {items.slice(from, from + 7).map((q, i) => {
        const body = <><SeverityTag value={q.severity} /><Typography.Text ellipsis style={{ flex: 1 }}>{q.title ?? q.id}</Typography.Text></>
        return from + i === index
          ? <div key={q.id} className="queue-row queue-current" aria-current="page">{body}</div>
          : <Link key={q.id} to={`/incidents/${q.id}`} className="queue-row">{body}</Link>
      })}
      <Typography.Text type="secondary" className="queue-hint"><kbd>J</kbd><kbd>K</kbd> {t('queueHint')}</Typography.Text>
    </Card>
  )
}

export function IncidentDetailPage() {
  const { t } = useI18n()
  const { id } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { groups } = useSession()
  const [suppressing, setSuppressing] = useState(false)
  const [resolving, setResolving] = useState<'closed' | 'false_positive' | null>(null)
  // 采纳 AI 结案建议：带着它的说明打开结案弹窗，人确认后才结案
  const [adopting, setAdopting] = useState(false)
  const [alertView, setAlertView] = useState<'table' | 'timeline'>('timeline')
  const { data: inc, isPending, error, refetch } = useQuery({ queryKey: ['incident', id], queryFn: () => fetchIncident(id!), refetchInterval: 5_000 })
  const canAct = useCanActIn(inc?.groupId)
  const canChat = useCanChat()(inc?.groupId)
  const handoff = useHandoff()
  const queue = neighbors(id)
  const wide = useWideTable()
  const step = (to: string | undefined) => to && navigate(`/incidents/${to}`)
  useKeys({ j: () => step(queue.next), k: () => step(queue.prev) })
  useRemember(inc && { to: `/incidents/${inc.id}`, label: inc.title ?? inc.id, kind: 'incident' })

  if (isPending) return <Skeleton active paragraph={{ rows: 12 }} style={{ marginTop: 24 }} />
  if (error instanceof HttpError && error.status === 404) {
    return <Result status="404" title={t('incidentNotFound')} extra={<Button onClick={() => navigate('/incidents')}>{t('backToList')}</Button>} />
  }
  if (error || !inc) return <LoadError error={error} onRetry={() => refetch()} />

  // 返回是否成功：结案弹窗靠它决定关不关、备注留不留
  const changeStatus = async (status: string, note?: string) => {
    try {
      await setIncidentStatus(inc.id, status, note)
    } catch (e) {
      message.error(errText(e, t))
      return false
    }
    setResolving(null)
    setAdopting(false)
    await client.invalidateQueries({ queryKey: ['incident', id] })
    client.invalidateQueries({ queryKey: ['incidents'] })
    if (status === 'false_positive') setSuppressing(true)
    // 逐条处理：结案后直接转到列表里的下一条；误报要先填抑制，留在本页
    else if (status === 'closed' && queue.next) {
      message.success(t('closedNext'))
      step(queue.next)
    }
    return true
  }
  const done = inc.status === 'closed' || inc.status === 'false_positive'
  const exportReport = () => downloadReport(inc.id, inc.title).catch(e => message.error(errText(e, t)))

  return (
    <Page
      crumb={inc.title ?? inc.id}
      title={<Space align={wide ? "center" : "start"}><Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/incidents')} />{wide && <SeverityTag value={inc.severity} />}{inc.title ?? inc.id}{wide && <IncidentStatusTag value={inc.status} retriage={inc.retriage} triageStartedAt={inc.triageStartedAt} />}</Space>}
      // 窄屏标题会折行，级别与状态挪到标题下面一行，不夹在折行的标题中间
      subtitle={!wide && <Space size={4} style={{ marginLeft: 40 }}><SeverityTag value={inc.severity} /><IncidentStatusTag value={inc.status} retriage={inc.retriage} triageStartedAt={inc.triageStartedAt} /></Space>}
      extra={
        <>
          {queue.index >= 0 && (
            <Space size={4}>
              <Typography.Text type="secondary" style={{ fontVariantNumeric: 'tabular-nums' }}>{queue.index + 1} / {queue.total}</Typography.Text>
              <Space.Compact>
                <Tooltip title={t('queuePrev')}><Button aria-label={t('queuePrev')} icon={<UpOutlined />} disabled={!queue.prev} onClick={() => step(queue.prev)} /></Tooltip>
                <Tooltip title={t('queueNext')}><Button aria-label={t('queueNext')} icon={<DownOutlined />} disabled={!queue.next} onClick={() => step(queue.next)} /></Tooltip>
              </Space.Compact>
            </Space>
          )}
          {canChat && inc.groupId && !done && (
            <Button type="primary" icon={<RobotOutlined />} loading={handoff.busy}
              onClick={() => handoff.start(inc.groupId!, [`incident:${inc.id}`], t('handoffIncidentTitle', { title: inc.title ?? inc.id }), t('handoffIncidentPrompt'))}>
              {t('handoffToAI')}
            </Button>
          )}
          {/* 只读角色也能导报告：写汇报不是处置动作。窄屏把次要操作收进「更多」，标题区不至于折成好几行 */}
          {wide ? (
            <>
              <Button icon={<DownloadOutlined />} onClick={exportReport}>{t('exportReport')}</Button>
              {canAct && !done && verdictStatus(inc.aiVerdict) && (
                <Button type="primary" ghost onClick={() => changeStatus(verdictStatus(inc.aiVerdict)!, '')}>{t('adoptVerdict')}</Button>
              )}
              {canAct && !done && <Button onClick={() => setResolving('closed')}>{t('markTrue')}</Button>}
              {canAct && !done && <Button danger onClick={() => setResolving('false_positive')}>{t('markFp')}</Button>}
              {canAct && done && <Button onClick={() => changeStatus('open')}>{t('reopen')}</Button>}
            </>
          ) : (
            <Dropdown trigger={['click']} menu={{
              items: [
                { key: 'export', icon: <DownloadOutlined />, label: t('exportReport') },
                ...(canAct && !done ? [{ key: 'closed', label: t('markTrue') }, { key: 'false_positive', label: t('markFp'), danger: true }] : []),
                ...(canAct && done ? [{ key: 'open', label: t('reopen') }] : []),
              ],
              onClick: ({ key }) => {
                if (key === 'export') exportReport()
                else if (key === 'open') void changeStatus('open')
                else setResolving(key as 'closed' | 'false_positive')
              },
            }}>
              <Button icon={<EllipsisOutlined />} aria-label={t('more')} />
            </Dropdown>
          )}
        </>
      }
    >
      <Row gutter={[20, 20]}>
        <Col xs={24} xl={16}>
          <Space orientation="vertical" size={20} style={{ width: '100%' }}>
            {inc.closureProposal && !done && (
              <Alert type="info" showIcon icon={<RobotOutlined />}
                title={t(inc.closureProposal.status === 'closed' ? 'proposalClosed' : 'proposalFp')}
                description={<>
                  <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 8 }}>{inc.closureProposal.note}</Typography.Paragraph>
                  <Space size={12} wrap>
                    <Link to={`/chat/${inc.closureProposal.sessionId}`}>{t('openSession')}</Link>
                    {inc.closureProposal.reportId && <a href={`/api/agent-reports/${inc.closureProposal.reportId}/html`} target="_blank" rel="noreferrer">{t('proposalReport')}</a>}
                  </Space>
                </>}
                action={canAct && (
                  <Space orientation="vertical">
                    <Button type="primary" size="small" onClick={() => { setAdopting(true); setResolving(inc.closureProposal!.status) }}>{t('proposalAdopt')}</Button>
                    <Button size="small" onClick={() => dismissClosureProposal(inc.id).then(() => client.invalidateQueries({ queryKey: ['incident', id] }), e => message.error(errText(e, t)))}>{t('proposalDismiss')}</Button>
                  </Space>
                )} />
            )}
            <VerdictCard verdict={inc.aiVerdict} />
            <TriageHistory key={inc.id} id={inc.id} />
            <Card title={t('graphTitle')}><IncidentGraph graph={inc.graph} assetId={inc.assetId} incidentId={inc.id} canAct={canAct} /></Card>
            <Card title={t('alertsTitle', { n: inc.alerts.length })} styles={{ body: { padding: alertView === 'timeline' ? '20px 24px 4px' : 0 } }}
              extra={<Segmented size="small" value={alertView} onChange={v => setAlertView(v as 'table' | 'timeline')}
                options={[{ value: 'timeline', label: t('viewTimeline') }, { value: 'table', label: t('viewTable') }]} />}>
              {alertView === 'timeline' ? <AlertTimeline alerts={inc.alerts} /> : (
              <div className="table-card-content">
              <Table<AlertRow>
                size="small"
                rowKey="id"
                dataSource={inc.alerts}
                pagination={{ pageSize: 20, hideOnSinglePage: true }}
                expandable={{ expandedRowRender: a => <>
                  <TemporalRuleAtAlert alertId={a.id} ruleId={a.ruleId} />
                  {a.event ? (
                  <>
                    <Typography.Text copyable={{ text: JSON.stringify(a.event, null, 2) }} type="secondary" style={{ fontSize: 12, display: 'block' }}>{t('rawEvent')}</Typography.Text>
                    <pre className="json-block">{JSON.stringify(a.event, null, 2)}</pre>
                  </>
                  ) : t('noRawEvent')}
                </> }}
                columns={[
                  { title: t('thFirst'), dataIndex: 'ts', render: fmtTime, width: 170 },
                  { title: t('thLast'), dataIndex: 'lastTs', render: fmtTime, width: 170 },
                  { title: t('thRule'), dataIndex: 'ruleTitle', render: (v, a) => <Space size={4}><Tooltip title={a.ruleAuthor && t('ruleBy', { author: a.ruleAuthor })}><Link to={`/rules?q=${encodeURIComponent(a.ruleId)}`}>{v ?? a.ruleId}</Link></Tooltip><AutomationTag value={a.automation} /></Space>, ellipsis: true },
                  { title: t('thSeverity'), dataIndex: 'severity', render: v => <SeverityTag value={v} />, width: 90 },
                  { title: t('thCount'), dataIndex: 'count', align: 'right', width: 70 },
                  {
                    // 前后各 10 分钟的原始日志：判断告警之前发生了什么、之后有没有后续
                    title: '', width: 90,
                    render: (_, a) => inc.assetId && (
                      <Link className="row-actions" to={`/events?${new URLSearchParams({
                        assetId: inc.assetId,
                        from: new Date(Date.parse(a.ts) - 600_000).toISOString(),
                        to: new Date(Date.parse(a.lastTs ?? a.ts) + 600_000).toISOString(),
                      })}`}>{t('logContext')}</Link>
                    ),
                  },
                ]}
              />
              </div>
              )}
            </Card>
          </Space>
        </Col>
        <Col xs={24} xl={8}>
          <Space orientation="vertical" size={20} style={{ width: '100%' }}>
            {queue.total > 1 && queue.index >= 0 && <QueueCard items={queue.items} index={queue.index} />}
            <Card title={t('basicInfo')}>
              <Descriptions column={1} size="small">
                <Descriptions.Item label="ID"><Typography.Text className="mono" copyable ellipsis style={{ maxWidth: 220 }}>{inc.id}</Typography.Text></Descriptions.Item>
                <Descriptions.Item label={t('thStatus')}><Space size={4} wrap><IncidentStatusTag value={inc.status} retriage={inc.retriage} triageStartedAt={inc.triageStartedAt} /></Space></Descriptions.Item>
                {inc.triageStartedAt && <Descriptions.Item label={t('triageRunning')}>{t('triageStartedDetail', { at: fmtTime(inc.triageStartedAt) })}</Descriptions.Item>}
                {inc.triagedAt && <Descriptions.Item label={t('lastTriaged')}>{fmtTime(inc.triagedAt)} · {t('triageRounds', { n: inc.triageCount })}</Descriptions.Item>}
                {!inc.triageStartedAt && !!inc.triageFailures && <Descriptions.Item label={t('triageFailed')}>{t('triageFailedDetail', { n: inc.triageFailures, at: fmtTime(inc.triageRetryAt) })}</Descriptions.Item>}
                <Descriptions.Item label={t('thSeverity')}><SeverityTag value={inc.severity} /></Descriptions.Item>
                <Descriptions.Item label={t('thCreatedAt')}>{fmtTime(inc.createdAt)}</Descriptions.Item>
                <Descriptions.Item label={t('thAlerts')}>{inc.alerts.length}</Descriptions.Item>
                <Descriptions.Item label={t('thHostname')}><HostLink id={inc.assetId} /></Descriptions.Item>
                <Descriptions.Item label={t('group')}>{groups.find(g => g.id === inc.groupId)?.name ?? '-'}</Descriptions.Item>
                {inc.resolvedAt && <Descriptions.Item label={t('resolution')}>{inc.resolution}</Descriptions.Item>}
                {inc.resolvedAt && <Descriptions.Item label={t('resolvedBy')}>{inc.resolvedBy} · {fmtTime(inc.resolvedAt)}</Descriptions.Item>}
              </Descriptions>
            </Card>
            <ExternalTickets incidentId={inc.id} />
            <ResponsePanel incidentId={inc.id} assetId={inc.assetId} canAct={canAct} />
          </Space>
        </Col>
      </Row>
      <ResolveModal
        open={!!resolving}
        title={t(resolving === 'closed' ? 'resolveClosedTitle' : 'resolveFpTitle')}
        hint={t('resolveHint')}
        initialNote={adopting ? inc.closureProposal?.note : undefined}
        optional={agreesWithAI(inc.aiVerdict, resolving)}
        contradicts={!!verdictStatus(inc.aiVerdict) && !agreesWithAI(inc.aiVerdict, resolving)}
        onCancel={() => { setResolving(null); setAdopting(false) }}
        onSubmit={async note => { if (!await changeStatus(resolving!, note)) throw new Error() }}
      />
      <SuppressModal open={suppressing} alerts={inc.alerts} assetId={inc.assetId} onClose={() => setSuppressing(false)} />
    </Page>
  )
}
