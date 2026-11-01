import {
  AlertOutlined, ArrowRightOutlined, CheckCircleOutlined, CloudServerOutlined, FileTextOutlined, RightOutlined, ToolOutlined,
} from '@ant-design/icons'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Card, Col, Empty, Flex, Row, Segmented, Space, Table, Typography, theme } from 'antd'
import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { fetchAgentReports, fetchApprovals, fetchAssets, fetchFindingsPage, fetchIncidents, fetchStats, fetchTaskRuns, fetchTasks, type IncidentSummary } from '../api'
import { useSession } from '../app/session'
import { useTheme } from '../app/theme'
import { Ago } from '../components/Ago'
import { GettingStarted } from '../components/GettingStarted'
import { LoadError } from '../components/LoadError'
import { GeminiSparkle } from '../components/Logo'
import { Page, TableCard, WIDE_ONLY, useWideTable } from '../components/Page'
import { saveQueue } from '../components/incidentQueue'
import { useRowLink } from '../components/rowLink'
import { BarList, ColumnChart, SEVERITY_COLOR, compact, useSeriesColor } from '../components/charts'
import { HostStateBadge, IncidentStatusTag, SessionStatusTag, SeverityTag, fmtTime, hostState } from '../components/format'
import { useI18n } from '../i18n'

// 采集量按 24 小时统计，待复核是全部未结案存量；不同口径不计算降噪百分比。
function Funnel({ events, alerts, incidents, foot }: { events: number; alerts: number; incidents: number; foot: ReactNode }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { dark } = useTheme()
  const stages = [
    { label: t('funnelEvents'), value: events, to: '/events' },
    { label: t('funnelAlerts'), value: alerts },
    { label: t('funnelReview'), value: incidents, to: '/incidents' },
  ]
  return (
    <Card title={t('funnelTitle')} style={{ height: '100%' }}>
      <div className="funnel">
        {stages.flatMap((s, i) => [
          ...(i > 0 ? [
            <div key={`a${i}`} className="funnel-arrow" style={{ color: token.colorTextTertiary }}>
              <RightOutlined />
            </div>,
          ] : []),
          // 最后一级是结论：浅主色底加一圈细边。暗色算法里主色边框与底色同值、主色文字偏暗，换亮一档才压得住底色
          <div key={s.label} className="funnel-stage" style={i === 2
            ? { background: token.colorPrimaryBg, boxShadow: `inset 0 0 0 1px ${dark ? token.colorPrimary : token.colorPrimaryBorder}` }
            : { background: token.colorFillQuaternary }}>
            <Space size={6} align="center">
              {i === 2 && <GeminiSparkle size={14} />}
              <Typography.Text type="secondary">{s.label}</Typography.Text>
            </Space>
            <div className="funnel-value" style={{ color: i === 2 ? (dark ? token.colorPrimaryTextHover : token.colorPrimary) : token.colorText }}>
              {s.to ? <Link to={s.to} style={{ color: 'inherit' }}>{compact(s.value)}</Link> : compact(s.value)}
            </div>
          </div>,
        ])}
      </div>
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0, fontSize: 12 }}>{t('funnelScopeHint')}</Typography.Paragraph>
      <div className="funnel-foot">{foot}</div>
    </Card>
  )
}

// 需要人处理的事：每项一个入口，全部清零时给一句定心话
function ActionCenter({ items }: { items: { icon: ReactNode; label: string; count: number | undefined; to: string; color: string }[] }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  return (
    <Card title={t('actionCenter')} style={{ height: '100%' }} styles={{ body: { padding: '12px 20px 20px' } }}>
      <div className="action-list-wrap">
        {items.map(i => (
          <Link key={i.to} to={i.to} className="action-row">
            <span className="action-icon" style={{ color: i.count ? i.color : token.colorTextQuaternary, background: i.count ? `${i.color}1a` : token.colorFillTertiary }}>{i.icon}</span>
            <Typography.Text style={{ flex: 1 }}>{i.label}</Typography.Text>
            <span className="action-count" style={{ color: i.count ? token.colorText : token.colorTextQuaternary }}>{i.count ?? '-'}</span>
            <RightOutlined style={{ color: token.colorTextQuaternary, fontSize: 12 }} />
          </Link>
        ))}
      </div>
      {items.every(i => i.count === 0) && (
        <Flex align="center" gap={6} style={{ padding: '12px 8px 2px', color: token.colorSuccess }}>
          <CheckCircleOutlined />{t('allClear')}
        </Flex>
      )}
    </Card>
  )
}

// AI 运营：最近任务运行与报告，体现"纳管即运维"的持续巡检
function AiOps() {
  const { t, locale } = useI18n()
  const { group } = useSession()
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks })
  const runs = useQuery({
    queryKey: ['taskRuns', 'recent', tasks.data?.map(x => x.id)],
    queryFn: async () => (await Promise.all((tasks.data ?? []).map(x => fetchTaskRuns(x.id).then(rs => rs.map(r => ({ ...r, name: x.name, nameEn: x.nameEn }))))))
      .flat()
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .slice(0, 4),
    enabled: !!tasks.data,
    refetchInterval: 30_000,
  })
  const reports = useQuery({ queryKey: ['reports', group?.id], queryFn: () => fetchAgentReports(group!.id), enabled: !!group })

  return (
    <Card title={<Space size={8}><GeminiSparkle size={16} />{t('aiOpsTitle')}</Space>} style={{ height: '100%' }} extra={<Link to="/chat">{t('navChat')} <ArrowRightOutlined /></Link>}>
      <Typography.Text type="secondary" strong>{t('recentRuns')}</Typography.Text>
      <div className="mini-list">
        {(runs.data ?? []).length === 0 && <div className="mini-row"><Typography.Text type="secondary">{t('noTaskRuns')}</Typography.Text></div>}
        {runs.data?.map(r => (
          <Flex key={r.id} justify="space-between" align="center" className="mini-row">
            <Typography.Text ellipsis style={{ maxWidth: '55%' }}>{locale === 'en' && r.nameEn ? r.nameEn : r.name}</Typography.Text>
            <Space size={6}>
              <SessionStatusTag value={r.status} />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(r.startedAt).slice(5, 16)}</Typography.Text>
            </Space>
          </Flex>
        ))}
      </div>
      <Typography.Text type="secondary" strong>{t('recentReports')}</Typography.Text>
      <div className="mini-list">
        {(reports.data ?? []).length === 0 && <div className="mini-row"><Typography.Text type="secondary">{t('noReports')}</Typography.Text></div>}
        {reports.data?.slice(0, 4).map(r => (
          <Flex key={r.id} justify="space-between" align="center" className="mini-row">
            <Link to="/reports" style={{ maxWidth: '65%' }}><Typography.Text ellipsis><FileTextOutlined /> {r.title}</Typography.Text></Link>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(r.created_at).slice(5, 16)}</Typography.Text>
          </Flex>
        ))}
      </div>
    </Card>
  )
}

// 态势总览：先回答"今天挡掉多少噪声、还剩几件事要我处理"，再看趋势、分布与明细
export function OverviewPage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { group } = useSession()
  const series = useSeriesColor()
  const [trendView, setTrendView] = useState<'chart' | 'table'>('chart')
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 30_000, placeholderData: keepPreviousData })
  const incidents = useQuery({ queryKey: ['incidents', 'review', 'overview'], queryFn: () => fetchIncidents({ status: 'review', limit: 6 }), refetchInterval: 30_000 })
  const findings = useQuery({ queryKey: ['findings', 'count', 'open'], queryFn: () => fetchFindingsPage({ status: 'open', limit: 1 }), refetchInterval: 60_000 })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 30_000 })
  // 手机上标题换行完整显示，不截断成看不出是什么的半句
  const wideTable = useWideTable()
  const rowLink = useRowLink<IncidentSummary>(r => `/incidents/${r.id}`)
  useEffect(() => { if (incidents.data) saveQueue(incidents.data.items) }, [incidents.data])
  const isGroupAdmin = group?.role === 'admin'
  const approvals = useQuery({ queryKey: ['approvals', group?.id], queryFn: () => fetchApprovals(group!.id), enabled: !!group && isGroupAdmin, refetchInterval: 10_000 })
  const s = stats.data
  const topRules = s?.topRules ?? []
  const offline = (assets.data ?? []).filter(a => ['silent', 'stale'].includes(hostState(a)))
  const sevItems = [5, 4, 3, 2, 1].map(n => ({
    key: String(n),
    label: <SeverityTag value={n} />,
    value: s?.alertsBySeverity?.[n] ?? 0,
    color: SEVERITY_COLOR[n],
  }))
  const hourOf = (iso: string) => new Date(iso).getHours()

  if (stats.isError && !s) return <Page title={t('navOverview')}><LoadError error={stats.error} onRetry={() => stats.refetch()} /></Page>

  return (
    <Page title={t('navOverview')} subtitle={t('overviewSubtitle')}>
      <GettingStarted />
      <Row gutter={[20, 20]}>
        <Col xs={24} xl={16}>
          <Funnel events={s?.events24h ?? 0} alerts={s?.alerts24h ?? 0} incidents={s?.reviewIncidents ?? 0}
            foot={[
              ...(s && s.openIncidents > s.reviewIncidents ? [t('footBenignPending', { n: s.openIncidents - s.reviewIncidents })] : []),
              t('footRules', { n: topRules.length }),
              t('footCritical', { n: (s?.alertsBySeverity?.[5] ?? 0) + (s?.alertsBySeverity?.[4] ?? 0) }),
              t('footHosts', { up: s?.assetsOnline ?? 0, total: s?.assetsTotal ?? 0 }),
            ].map(x => <Typography.Text key={x} type="secondary">{x}</Typography.Text>)} />
        </Col>
        <Col xs={24} xl={8}>
          <ActionCenter items={[
            { icon: <AlertOutlined />, label: t('reviewIncidents'), count: stats.isError ? undefined : s?.reviewIncidents, to: '/incidents', color: token.colorError },
            { icon: <ToolOutlined />, label: t('navFindings'), count: findings.isError ? undefined : findings.data?.total, to: '/findings', color: token.colorWarning },
            ...(isGroupAdmin ? [{ icon: <CheckCircleOutlined />, label: t('navApprovals'), count: approvals.isError ? undefined : approvals.data?.filter(a => a.status === 'pending').length, to: '/approvals', color: token.colorPrimary }] : []),
            { icon: <CloudServerOutlined />, label: t('offlineHosts'), count: assets.isError || !assets.data ? undefined : offline.length, to: '/assets', color: token.colorError },
          ]} />
        </Col>

        <Col xs={24} xl={16}>
          <Card title={t('alertTrend24h')} style={{ height: '100%' }}
            extra={<Segmented size="small" value={trendView} onChange={v => setTrendView(v as 'chart' | 'table')} options={[{ value: 'chart', label: t('viewChart') }, { value: 'table', label: t('viewTable') }]} />}>
            {!s ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> : trendView === 'chart' ? (
              <ColumnChart
                dim={stats.isFetching && !stats.isPending}
                data={s.alertTrend.map(b => ({ key: b.hour, value: b.count }))}
                xLabel={i => (hourOf(s.alertTrend[i].hour) % 6 === 0 ? `${String(hourOf(s.alertTrend[i].hour)).padStart(2, '0')}:00` : null)}
                tip={i => t('trendTip', { h: String(hourOf(s.alertTrend[i].hour)).padStart(2, '0'), n: s.alertTrend[i].count })}
              />
            ) : (
              <Table size="small" rowKey="hour" pagination={false} scroll={{ y: 200 }} dataSource={s.alertTrend}
                columns={[
                  { title: t('thTime'), dataIndex: 'hour', render: v => fmtTime(v).slice(0, 16) },
                  { title: t('thAlerts'), dataIndex: 'count', align: 'right' },
                ]} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={t('alertsBySeverity')} style={{ height: '100%' }}>
            <BarList items={sevItems} labelWidth="64px" dim={stats.isFetching && !stats.isPending} />
          </Card>
        </Col>

        <Col xs={24} xl={16}>
          <TableCard title={t('reviewIncidents')} extra={<Link to="/incidents">{t('viewAll')}</Link>} style={{ height: '100%' }}>
            {incidents.isError ? <LoadError error={incidents.error} onRetry={() => incidents.refetch()} /> : (
              <Table<IncidentSummary>
                size="small"
                rowKey="id"
                rowClassName="row-link"
                onRow={rowLink}
                loading={incidents.isPending}
                dataSource={incidents.data?.items ?? []}
                pagination={false}
                locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIncidents')} /> }}
                columns={[
                  { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
                  { title: t('thTitle'), dataIndex: 'title', ellipsis: wideTable, render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
                  { title: t('thStatus'), dataIndex: 'status', width: 100, render: (v, r) => <Space size={4} wrap><IncidentStatusTag value={v} retriage={r.retriage} triageStartedAt={r.triageStartedAt} /></Space> },
                  { responsive: WIDE_ONLY, title: t('thAlerts'), dataIndex: 'alertCount', width: 80, align: 'right' },
                  { responsive: WIDE_ONLY, title: t('thCreatedAt'), dataIndex: 'createdAt', width: 110, render: v => <Ago iso={v} /> },
                ]}
              />
            )}
          </TableCard>
        </Col>
        <Col xs={24} xl={8}>
          <AiOps />
        </Col>

        <Col xs={24} xl={16}>
          <Card title={t('topRules')} style={{ height: '100%' }}>
            {topRules.length ? (
              <BarList items={topRules.map(r => ({ key: r.ruleId, label: <Typography.Text ellipsis title={r.ruleAuthor ? `${r.ruleId} · ${t('ruleBy', { author: r.ruleAuthor })}` : r.ruleId}>{r.ruleTitle ?? r.ruleId}</Typography.Text>, value: r.count, color: series, to: `/rules?q=${encodeURIComponent(r.ruleId)}` }))} />
            ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noAlerts24h')} />}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={t('offlineAssets', { n: offline.length })} style={{ height: '100%' }} extra={<Link to="/assets">{t('viewAll')}</Link>}>
            {offline.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('allOnline')} />
            ) : (
              <div className="mini-list">
                {offline.slice(0, 6).map(a => (
                  <Flex key={a.id} justify="space-between" className="mini-row">
                    <Space><Link to={`/assets/${a.id}`}>{a.hostname}</Link><HostStateBadge asset={a} /></Space>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('lastSeenAt', { time: fmtTime(a.lastSeen) })}</Typography.Text>
                  </Flex>
                ))}
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </Page>
  )
}
