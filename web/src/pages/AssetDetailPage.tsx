import { ArrowLeftOutlined, LayoutOutlined, RobotOutlined, SearchOutlined } from '@ant-design/icons'
import { AssetVulns } from '../components/AssetVulns'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Badge, Button, Card, Col, Descriptions, Empty, Form, Input, Result, Row, Segmented, Select, Skeleton, Space, Switch, Table, Tabs, Tag, Tooltip, Typography,
  theme,
} from 'antd'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import {
  createAgentSession, fetchAgentConfig, fetchAssets, fetchCommandsPage, fetchFindingsPage, fetchIncidents, saveAgentConfig, searchEvents,
  type AgentConfig, type CommandRow, type EventRow, type FindingRow, type IncidentSummary,
} from '../api'
import { useRemember } from '../app/recent'
import { saveQueue } from '../components/incidentQueue'
import { useRowLink } from '../components/rowLink'
import { useCanActIn, useSession } from '../app/session'
import { CommandDetailDrawer } from '../components/CommandDetailDrawer'
import { CommandVerificationDrawer } from '../components/CommandVerificationDrawer'
import { LocalAccounts } from '../components/LocalAccounts'
import { IdentityObservations } from '../components/IdentityObservations'
import { TemporalGaps } from '../components/TemporalGaps'
import { CollectorHealth, SensorHealth } from '../components/CollectorHealth'
import { AssetProfileView } from '../components/AssetProfile'
import { LoadError } from '../components/LoadError'
import { Page, WIDE_ONLY, useWideTable } from '../components/Page'
import { eventSummary } from '../components/eventSummary'
import {
  CLASS_KEY, CommandStatusTag, HostStateBadge, IncidentStatusTag, SeverityTag, commandKind, errText, fmtTime, hostSeen,
} from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const FINDING_SEVERITY: Record<FindingRow['severity'], number> = { info: 1, low: 2, medium: 3, high: 4 }
const INCIDENT_PAGE = 10

// 详情页顶部的小指标：标签在上、数值在下，可点进对应标签页
function Stat({ label, value, tone, active, onClick }: { label: string; value: ReactNode; tone?: string; active?: boolean; onClick?: () => void }) {
  const { token } = theme.useToken()
  return (
    <Card size="small" hoverable={!!onClick} onClick={onClick}
      role={onClick ? 'button' : undefined} tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick() } } : undefined}
      style={{
        height: '100%',
        borderColor: active ? token.colorPrimaryBorder : undefined,
        background: active ? token.colorPrimaryBg : undefined,
      }}
      styles={{ body: { padding: '16px 20px' } }}>
      <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{label}</Typography.Text>
      <div style={{ fontSize: 24, fontWeight: 600, marginTop: 4, color: tone ?? token.colorText, fontVariantNumeric: 'tabular-nums', lineHeight: 1.25 }}>{value}</div>
    </Card>
  )
}
const SWITCHES: { name: keyof AgentConfig; key: MsgKey }[] = [
  { name: 'collectFiles', key: 'cfgFiles' },
  { name: 'collectAuth', key: 'cfgAuth' },
  { name: 'collectPersist', key: 'cfgPersist' },
  { name: 'collectNetwork', key: 'cfgNetwork' },
  { name: 'collectInventory', key: 'cfgInventory' },
  { name: 'collapsePeriodic', key: 'cfgCollapse' },
]

// 采集配置：开关缺省全开；目录为空表示用 agent 内置的敏感目录清单
function ConfigTab({ assetId, canEdit }: { assetId: string; canEdit: boolean }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [form] = Form.useForm()
  const [saving, setSaving] = useState(false)
  const { data, isPending } = useQuery({ queryKey: ['agentConfig', assetId], queryFn: () => fetchAgentConfig(assetId) })

  useEffect(() => {
    if (!data) return
    form.setFieldsValue({
      ...Object.fromEntries(SWITCHES.map(s => [s.name, data[s.name] !== false])),
      fileWatchDirs: data.fileWatchDirs ?? [],
    })
  }, [data, form])

  const save = async (v: Record<string, unknown>) => {
    setSaving(true)
    try {
      const cfg: AgentConfig = { fileWatchDirs: (v.fileWatchDirs as string[]).length ? (v.fileWatchDirs as string[]) : undefined }
      // 只写关掉的开关，开着的留空 = 用 agent 默认，配置里不堆冗余字段
      for (const s of SWITCHES) if (v[s.name] === false) (cfg as Record<string, unknown>)[s.name] = false
      await saveAgentConfig(assetId, cfg)
      message.success(t('cfgSaved'))
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setSaving(false)
    }
  }

  if (isPending) return <Skeleton active />
  return (
    <Form form={form} layout="horizontal" labelCol={{ span: 6 }} wrapperCol={{ span: 14 }} onFinish={save} disabled={!canEdit} style={{ maxWidth: 760 }}>
      <Alert type="info" showIcon title={t('cfgHint')} style={{ marginBottom: 20 }} />
      {SWITCHES.map(s => (
        <Form.Item key={s.name} name={s.name} label={t(s.key)} valuePropName="checked">
          <Switch />
        </Form.Item>
      ))}
      <Form.Item name="fileWatchDirs" label={t('cfgDirs')} extra={t('cfgDirsHint')}>
        <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="/etc /root/.ssh" />
      </Form.Item>
      {canEdit && (
        <Form.Item wrapperCol={{ offset: 6 }}>
          <Button type="primary" htmlType="submit" loading={saving}>{t('save')}</Button>
        </Form.Item>
      )}
    </Form>
  )
}

export function AssetDetailPage() {
  const { id } = useParams()
  return <AssetDetail key={id} />
}

const VALID_TABS = ['incidents', 'findings', 'events', 'commands', 'vulns', 'localAccounts', 'identity', 'detectionGaps', 'config', 'profile']

function AssetDetail() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { id } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { groups, isAdmin } = useSession()
  const [starting, setStarting] = useState(false)
  const [showSideProfile, setShowSideProfile] = useState(true)
  // 从攻击面等处带 ?tab= 进来时直接打开对应标签
  const [params, setParams] = useSearchParams()
  const requestedTab = params.get('tab') ?? 'incidents'
  const tab = VALID_TABS.includes(requestedTab) ? requestedTab : 'incidents'
  const setTab = (key: string) => setParams(prev => {
    const next = new URLSearchParams(prev)
    next.set('tab', key)
    return next
  })
  const detailsRef = useRef<HTMLDivElement>(null)
  const openTab = (key: string) => {
    setTab(key)
    requestAnimationFrame(() => {
      detailsRef.current?.focus({ preventScroll: true })
      detailsRef.current?.scrollIntoView({ block: 'start', behavior: 'smooth' })
    })
  }
  const [commandPage, setCommandPage] = useState(1)
  const [commandDetail, setCommandDetail] = useState<string | null>(null)
  const [verifying, setVerifying] = useState<CommandRow | null>(null)
  const [incPage, setIncPage] = useState(1)
  const [incStatus, setIncStatus] = useState<string>('')
  const [incQ, setIncQ] = useState('')
  const [findingPage, setFindingPage] = useState(1)
  const [findingStatus, setFindingStatus] = useState<string>('')
  const [findingQ, setFindingQ] = useState('')
  const [eventClass, setEventClass] = useState<number | undefined>()
  const [eventQ, setEventQ] = useState('')

  useEffect(() => { setCommandPage(1); setCommandDetail(null) }, [id])
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 15000 })
  const asset = assets.data?.find(a => a.id === id)
  const canAct = useCanActIn(asset?.groupId)
  const incidents = useQuery({
    queryKey: ['incidents', 'asset', id, incStatus, incPage],
    queryFn: () => fetchIncidents({ assetId: id, status: incStatus || undefined, limit: INCIDENT_PAGE, offset: (incPage - 1) * INCIDENT_PAGE }),
    enabled: !!asset,
  })
  const unresolved = useQuery({ queryKey: ['incidents', 'asset', id, 'unresolved'], queryFn: () => fetchIncidents({ assetId: id, status: 'unresolved', limit: 1 }), enabled: !!asset })
  const findings = useQuery({
    queryKey: ['findings', 'asset', id, findingStatus, findingPage],
    queryFn: () => fetchFindingsPage({ assetId: id, status: findingStatus || undefined, limit: 10, offset: (findingPage - 1) * 10 }),
    enabled: !!asset,
  })
  const findingCount = useQuery({ queryKey: ['findings', 'asset', id, 'open-count'], queryFn: () => fetchFindingsPage({ assetId: id, status: 'open', limit: 1 }), enabled: !!asset })
  const events = useQuery({ queryKey: ['events', 'asset', id], queryFn: () => searchEvents({ assetId: id, hours: 168 }), enabled: !!asset })
  const commands = useQuery({ queryKey: ['commands', 'asset', id, commandPage], queryFn: () => fetchCommandsPage({ assetId: id! }, commandPage), enabled: !!asset })

  useEffect(() => {
    if (!incidents.isSuccess || incidents.isFetching || incidents.data.total === undefined) return
    const lastPage = Math.max(1, Math.ceil(incidents.data.total / INCIDENT_PAGE))
    if (incPage > lastPage) setIncPage(lastPage)
  }, [incidents.data?.total, incidents.isSuccess, incidents.isFetching, incPage])
  useEffect(() => {
    if (!findings.isSuccess || findings.isFetching || findings.data.total === undefined) return
    const lastPage = Math.max(1, Math.ceil(findings.data.total / 10))
    if (findingPage > lastPage) setFindingPage(lastPage)
  }, [findings.data?.total, findings.isSuccess, findings.isFetching, findingPage])

  // 手机上标题换行完整显示，不截断成看不出是什么的半句
  const wideTable = useWideTable()
  const rowLink = useRowLink<IncidentSummary>(r => `/incidents/${r.id}`)
  useEffect(() => { if (incidents.data) saveQueue(incidents.data.items) }, [incidents.data])
  useRemember(asset && { to: `/assets/${asset.id}`, label: asset.hostname, kind: 'asset' })

  const filteredIncidents = useMemo(() => {
    const items = incidents.data?.items ?? []
    const q = incQ.trim().toLowerCase()
    if (!q) return items
    return items.filter(r => (r.title ?? '').toLowerCase().includes(q) || r.id.toLowerCase().includes(q))
  }, [incidents.data?.items, incQ])

  const filteredFindings = useMemo(() => {
    const items = findings.data?.items ?? []
    const q = findingQ.trim().toLowerCase()
    if (!q) return items
    return items.filter(r => r.title.toLowerCase().includes(q) || r.key.toLowerCase().includes(q) || (r.detail ?? '').toLowerCase().includes(q))
  }, [findings.data?.items, findingQ])

  const filteredEvents = useMemo(() => {
    let items = events.data?.items ?? []
    if (eventClass !== undefined) items = items.filter(r => r.classUid === eventClass)
    const q = eventQ.trim().toLowerCase()
    if (q) {
      items = items.filter(r =>
        (eventSummary(r.classUid, r.raw, t) || '').toLowerCase().includes(q) ||
        (r.connTuple ?? '').toLowerCase().includes(q) ||
        (r.username ?? '').toLowerCase().includes(q)
      )
    }
    return items
  }, [events.data?.items, eventClass, eventQ, t])

  if (assets.isPending) return <Skeleton active style={{ marginTop: 24 }} />
  if (assets.isError) return <LoadError error={assets.error} onRetry={() => assets.refetch()} />
  if (!asset) return <Result status="404" title={t('assetNotFound')} extra={<Button onClick={() => navigate('/assets')}>{t('backToList')}</Button>} />

  const group = groups.find(g => g.id === asset.groupId)
  // 对话只看组内角色（后端同口径），全局只读的组内分析师也能发起排查
  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const unresolvedCount = unresolved.isError ? undefined : unresolved.data?.total
  const openFindingCount = findingCount.isError ? undefined : findingCount.data?.total
  const incidentCount = incidents.isError ? undefined : incidents.data?.total
  const eventCount = !events.isError && events.data ? `${events.data.items.length}${events.data.truncated ? '+' : ''}` : '-'
  const collectorDegraded = Boolean(
    asset.collectorHealth?.writeBlocked ||
    Object.values(asset.collectorHealth?.capabilities ?? {}).some(c => c.state === 'degraded' || c.state === 'unavailable') ||
    asset.sensorHealth?.capabilities?.capture?.state === 'degraded' ||
    asset.sensorHealth?.capabilities?.capture?.state === 'unavailable'
  )

  // 一键排查：在主机所在组新建对话，把主机名预填进提问
  const investigate = async () => {
    if (!asset.groupId) return
    setStarting(true)
    try {
      const s = await createAgentSession({ groupId: asset.groupId, title: t('investigateTitle', { host: asset.hostname }) })
      client.invalidateQueries({ queryKey: ['sessions', asset.groupId] })
      navigate(`/chat/${s.id}?prompt=${encodeURIComponent(t('investigatePrompt', { host: asset.hostname }))}`)
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setStarting(false)
    }
  }

  return (
    <Page
      crumb={asset.hostname}
      title={<Space><Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/assets')} />{asset.hostname}<HostStateBadge asset={asset} /></Space>}
      subtitle={[asset.osDisplay ?? asset.os, group?.name ?? t('ungrouped')].filter(Boolean).join(' · ')}
      extra={
        <Space wrap>
          <Button icon={<SearchOutlined />} onClick={() => navigate(`/events?assetId=${asset.id}`)}>{t('openInEvents')}</Button>
          {canChat && asset.groupId && <Button type="primary" icon={<RobotOutlined />} loading={starting} onClick={investigate}>{t('investigateHost')}</Button>}
        </Space>
      }
    >
      {commandDetail && <CommandDetailDrawer id={commandDetail} onClose={() => setCommandDetail(null)} />}
      {verifying?.assetId === asset.id && <CommandVerificationDrawer key={`${verifying.id}:${asset.groupId}`} command={verifying} canEdit={canAct} onClose={() => setVerifying(null)} />}
      <Row gutter={[20, 20]}>
        {/* 顶部左：主机身份与核心元数据（支持单 IP 一键复制） */}
        <Col xs={24} xl={14}>
          <Card size="small" style={{ height: '100%' }} styles={{ body: { padding: '18px 22px' } }}>
            <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small" colon={false}
              styles={{ label: { color: token.colorTextSecondary, fontSize: 12.5, paddingBottom: 2 }, content: { fontWeight: 500, paddingBottom: 8 } }}>
              <Descriptions.Item label="OS">{asset.osDisplay ?? asset.os ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('group')}>
                {group ? <Tag color="blue" variant="filled" style={{ margin: 0 }}>{group.name}</Tag> : <Tag style={{ margin: 0 }}>{t('ungrouped')}</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label={t('thSource')}>
                <Space size={4} wrap>
                  {asset.agentId || asset.sensorSeen
                    ? [asset.agentId && <Tag key="agent" style={{ margin: 0 }}>agent{asset.agentVersion ? ` v${asset.agentVersion}` : ''}</Tag>, asset.sensorSeen && <Tag key="sensor" color="cyan" style={{ margin: 0 }}>sensor</Tag>].filter(Boolean)
                    : <Tag style={{ margin: 0 }}>{t('sourceLog')}</Tag>}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label={t('thIP')} span={2}>
                {asset.ipAddrs?.length ? (
                  <Space size={[6, 4]} wrap>
                    {asset.ipAddrs.map(ip => (
                      <Typography.Text key={ip} className="mono" copyable style={{ fontSize: 12.5, background: token.colorFillQuaternary, padding: '1px 8px', borderRadius: 6 }}>
                        {ip}
                      </Typography.Text>
                    ))}
                  </Space>
                ) : '-'}
              </Descriptions.Item>
              <Descriptions.Item label={t('firstSeen')}>{fmtTime(asset.firstSeen)}</Descriptions.Item>
              <Descriptions.Item label="ID">
                <Typography.Text className="mono" copyable ellipsis style={{ maxWidth: 160, fontSize: 12 }}>{asset.id}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="Agent ID" span={2}>
                {asset.agentId ? <Typography.Text className="mono" copyable ellipsis style={{ maxWidth: 220, fontSize: 12 }}>{asset.agentId}</Typography.Text> : '-'}
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>

        {/* 顶部右：2×2 关键运营指标卡片（点击直达对应标签页） */}
        <Col xs={24} xl={10}>
          <Row gutter={[14, 14]} style={{ height: '100%' }}>
            <Col xs={12}>
              <Stat label={t('unresolvedIncidents')} value={unresolvedCount ?? '-'} tone={unresolvedCount ? token.colorError : undefined} active={tab === 'incidents'}
                onClick={() => { setIncStatus('unresolved'); setIncPage(1); openTab('incidents') }} />
            </Col>
            <Col xs={12}>
              <Stat label={t('navFindings')} value={openFindingCount ?? '-'} tone={openFindingCount ? token.colorWarning : undefined} active={tab === 'findings'}
                onClick={() => { setFindingStatus('open'); setFindingPage(1); openTab('findings') }} />
            </Col>
            <Col xs={12}>
              <Stat label={t('tabEvents')} value={eventCount} active={tab === 'events'} onClick={() => openTab('events')} />
            </Col>
            <Col xs={12}>
              <Stat label={t('thLastSeen')} active={tab === 'config'}
                tone={collectorDegraded ? token.colorWarning : undefined}
                value={<span style={{ fontSize: 16 }}>{asset.agentId || asset.sensorSeen ? fmtTime(hostSeen(asset)).slice(5) : '—'}</span>}
                onClick={() => openTab('config')} />
            </Col>
          </Row>
        </Col>

        {/* 仅当采集或探针处于降级/异常时在顶层显著提示；常规健康状态收敛在「采集与配置」标签页中 */}
        {collectorDegraded && (asset.agentId || !asset.sensorSeen) && <Col span={24}><CollectorHealth asset={asset} /></Col>}
        {collectorDegraded && asset.sensorSeen && <Col span={24}><SensorHealth asset={asset} /></Col>}

        {/* 主工作区：支持切换右侧画像边栏或全宽表格模式 */}
        <Col xs={24} xl={showSideProfile && tab !== 'profile' ? 16 : 24}>
          <Card ref={detailsRef} tabIndex={-1} style={{ scrollMarginTop: 72 }} styles={{ body: { paddingTop: 6 } }}>
            <Tabs
              activeKey={tab}
              onChange={setTab}
              tabBarExtraContent={wideTable && tab !== 'profile' ? (
                <Tooltip title={t('profileTitle')}>
                  <Button size="small" type={showSideProfile ? 'default' : 'dashed'} icon={<LayoutOutlined />} onClick={() => setShowSideProfile(v => !v)}>
                    {t('profileTitle')}
                  </Button>
                </Tooltip>
              ) : undefined}
              items={[
                {
                  key: 'incidents',
                  label: t('tabIncidents', { n: incidentCount ?? '-' }),
                  children: incidents.isError ? <LoadError error={incidents.error} onRetry={() => { incidents.refetch(); unresolved.refetch() }} /> : (
                    <>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
                        <Segmented
                          size="small"
                          value={incStatus}
                          onChange={v => { setIncStatus(String(v)); setIncPage(1) }}
                          options={[
                            { label: t('all'), value: '' },
                            { label: t('statusUnresolved'), value: 'unresolved' },
                            { label: t('statusOpen'), value: 'open' },
                            { label: t('statusTriaged'), value: 'triaged' },
                            { label: t('statusClosed'), value: 'closed' },
                            { label: t('statusFalsePositive'), value: 'false_positive' },
                          ]}
                        />
                        <Input allowClear size="small" prefix={<SearchOutlined style={{ color: token.colorTextQuaternary }} />}
                          placeholder={t('searchIncidents')} value={incQ} onChange={e => setIncQ(e.target.value)} style={{ width: 220 }} />
                      </div>
                      <Table<IncidentSummary> size="small" rowKey="id" rowClassName="row-link" onRow={rowLink} loading={incidents.isPending} dataSource={filteredIncidents}
                        pagination={{ current: incPage, pageSize: INCIDENT_PAGE, total: incQ ? filteredIncidents.length : incidents.data?.total, showSizeChanger: false, hideOnSinglePage: true, onChange: setIncPage }}
                        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIncidents')} /> }}
                        columns={[
                          { title: t('thSeverity'), dataIndex: 'severity', width: 95, sorter: (a, b) => a.severity - b.severity, render: v => <SeverityTag value={v} /> },
                          { title: t('thTitle'), dataIndex: 'title', ellipsis: wideTable, render: (v, r) => <Link to={`/incidents/${r.id}`} style={{ overflowWrap: 'anywhere' }}>{v ?? r.id}</Link> },
                          { title: t('thStatus'), dataIndex: 'status', width: 110, sorter: (a, b) => a.status.localeCompare(b.status), render: (v, r) => <Space size={4} wrap><IncidentStatusTag value={v} retriage={r.retriage} triageStartedAt={r.triageStartedAt} /></Space> },
                          { responsive: WIDE_ONLY, title: t('thCreatedAt'), dataIndex: 'createdAt', width: 170, sorter: (a, b) => a.createdAt.localeCompare(b.createdAt), render: fmtTime },
                        ]} />
                    </>
                  ),
                },
                {
                  key: 'findings',
                  label: t('tabFindings', { n: openFindingCount ?? '-' }),
                  children: findings.isError ? <LoadError error={findings.error} onRetry={() => { findings.refetch(); findingCount.refetch() }} /> : (
                    <>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
                        <Segmented
                          size="small"
                          value={findingStatus}
                          onChange={v => { setFindingStatus(String(v)); setFindingPage(1) }}
                          options={[
                            { label: t('all'), value: '' },
                            { label: t('findingOpen'), value: 'open' },
                            { label: t('findingResolved'), value: 'resolved' },
                            { label: t('findingIgnored'), value: 'ignored' },
                          ]}
                        />
                        <Input allowClear size="small" prefix={<SearchOutlined style={{ color: token.colorTextQuaternary }} />}
                          placeholder={t('searchFindings')} value={findingQ} onChange={e => setFindingQ(e.target.value)} style={{ width: 220 }} />
                      </div>
                      <Table<FindingRow> size="small" rowKey="id" scroll={{ x: 700 }} loading={findings.isPending} dataSource={filteredFindings}
                        pagination={{ current: findingPage, pageSize: 10, total: findingQ ? filteredFindings.length : findings.data?.total, showSizeChanger: false, hideOnSinglePage: true, onChange: setFindingPage }}
                        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noFindings')} /> }}
                        expandable={{ expandedRowRender: f => <div className="ev-expand"><pre className="json-block" style={{ whiteSpace: 'pre-wrap' }}>{f.detail || '-'}</pre></div> }}
                        columns={[
                          { title: t('thSeverity'), dataIndex: 'severity', width: 95, sorter: (a, b) => FINDING_SEVERITY[a.severity] - FINDING_SEVERITY[b.severity], render: v => <SeverityTag value={FINDING_SEVERITY[v as FindingRow['severity']]} /> },
                          { title: t('thTitle'), dataIndex: 'title', ellipsis: wideTable, render: v => <span style={{ overflowWrap: 'anywhere' }}>{v}</span> },
                          { title: t('thStatus'), dataIndex: 'status', width: 100, sorter: (a, b) => a.status.localeCompare(b.status), render: v => <Tag>{t(FINDING_STATUS_KEY[v as FindingRow['status']])}</Tag> },
                          { title: t('thLastConfirmed'), dataIndex: 'lastSeen', width: 170, sorter: (a, b) => a.lastSeen.localeCompare(b.lastSeen), render: fmtTime },
                        ]} />
                    </>
                  ),
                },
                {
                  key: 'events',
                  label: t('tabEvents'),
                  children: events.isError ? <LoadError error={events.error} onRetry={() => events.refetch()} /> : (
                    <>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
                        <Space wrap>
                          <Input allowClear size="small" prefix={<SearchOutlined style={{ color: token.colorTextQuaternary }} />}
                            placeholder={t('eventSearchHint')} value={eventQ} onChange={e => setEventQ(e.target.value)} style={{ width: 240 }} />
                          <Select
                            allowClear
                            size="small"
                            placeholder={t('allClasses')}
                            value={eventClass}
                            onChange={setEventClass}
                            style={{ width: 140 }}
                            options={Object.entries(CLASS_KEY).map(([k, label]) => ({ value: Number(k), label: t(label) }))}
                          />
                        </Space>
                        <Button size="small" type="link" icon={<SearchOutlined />} onClick={() => navigate(`/events?assetId=${asset.id}`)}>
                          {t('openInEvents')}
                        </Button>
                      </div>
                      {events.data?.truncated && <Alert type="info" showIcon title={t('listTruncated', { n: events.data.items.length })} style={{ marginBottom: 12 }} />}
                      <Table<EventRow> size="small" rowKey="id" scroll={{ x: 700 }} loading={events.isPending} dataSource={filteredEvents} pagination={{ pageSize: 20, hideOnSinglePage: true }}
                        expandable={{ expandedRowRender: r => <pre className="json-block">{JSON.stringify(r.raw, null, 2)}</pre> }}
                        columns={[
                          { title: t('thTime'), dataIndex: 'ts', sorter: (a, b) => a.ts.localeCompare(b.ts), render: fmtTime, width: 170 },
                          { title: t('thClass'), dataIndex: 'classUid', width: 100, sorter: (a, b) => a.classUid - b.classUid, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v) },
                          { title: t('thDetail'), ellipsis: true, render: (_, r) => <span className="mono">{eventSummary(r.classUid, r.raw, t) || r.connTuple || '-'}</span> },
                          { title: t('thUser'), dataIndex: 'username', width: 120, sorter: (a, b) => (a.username ?? '').localeCompare(b.username ?? ''), render: v => v ?? '-' },
                        ]} />
                    </>
                  ),
                },
                {
                  key: 'commands',
                  label: t('tabCommands'),
                  children: commands.isError ? <LoadError error={commands.error} onRetry={() => commands.refetch()} /> : (
                    <Table<CommandRow> size="small" rowKey="id" scroll={{ x: 1140 }} loading={commands.isPending} dataSource={commands.data?.items ?? []} pagination={{ current: commandPage, pageSize: 10, total: commands.data?.total ?? 0, onChange: setCommandPage, showSizeChanger: false, hideOnSinglePage: true }}
                      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noCommands')} /> }}
                      columns={[
                        { title: t('thTime'), dataIndex: 'createdAt', sorter: (a, b) => a.createdAt.localeCompare(b.createdAt), render: fmtTime, width: 170 },
                        { title: t('thAction'), dataIndex: 'kind', width: 200, sorter: (a, b) => a.kind.localeCompare(b.kind), render: (v, c) => <>{commandKind(v, t)}{c.target && <Typography.Text className="mono" type="secondary" style={{ display: 'block', fontSize: 12 }}>{c.target}</Typography.Text>}</> },
                        { title: t('thStatus'), dataIndex: 'status', width: 100, sorter: (a, b) => a.status.localeCompare(b.status), render: v => <CommandStatusTag value={v} /> },
                        { title: t('thCreatedBy'), dataIndex: 'issuedBy', width: 110, sorter: (a, b) => a.issuedBy.localeCompare(b.issuedBy) },
                        { title: t('verificationTitle'), width: 100, render: (_, row: CommandRow) => <Button size="small" onClick={() => setVerifying(row)}>{t('verificationTitle')}</Button> },
                        { title: t('thResult'), width: 140, render: (_, row) => <Button type="link" onClick={() => setCommandDetail(row.id)}>{t('commandViewDetail')}</Button> },
                        {
                          title: t('thDetections'), dataIndex: 'detections', width: 220,
                          render: (v: CommandRow['detections']) => v?.length
                            ? <Tooltip title={t('commandDetectionsHint')}>{v.map(d => <Tag key={d.ruleId} color="orange" variant="filled" title={d.author && t('ruleBy', { author: d.author })}>{d.title || d.ruleId} ×{d.count}</Tag>)}</Tooltip>
                            : null,
                        },
                      ]} />
                  ),
                },
                { key: 'vulns', label: t('tabVulns'), children: tab === 'vulns' ? <AssetVulns key={asset.id} assetId={asset.id} /> : null },
                { key: 'localAccounts', label: t('collectorLocalAccounts'), children: tab === 'localAccounts' ? <LocalAccounts key={asset.id} asset={asset} /> : null },
                { key: 'identity', label: t('identityTitle'), children: tab === 'identity' ? <IdentityObservations key={asset.id} asset={asset} /> : null },
                { key: 'detectionGaps', label: t('temporalGapsTitle'), children: tab === 'detectionGaps' ? <TemporalGaps key={asset.id} asset={asset} /> : null },
                {
                  key: 'config',
                  label: (
                    <Space size={6}>
                      {collectorDegraded && <Badge status="warning" />}
                      {t('tabCollector')}
                    </Space>
                  ),
                  children: (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                      {(asset.agentId || !asset.sensorSeen) && <CollectorHealth asset={asset} />}
                      {asset.sensorSeen && <SensorHealth asset={asset} />}
                      <ConfigTab assetId={asset.id} canEdit={canAct} />
                    </div>
                  ),
                },
                ...(!showSideProfile || !wideTable ? [{
                  key: 'profile',
                  label: t('tabProfile'),
                  children: <AssetProfileView assetId={asset.id} hostname={asset.hostname} groupId={asset.groupId} canEdit={canAct} isGroupAdmin={isAdmin || group?.role === 'admin'} noAgent={!asset.agentId} />,
                }] : []),
              ]}
            />
          </Card>
        </Col>

        {showSideProfile && tab !== 'profile' && (
          <Col xs={24} xl={8}>
            <Card title={t('profileTitle')}>
              <AssetProfileView assetId={asset.id} hostname={asset.hostname} groupId={asset.groupId} canEdit={canAct} isGroupAdmin={isAdmin || group?.role === 'admin'} compact noAgent={!asset.agentId} />
            </Card>
          </Col>
        )}
      </Row>
    </Page>
  )
}

const FINDING_STATUS_KEY: Record<FindingRow['status'], MsgKey> = { open: 'findingOpen', resolved: 'findingResolved', ignored: 'findingIgnored' }
