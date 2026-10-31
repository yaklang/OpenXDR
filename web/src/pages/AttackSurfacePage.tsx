import { ApartmentOutlined, DeleteOutlined, PlusOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Col, Descriptions, Drawer, Empty, Flex, Form, Input, Modal, Popconfirm, Row, Segmented, Select, Skeleton, Space, Switch, Table, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useMemo, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import {
  createZone, deleteZone, fetchAttackSurface, fetchVulnSummary, fetchZones, saveServiceNote, updateZone, type BlindSpot, type ExposedService, type ServiceNote, type ZoneKind, type ZoneRow,
} from '../api'
import { useCanAct, useSession } from '../app/session'
import { useCanChat, useHandoff } from '../components/Handoff'
import { SurfaceGraph } from '../components/SurfaceGraph'
import { CritTag, ExposureTag, ZoneTag, useZoneColor } from '../components/AssetProfile'
import { LoadError } from '../components/LoadError'
import { ScoreTag } from '../components/AssetVulns'
import { Page, TableCard } from '../components/Page'
import { errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const RISK: Record<string, { key: MsgKey; color: string; rank: number }> = {
  high: { key: 'riskHigh', color: 'red', rank: 3 },
  medium: { key: 'riskMedium', color: 'orange', rank: 2 },
  low: { key: 'riskLow', color: 'default', rank: 1 },
}

const LEVEL_RANK: Record<string, number> = { internet: 3, dmz: 2, internal: 1 }

function Stat({ label, value, tone, active, onClick }: { label: string; value: ReactNode; tone?: string; active?: boolean; onClick?: () => void }) {
  const { token } = theme.useToken()
  return (
    <Card size="small" hoverable={!!onClick} onClick={onClick}
      style={{
        borderColor: active ? token.colorPrimaryBorder : undefined,
        background: active ? token.colorPrimaryBg : undefined,
      }}
      styles={{ body: { padding: '18px 22px' } }}>
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>{label}</Typography.Text>
      <div style={{ fontSize: 26, fontWeight: 600, marginTop: 4, color: tone ?? token.colorText, fontVariantNumeric: 'tabular-nums' }}>{value}</div>
    </Card>
  )
}

export function AttackSurfacePage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { group, isAdmin } = useSession()
  const [zonesOpen, setZonesOpen] = useState(false)
  const [view, setView] = useState<'graph' | 'list'>('graph')
  const [hideLow, setHideLow] = useState(true)
  const [q, setQ] = useState('')
  const [levelFilter, setLevelFilter] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [picked, setPicked] = useState<ExposedService | null>(null)
  const blindRef = useRef<HTMLDivElement>(null)
  const query = useQuery({ queryKey: ['attackSurface', group?.id], queryFn: () => fetchAttackSurface(group!.id), enabled: !!group })
  // 暴露服务的已知漏洞：按资产拿汇总，用服务进程所属的包对上
  const vulns = useQuery({ queryKey: ['vuln-summary'], queryFn: fetchVulnSummary })
  const vulnOf = (e: ExposedService) => e.package
    ? vulns.data?.find(v => v.assetId === e.assetId)?.exposedPackages?.find(p => p.binaries.includes(e.package!))
    : undefined
  const s = query.data
  const isGroupAdmin = isAdmin || group?.role === 'admin'
  // 刷新后抽屉里显示最新数据（调查或标注会改它）
  const current = picked && s?.exposures.find(e => e.assetId === picked.assetId && e.proto === picked.proto && e.port === picked.port)

  const activeQ = q.trim().toLowerCase()
  const hasFilters = Boolean(activeQ || levelFilter || riskFilter)
  const filteredExposures = useMemo(() => (s?.exposures ?? []).filter(e =>
    (!levelFilter || e.level === levelFilter) &&
    (!riskFilter || e.service.risk === riskFilter) &&
    (!activeQ ||
      e.hostname.toLowerCase().includes(activeQ) ||
      `${e.proto}/${e.port}`.toLowerCase().includes(activeQ) ||
      (e.service.name ?? '').toLowerCase().includes(activeQ) ||
      (e.process ?? '').toLowerCase().includes(activeQ) ||
      (e.note?.note ?? '').toLowerCase().includes(activeQ) ||
      e.addrs.some(a => a.toLowerCase().includes(activeQ)))
  ), [s?.exposures, levelFilter, riskFilter, activeQ])

  const quickFilterLevel = (lvl: string) => {
    setView('list')
    setRiskFilter('')
    setLevelFilter(prev => prev === lvl ? '' : lvl)
  }

  return (
    <Page title={t('navAttackSurface')} subtitle={t('surfaceSubtitle')}
      extra={group && <Button icon={<ApartmentOutlined />} onClick={() => setZonesOpen(true)}>{t('manageZones')}</Button>}>
      {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : (
        <Flex vertical gap={20}>
          <Row gutter={[20, 20]}>
            <Col xs={12} md={8} xl={{ flex: '20%' }}><Stat label={t('surfInternet')} value={s?.summary.internet ?? '-'} tone={s?.summary.internet ? token.colorError : undefined} active={view === 'list' && levelFilter === 'internet'} onClick={() => quickFilterLevel('internet')} /></Col>
            <Col xs={12} md={8} xl={{ flex: '20%' }}><Stat label={t('surfDmz')} value={s?.summary.dmz ?? '-'} tone={s?.summary.dmz ? token.colorWarning : undefined} active={view === 'list' && levelFilter === 'dmz'} onClick={() => quickFilterLevel('dmz')} /></Col>
            <Col xs={12} md={8} xl={{ flex: '20%' }}><Stat label={t('surfInternal')} value={s?.summary.internal ?? '-'} active={view === 'list' && levelFilter === 'internal'} onClick={() => quickFilterLevel('internal')} /></Col>
            <Col xs={12} md={8} xl={{ flex: '20%' }}><Stat label={t('surfHigh')} value={s?.summary.high ?? '-'} tone={s?.summary.high ? token.colorError : undefined} active={view === 'list' && riskFilter === 'high'} onClick={() => { setView('list'); setLevelFilter(''); setRiskFilter(prev => prev === 'high' ? '' : 'high') }} /></Col>
            <Col xs={12} md={8} xl={{ flex: '20%' }}><Stat label={t('surfBlind')} value={s?.summary.blind ?? '-'} tone={s?.summary.blind ? token.colorWarning : undefined} onClick={() => blindRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })} /></Col>
          </Row>
          {!!s?.summary.noInventory.length && (
            <Alert type="info" showIcon title={t('surfNoInventory', { n: s.summary.noInventory.length, hosts: s.summary.noInventory.slice(0, 8).join('、') })} />
          )}
          <TableCard title={t('exposuresTitle')}
            extra={<Space wrap>
              {view === 'list' && (
                <>
                  {hasFilters && s && <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: filteredExposures.length, total: s.exposures.length })}</Typography.Text>}
                  <Input.Search allowClear size="small" style={{ width: 220 }} placeholder={t('searchSurface')} value={q} onChange={e => setQ(e.target.value)} />
                  <Select size="small" aria-label={t('thLevel')} style={{ width: 135 }} value={levelFilter} onChange={setLevelFilter}
                    options={[
                      { value: '', label: t('allLevels') },
                      { value: 'internet', label: t('exposureInternet') },
                      { value: 'dmz', label: t('exposureDmz') },
                      { value: 'internal', label: t('exposureInternal') },
                    ]}
                  />
                  <Select size="small" aria-label={t('serviceRisk')} style={{ width: 130 }} value={riskFilter} onChange={setRiskFilter}
                    options={[
                      { value: '', label: t('allRisks') },
                      { value: 'high', label: t('riskHigh') },
                      { value: 'medium', label: t('riskMedium') },
                      { value: 'low', label: t('riskLow') },
                    ]}
                  />
                  {hasFilters && <Button size="small" type="link" onClick={() => { setQ(''); setLevelFilter(''); setRiskFilter('') }}>{t('resetFilters')}</Button>}
                </>
              )}
              <Typography.Text className="card-hint" type="secondary" style={{ fontSize: 12 }}>{view === 'graph' ? t('surfaceGraphHint') : t('portGuessHint')}</Typography.Text>
              {view === 'graph' && <Space size={6}><Switch size="small" checked={hideLow} onChange={setHideLow} aria-label={t('hideLowRisk')} />{t('hideLowRisk')}</Space>}
              <Segmented size="small" value={view} onChange={v => setView(v as 'graph' | 'list')}
                options={[{ value: 'graph', label: t('viewGraph') }, { value: 'list', label: t('viewList') }]} />
            </Space>}>
            {view === 'graph' ? (s ? <SurfaceGraph surface={s} hideLow={hideLow} onPick={setPicked} /> : <Skeleton active style={{ padding: 24 }} />) : <Table<ExposedService> rowKey={e => `${e.assetId}/${e.proto}/${e.port}`} loading={query.isPending} dataSource={filteredExposures}
              scroll={{ x: 1100 }} pagination={{ defaultPageSize: 20, showSizeChanger: true, hideOnSinglePage: true }}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t(hasFilters ? 'noMatch' : 'surfaceEmpty')} /> }}
              columns={[
                { title: t('thScore'), dataIndex: 'score', width: 96, sorter: (a, b) => a.score - b.score, render: v => <Typography.Text strong>{v}</Typography.Text> },
                { title: t('thHostname'), dataIndex: 'hostname', width: 150, sorter: (a, b) => a.hostname.localeCompare(b.hostname), render: (v, e) => <Link to={`/assets/${e.assetId}`}>{v}</Link> },
                { title: t('thService'), width: 260, sorter: (a, b) => a.port - b.port, render: (_, e) => (
                  <Space size={4} wrap>
                    <span className="mono">{e.proto}/{e.port}</span>
                    <Typography.Text type={e.service.name ? 'secondary' : 'warning'}>{e.service.name || t('serviceUnknown')}</Typography.Text>
                    {e.note && <NoteTag note={e.note} />}
                    <Tag color={RISK[e.service.risk].color}>{t(RISK[e.service.risk].key)}</Tag>
                  </Space>
                ) },
                { title: t('thLevel'), dataIndex: 'level', width: 130, sorter: (a, b) => (LEVEL_RANK[a.level] ?? 0) - (LEVEL_RANK[b.level] ?? 0), render: (v, e) => <Space size={4} wrap><ExposureTag level={v} />{e.fromPublic && <Tag color="volcano">{t('fromPublicTag')}</Tag>}</Space> },
                { title: t('zoneLabel'), width: 120, render: (_, e) => <ZoneTag zone={e.zone} /> },
                { title: t('criticality'), dataIndex: 'criticality', width: 110, sorter: (a, b) => (a.criticality ?? 0) - (b.criticality ?? 0), render: v => <CritTag value={v} /> },
                { title: t('listenProcess'), dataIndex: 'process', width: 130, sorter: (a, b) => (a.process ?? '').localeCompare(b.process ?? ''), render: v => v ?? '-' },
                {
                  title: t('tabVulns'), width: 150, render: (_, e) => {
                    const v = vulnOf(e)
                    return v ? <Link to={`/assets/${e.assetId}?tab=vulns`} style={{ whiteSpace: 'nowrap' }}><ScoreTag score={v.maxScore} />{t('vulnOnSurface', { n: v.vulns })}</Link> : '-'
                  },
                },
                { title: t('thBind'), dataIndex: 'addrs', width: 150, render: (v: string[]) => <span className="mono">{v.join(', ')}</span> },
                { title: t('thPeers'), sorter: (a, b) => a.peerCount - b.peerCount, render: (_, e) => e.peerCount === 0 ? '-' : (
                  <Tooltip title={(e.peers ?? []).join(', ')}>
                    <span>{(e.peers ?? []).slice(0, 3).join(', ')}{e.peerCount > 3 && ` +${e.peerCount - 3}`}</span>
                  </Tooltip>
                ) },
                { title: t('actions'), width: 90, fixed: 'right', render: (_, e) => <Button type="link" size="small" onClick={() => setPicked(e)}>{t('serviceDetail')}</Button> },
              ]} />}
          </TableCard>
          <div ref={blindRef} style={{ scrollMarginTop: 72 }}>
            <TableCard title={t('blindTitle')}>
              <Table<BlindSpot> rowKey="ip" loading={query.isPending} dataSource={s?.blind ?? []} pagination={{ defaultPageSize: 10, showSizeChanger: true, hideOnSinglePage: true }}
                scroll={{ x: 900 }} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
                columns={[
                  { title: t('thIP'), dataIndex: 'ip', width: 165, sorter: (a, b) => a.ip.localeCompare(b.ip), render: v => <Typography.Text className="mono" copyable>{v}</Typography.Text> },
                  { title: t('zoneLabel'), width: 120, render: (_, b) => <ZoneTag zone={b.zone} /> },
                  { title: t('thPorts'), dataIndex: 'ports', render: (v: string[]) => v.length ? v.map(p => <Tag key={p} className="mono">{p}</Tag>) : '-' },
                  { title: t('thAccessed'), dataIndex: 'accessed', render: (v: string[]) => v.length ? v.map(p => <Tag key={p} className="mono">{p}</Tag>) : '-' },
                  { title: t('thSeenBy'), dataIndex: 'seenBy', render: (v: string[]) => v.join(', ') },
                  { title: t('thConnCount'), dataIndex: 'count', width: 115, align: 'right', sorter: (a, b) => a.count - b.count },
                  { title: t('thLastActive'), dataIndex: 'lastSeen', width: 170, sorter: (a, b) => a.lastSeen.localeCompare(b.lastSeen), render: fmtTime },
                ]} />
            </TableCard>
          </div>
        </Flex>
      )}
      {group && <ZonesDrawer open={zonesOpen} groupId={group.id} canEdit={isGroupAdmin} onClose={() => setZonesOpen(false)} />}
      {group && <ServiceDrawer service={current ?? null} groupId={group.id} onClose={() => setPicked(null)} />}
    </Page>
  )
}

const SOURCE: Record<ServiceNote['source'], MsgKey> = { ai: 'noteSourceAi', investigation: 'noteSourceInvestigation', human: 'noteSourceHuman' }

function NoteTag({ note }: { note: ServiceNote }) {
  const { t } = useI18n()
  return <Tooltip title={note.note}><Tag color={note.source === 'ai' ? 'purple' : 'cyan'}>{t(SOURCE[note.source])}</Tag></Tooltip>
}

// 服务详情：事实、说明的来源，以及「调查」（交给 AI 上机查）与「标注服务」（人工定名，优先级最高）
function ServiceDrawer({ service: e, groupId, onClose }: { service: ExposedService | null; groupId: string; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const canChat = useCanChat()(groupId)
  const canAct = useCanAct()(groupId)
  const handoff = useHandoff()
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm()
  if (!e) return <Drawer open={false} />
  const port = `${e.proto}/${e.port}`
  const level = t(({ internet: 'exposureInternet', dmz: 'exposureDmz', internal: 'exposureInternal' } as const)[e.level])

  const investigate = () => handoff.start(groupId, [], t('investigateServiceTitle', { host: e.hostname, port }), t('investigateServicePrompt', {
    host: e.hostname, id: e.assetId, port, addrs: e.addrs.join(', '), process: e.process || '-', level, peers: (e.peers ?? []).join(', ') || '-',
  }))
  const save = async (body: { name: string; note?: string; risk?: string }) => {
    setBusy(true)
    try {
      await saveServiceNote(e.assetId, { port, ...body })
      await client.invalidateQueries({ queryKey: ['attackSurface'] })
      client.invalidateQueries({ queryKey: ['assetProfile', e.assetId] })
      setEditing(false)
    } catch (err) {
      message.error(errText(err, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Drawer open size={460} title={<Space><span>{e.hostname}</span><span className="mono">{port}</span></Space>} onClose={onClose}
      extra={<Space>
        {canChat && <Button type="primary" icon={<SearchOutlined />} loading={handoff.busy} onClick={investigate}>{t('investigate')}</Button>}
        {canAct && <Button onClick={() => setEditing(true)}>{t('editService')}</Button>}
      </Space>}>
      <Descriptions column={1} size="small" styles={{ label: { width: 96 } }}>
        <Descriptions.Item label={t('thService')}>
          <Space size={4} wrap>
            <Typography.Text strong type={e.service.name ? undefined : 'warning'}>{e.service.name || t('serviceUnknown')}</Typography.Text>
            {e.note && <NoteTag note={e.note} />}
            <Tag color={RISK[e.service.risk].color}>{t(RISK[e.service.risk].key)}</Tag>
            {!e.note?.risk && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('riskByPort')}</Typography.Text>}
          </Space>
          {e.note && <div><Typography.Text type="secondary" style={{ fontSize: 12 }}>{[t(SOURCE[e.note.source]), e.note.source === 'human' ? e.note.by : null, fmtTime(e.note.at)].filter(Boolean).join(' · ')}</Typography.Text></div>}
        </Descriptions.Item>
        {e.note?.note && <Descriptions.Item label={t('serviceNoteLabel')}>{e.note.note}</Descriptions.Item>}
        <Descriptions.Item label={t('listenProcess')}>{e.process || '-'}</Descriptions.Item>
        <Descriptions.Item label={t('thBind')}><span className="mono">{e.addrs.join(', ')}</span></Descriptions.Item>
        <Descriptions.Item label={t('thLevel')}><Space size={4}><ExposureTag level={e.level} />{e.fromPublic && <Tag color="volcano">{t('fromPublicTag')}</Tag>}</Space></Descriptions.Item>
        <Descriptions.Item label={t('zoneLabel')}><ZoneTag zone={e.zone} /></Descriptions.Item>
        <Descriptions.Item label={t('criticality')}><CritTag value={e.criticality} /></Descriptions.Item>
        <Descriptions.Item label={t('thScore')}>{e.score}</Descriptions.Item>
        <Descriptions.Item label={t('thPeers')}>{e.peers?.length ? e.peers.map(p => <Tag key={p} className="mono">{p}</Tag>) : <Typography.Text type="secondary">{t('noPaths')}</Typography.Text>}</Descriptions.Item>
      </Descriptions>
      <Modal open={editing} title={t('editService')} confirmLoading={busy} destroyOnHidden onCancel={() => { if (!busy) setEditing(false) }} onOk={() => form.submit()}
        footer={(_, { OkBtn, CancelBtn }) => <Space>
          {e.note?.source === 'human' && <Button danger disabled={busy} onClick={() => save({ name: '' })}>{t('clearServiceNote')}</Button>}
          <CancelBtn /><OkBtn />
        </Space>}
        afterOpenChange={o => o && form.setFieldsValue({ name: e.service.name, note: e.note?.note ?? '', risk: e.note?.risk ?? '' })}>
        <Form form={form} layout="vertical" disabled={busy} onFinish={v => save({ name: v.name.trim(), note: v.note, risk: v.risk || undefined })}>
          <Form.Item name="name" label={t('serviceName')} rules={[{ required: true, whitespace: true, max: 32 }]}><Input /></Form.Item>
          <Form.Item name="risk" label={t('serviceRisk')}>
            <Select options={[{ value: '', label: t('riskByPort') }, ...(['high', 'medium', 'low'] as const).map(r => ({ value: r, label: t(RISK[r].key) }))]} />
          </Form.Item>
          <Form.Item name="note" label={t('serviceNoteLabel')} rules={[{ max: 300 }]}><Input.TextArea rows={3} /></Form.Item>
        </Form>
      </Modal>
    </Drawer>
  )
}

const KINDS: { value: ZoneKind; key: MsgKey }[] = [
  { value: 'internal', key: 'zoneInternal' }, { value: 'dmz', key: 'zoneDmz' }, { value: 'external', key: 'zoneExternal' }, { value: 'cloud', key: 'zoneCloud' },
]

// 区域定义：组 admin 可改，其余只读
function ZonesDrawer({ open, groupId, canEdit, onClose }: { open: boolean; groupId: string; canEdit: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const color = useZoneColor()
  const [editing, setEditing] = useState<ZoneRow | 'new' | null>(null)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm()
  const zones = useQuery({ queryKey: ['zones', groupId], queryFn: () => fetchZones(groupId), enabled: open })

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['zones', groupId] })
      client.invalidateQueries({ queryKey: ['attackSurface'] })
      client.invalidateQueries({ queryKey: ['assetMap'] })
      client.invalidateQueries({ queryKey: ['assetProfile'] })
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally {
      setBusy(false)
    }
  }
  const submit = async (v: { name: string; kind: ZoneKind; cidrs?: string }) => {
    const body = { name: v.name.trim(), kind: v.kind, cidrs: (v.cidrs ?? '').split(/[\s,]+/).filter(Boolean) }
    const ok = await run(() => editing === 'new' ? createZone({ groupId, ...body }) : updateZone((editing as ZoneRow).id, body))
    if (ok) setEditing(null)
  }

  return (
    <Drawer open={open} size={520} title={t('manageZones')} onClose={onClose}
      extra={canEdit && <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing('new')}>{t('newZone')}</Button>}>
      <Typography.Paragraph type="secondary">{t('zonesHint')}</Typography.Paragraph>
      {zones.isError ? <LoadError error={zones.error} onRetry={() => zones.refetch()} /> : (
        zones.isPending ? <Skeleton active /> : !zones.data?.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noZones')} /> : (
          <Flex vertical gap={8}>
            {zones.data.map(z => (
              <Card key={z.id} size="small">
                <Flex justify="space-between" align="center" gap={8}>
                  <Space orientation="vertical" size={4} style={{ minWidth: 0 }}>
                    <Space><Tag color={color(z.kind)} variant="outlined">{t(KINDS.find(k => k.value === z.kind)!.key)}</Tag><Typography.Text strong>{z.name}</Typography.Text></Space>
                    <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{(z.cidrs ?? []).join(', ') || '-'}</Typography.Text>
                  </Space>
                  {canEdit && (
                    <Space size={0}>
                      <Button type="link" size="small" onClick={() => setEditing(z)}>{t('editProfile')}</Button>
                      <Popconfirm title={t('zoneDeleteConfirm', { name: z.name })} onConfirm={() => run(() => deleteZone(z.id))}>
                        <Button type="link" size="small" danger icon={<DeleteOutlined />} aria-label={t('del')} />
                      </Popconfirm>
                    </Space>
                  )}
                </Flex>
              </Card>
            ))}
          </Flex>
        )
      )}
      <Modal open={!!editing} title={editing === 'new' ? t('newZone') : t('editProfile')} confirmLoading={busy} destroyOnHidden
        onCancel={() => { if (!busy) setEditing(null) }} onOk={() => form.submit()}
        afterOpenChange={o => o && form.setFieldsValue(editing && editing !== 'new'
          ? { name: editing.name, kind: editing.kind, cidrs: (editing.cidrs ?? []).join('\n') }
          : { name: '', kind: 'dmz', cidrs: '' })}>
        <Form form={form} layout="vertical" disabled={busy} onFinish={submit}>
          <Form.Item name="name" label={t('zoneName')} rules={[{ required: true, whitespace: true, max: 64 }]}><Input /></Form.Item>
          <Form.Item name="kind" label={t('zoneKind')}><Select options={KINDS.map(k => ({ value: k.value, label: t(k.key) }))} /></Form.Item>
          <Form.Item name="cidrs" label={t('zoneCidrs')} extra={t('zoneCidrsHint')}><Input.TextArea rows={4} className="mono" /></Form.Item>
        </Form>
      </Modal>
    </Drawer>
  )
}
