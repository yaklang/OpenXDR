import { EditOutlined, LockOutlined, ReloadOutlined, UnlockOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App, Alert, Button, Descriptions, Empty, Flex, Form, Input, Modal, Rate, Select, Skeleton, Space, Table, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useState } from 'react'
import {
  assignAssetZone, fetchAssetProfile, fetchZones, requestAnnotate, saveAssetProfile,
  type AssetProfile, type ExposureLevel, type Listener, type PeerStat, type ProfileEdit, type ZoneKind, type ZoneRef,
} from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { Ago } from './Ago'
import { LoadError } from './LoadError'
import { PublicDestList } from './PublicDests'
import { errText, fmtTime } from './format'

const ZONE_KEY: Record<ZoneKind, MsgKey> = { internal: 'zoneInternal', dmz: 'zoneDmz', external: 'zoneExternal', cloud: 'zoneCloud' }
const SOURCE_KEY: Record<ZoneRef['source'], MsgKey> = { manual: 'zoneSourceManual', cidr: 'zoneSourceCidr', cloud: 'zoneSourceCloud', auto: 'zoneSourceAuto' }
const CLOUD_KEY: Record<string, MsgKey> = { aws: 'cloudAws', azure: 'cloudAzure', gcp: 'cloudGcp', aliyun: 'cloudAliyun', tencent: 'cloudTencent' }
const EXPOSURE_KEY: Record<ExposureLevel, MsgKey> = { internet: 'exposureInternet', dmz: 'exposureDmz', internal: 'exposureInternal' }
export const CRIT_KEY: Record<number, MsgKey> = { 1: 'crit1', 2: 'crit2', 3: 'crit3', 4: 'crit4', 5: 'crit5' }

// 区域颜色：公网红、隔离区橙、云上蓝、内网绿，图谱与表格同一套
export function useZoneColor() {
  const { token } = theme.useToken()
  return (kind: ZoneKind) => ({ external: token.colorError, dmz: token.colorWarning, cloud: token.colorInfo, internal: token.colorSuccess })[kind]
}

export function zoneName(z: ZoneRef, t: (k: MsgKey) => string) {
  if (z.source === 'cloud') return CLOUD_KEY[z.name] ? t(CLOUD_KEY[z.name]) : z.name
  return z.name || t(ZONE_KEY[z.kind])
}

export function ZoneTag({ zone, detail }: { zone: ZoneRef; detail?: boolean }) {
  const { t } = useI18n()
  const color = useZoneColor()(zone.kind)
  return (
    <Tooltip title={`${t(ZONE_KEY[zone.kind])} · ${t(SOURCE_KEY[zone.source])}`}>
      <Tag color={color} variant="outlined">{zoneName(zone, t)}{detail && zone.name && ` · ${t(ZONE_KEY[zone.kind])}`}</Tag>
    </Tooltip>
  )
}

export function ExposureTag({ level }: { level: ExposureLevel }) {
  const { t } = useI18n()
  const color = { internet: 'error', dmz: 'warning', internal: 'default' }[level]
  return <Tag color={color}>{t(EXPOSURE_KEY[level])}</Tag>
}

export function CritTag({ value }: { value?: number | null }) {
  const { t } = useI18n()
  if (!value) return <Typography.Text type="secondary">-</Typography.Text>
  const color = value >= 5 ? 'red' : value === 4 ? 'orange' : value === 3 ? 'blue' : 'default'
  return <Tag color={color}>{value} · {t(CRIT_KEY[value])}</Tag>
}

function Locked({ locked }: { locked: boolean }) {
  const { t } = useI18n()
  return locked ? <Tooltip title={t('lockedByHuman')}><LockOutlined style={{ marginLeft: 6, fontSize: 12, opacity: 0.6 }} /></Tooltip> : null
}

// 监听端口：同一端口 IPv4 / IPv6 各报一条，合成一行；只绑回环的另列，默认收起
interface Port { key: string; proto: string; port: number; addrs: string[]; process?: string; path?: string }
const loopback = (a: string) => a.startsWith('127.') || a === '::1'
const anyAddr = (a: string) => a === '0.0.0.0' || a === '::' || a === '*'

function mergePorts(ls: Listener[]): Port[] {
  const by = new Map<string, Port>()
  for (const l of ls) {
    const key = `${l.proto}/${l.port}/${l.process ?? ''}`
    const p = by.get(key) ?? { key, proto: l.proto, port: l.port, addrs: [], process: l.process, path: l.path }
    if (!p.addrs.includes(l.addr)) p.addrs.push(l.addr)
    by.set(key, p)
  }
  return [...by.values()].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto))
}

// 依赖：后端给的是「对端:端口 ← 进程」与「对端 → 端口」，按对端合并，端口与进程并列，配上 AI 的关系说明
interface Peer { peer: string; ports: string[]; procs: string[] }
function groupPeers(items: string[], dir: 'outbound' | 'inbound'): Peer[] {
  const by = new Map<string, Peer>()
  for (const s of items) {
    let peer: string, port: string, procs: string[] = []
    if (dir === 'outbound') {
      const [target, who = ''] = s.split(' ← ')
      const i = target.lastIndexOf(':')
      peer = target.slice(0, i)
      port = target.slice(i + 1)
      procs = who.split(', ').filter(p => p && p !== '?')
    } else {
      [peer, port] = s.split(' → ')
    }
    const p = by.get(peer) ?? { peer, ports: [], procs: [] }
    if (port && !p.ports.includes(port)) p.ports.push(port)
    for (const x of procs) if (!p.procs.includes(x)) p.procs.push(x)
    by.set(peer, p)
  }
  return [...by.values()]
}

function PeerList({ items, notes, stats }: { items: Peer[]; notes: Record<string, string>; stats: Record<string, PeerStat> }) {
  const { t } = useI18n()
  const [all, setAll] = useState(false)
  // 有关系说明的排前面（AI 认出来的往往是关键依赖），再按连接次数
  const count = (p: Peer) => stats[p.peer]?.count ?? 0
  const sorted = [...items].sort((a, b) => Number(!!notes[b.peer]) - Number(!!notes[a.peer]) || count(b) - count(a) || a.peer.localeCompare(b.peer))
  const shown = all ? sorted : sorted.slice(0, 8)
  if (!items.length) return <Typography.Text type="secondary">-</Typography.Text>
  return (
    <div className="dest-list">
      {shown.map(p => (
        <div key={p.peer} className="dest-row">
          <div className="dest-main">
            <Space size={6} wrap>
              <Typography.Text className={/^[\d.:a-f]+$/i.test(p.peer) ? 'mono' : undefined} strong>{p.peer}</Typography.Text>
              <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{p.ports.join(' ')}</Typography.Text>
              {stats[p.peer] && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {t('connCount', { n: stats[p.peer].count.toLocaleString() })} · <Ago iso={stats[p.peer].lastSeen} />
                </Typography.Text>
              )}
            </Space>
            {(notes[p.peer] || p.procs.length > 0) && (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {[notes[p.peer], p.procs.length ? t('viaProcess', { p: p.procs.join(', ') }) : ''].filter(Boolean).join(' · ')}
              </Typography.Text>
            )}
          </div>
        </div>
      ))}
      {items.length > 8 && <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setAll(!all)}>{all ? t('collapse') : t('showAllN', { n: items.length })}</Button>}
    </div>
  )
}

// 资产画像：AI 标注 + 采集到的事实。组 analyst 能改标注，组 admin 能指派区域
export function AssetProfileView({ assetId, hostname, groupId, canEdit, isGroupAdmin, compact, noAgent }: {
  assetId: string; hostname: string; groupId?: string | null; canEdit: boolean; isGroupAdmin: boolean; compact?: boolean
  // 只有流量探针、没装 agent 的主机：监听端口要 agent 才采得到，别提示「升级 agent」
  noAgent?: boolean
}) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [showLocal, setShowLocal] = useState(false)
  const profile = useQuery({ queryKey: ['assetProfile', assetId], queryFn: () => fetchAssetProfile(assetId) })
  const zones = useQuery({ queryKey: ['zones', groupId], queryFn: () => fetchZones(groupId!), enabled: !!groupId && isGroupAdmin })

  if (profile.isPending) return <Skeleton active />
  if (profile.isError) return <LoadError error={profile.error} onRetry={() => profile.refetch()} />
  const p = profile.data
  const locked = (f: string) => !!p.lockedFields?.includes(f)

  const run = async (fn: () => Promise<void>, ok?: string) => {
    setBusy(true)
    try {
      await fn()
      if (ok) message.success(ok)
      await client.invalidateQueries({ queryKey: ['assetProfile', assetId] })
      client.invalidateQueries({ queryKey: ['assetMap'] })
      client.invalidateQueries({ queryKey: ['attackSurface'] })
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally {
      setBusy(false)
    }
  }

  const annotation = !p.aiEnabled
    ? <Typography.Text type="secondary">{t('aiDisabledHint')}</Typography.Text>
    : p.annotateRequestedAt ? <Typography.Text type="secondary">{t('annotatePending')}</Typography.Text>
      : p.annotatedAt ? <Typography.Text type="secondary">{t('annotatedAt', { time: fmtTime(p.annotatedAt) })}</Typography.Text>
        : <Typography.Text type="secondary">{t('notAnnotated')}</Typography.Text>

  return (
    <Space orientation="vertical" size={20} style={{ width: '100%' }}>
      {/* 说明文字可以折行，按钮固定在右侧，卡片窄时不被挤到下一行 */}
      <Flex justify="space-between" align="center" gap={8} className="cmd-item">
        <div style={{ minWidth: 0 }}>{annotation}</div>
        {canEdit && (
          <Space size={6} style={{ flex: 'none' }}>
            <Button size="small" icon={<EditOutlined />} onClick={() => setEditing(true)}>{t('editProfile')}</Button>
            {p.aiEnabled && <Button size="small" icon={<ReloadOutlined />} loading={busy} disabled={!!p.annotateRequestedAt}
              onClick={() => run(() => requestAnnotate(assetId), t('annotateQueued'))}>{t('reannotate')}</Button>}
          </Space>
        )}
      </Flex>

      <Descriptions column={1} size="small" styles={{ label: { width: compact ? 88 : 110 } }}>
        <Descriptions.Item label={t('role')}>{p.role ? <Typography.Text strong>{p.role}</Typography.Text> : '-'}<Locked locked={locked('role')} /></Descriptions.Item>
        <Descriptions.Item label={t('criticality')}><CritTag value={p.criticality} /><Locked locked={locked('criticality')} /></Descriptions.Item>
        <Descriptions.Item label={t('summaryLabel')}>{p.summary || '-'}<Locked locked={locked('summary')} /></Descriptions.Item>
        {p.reason && <Descriptions.Item label={t('reasonLabel')}><Typography.Text type="secondary">{p.reason}</Typography.Text></Descriptions.Item>}
        <Descriptions.Item label={t('zoneLabel')}>
          <Space size={4} wrap>
            <ZoneTag zone={p.zone} detail />
            {isGroupAdmin && groupId && (
              <Select size="small" style={{ minWidth: 140 }} loading={zones.isPending} disabled={busy}
                value={p.zone.source === 'manual' ? p.zone.id : ''}
                onChange={v => run(() => assignAssetZone(assetId, v || null))}
                options={[{ value: '', label: t('zoneAuto') }, ...(zones.data ?? []).map(z => ({ value: z.id, label: z.name }))]} />
            )}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label={t('exposureLabel')}><ExposureTag level={p.exposure} /></Descriptions.Item>
        {p.cloud && (
          <Descriptions.Item label={t('cloudLabel')}>
            {[CLOUD_KEY[p.cloud.provider] ? t(CLOUD_KEY[p.cloud.provider]) : p.cloud.provider, p.cloud.region, p.cloud.instanceId, p.cloud.publicIp].filter(Boolean).join(' · ')}
          </Descriptions.Item>
        )}
      </Descriptions>

      <div>
        <Typography.Text strong>{t('listeningPorts')}</Typography.Text>
        {!p.inventoryAt ? <Alert type="info" showIcon style={{ marginTop: 8 }} title={t(noAgent ? 'noInventoryNoAgent' : 'noInventory')} /> : (() => {
          const ports = mergePorts(p.listening ?? [])
          const local = ports.filter(x => x.addrs.every(loopback))
          const table = (rows: Port[]) => (
            <Table<Port> size="small" rowKey="key" pagination={false} style={{ marginTop: 8 }} dataSource={rows}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
              columns={[
                { title: t('thPorts'), width: 92, render: (_, l) => <span className="mono">{l.proto}/{l.port}</span> },
                { title: t('thService'), ellipsis: true, render: (_, l) => p.services?.[`${l.proto}/${l.port}`]?.name ?? '-' },
                { title: t('thBind'), ellipsis: true, render: (_, l) => (l.addrs.some(anyAddr) ? t('bindAll') : l.addrs.every(loopback) ? t('bindLocal') : <span className="mono">{l.addrs.join(', ')}</span>) },
                { title: t('listenProcess'), dataIndex: 'process', ellipsis: true, render: (_, l) => <Tooltip title={l.path}>{l.process ?? '-'}</Tooltip> },
              ]} />
          )
          return (
            <>
              {table(ports.filter(x => !local.includes(x)))}
              {local.length > 0 && (
                <Button type="link" size="small" style={{ padding: 0, marginTop: 4 }} onClick={() => setShowLocal(!showLocal)}>
                  {t(showLocal ? 'hideLocalPorts' : 'showLocalPorts', { n: local.length })}
                </Button>
              )}
              {showLocal && table(local)}
            </>
          )
        })()}
      </div>

      {(['outbound', 'inbound'] as const).map(dir => (
        <div key={dir}>
          <Typography.Text strong>{t(dir === 'outbound' ? 'dependsOn' : 'dependedBy')}</Typography.Text>
          <div style={{ marginTop: 8 }}><PeerList items={groupPeers(p[dir] ?? [], dir)} notes={p.relationNotes ?? {}} stats={p[`${dir}Stats`] ?? {}} /></div>
        </div>
      ))}

      {p.publicDestinations > 0 && (
        <div>
          <Typography.Text strong>{t('publicEgress', { n: p.publicDestinations })}</Typography.Text>
          {p.public && p.publicDestinations > p.public.length && <Typography.Text type="secondary" style={{ fontSize: 12 }}> · {t('publicTopN', { n: p.public.length })}</Typography.Text>}
          <div style={{ marginTop: 8 }}><PublicDestList items={p.public ?? []} host={{ id: assetId, name: hostname, groupId }} limit={5} /></div>
        </div>
      )}

      <EditModal open={editing} profile={p} busy={busy} onClose={() => setEditing(false)}
        onSave={async edit => { if (await run(() => saveAssetProfile(assetId, edit))) setEditing(false) }} />
    </Space>
  )
}

// 编辑即锁定；已锁定的字段可以交还 AI
function EditModal({ open, profile, busy, onClose, onSave }: {
  open: boolean; profile: AssetProfile; busy: boolean; onClose: () => void; onSave: (e: ProfileEdit) => void
}) {
  const { t } = useI18n()
  const [form] = Form.useForm()
  const locked = profile.lockedFields ?? []
  const submit = (v: { role: string; summary: string; criticality: number }) => {
    const edit: ProfileEdit = {}
    if (v.role !== (profile.role ?? '')) edit.role = v.role
    if (v.summary !== (profile.summary ?? '')) edit.summary = v.summary
    if (v.criticality && v.criticality !== profile.criticality) edit.criticality = v.criticality
    onSave(edit)
  }
  const unlock = (f: string) => onSave({ unlock: [f] })
  const suffix = (f: string) => locked.includes(f) && (
    <Button type="link" size="small" icon={<UnlockOutlined />} disabled={busy} onClick={() => unlock(f)}>{t('unlockToAi')}</Button>
  )
  return (
    <Modal open={open} title={t('editProfile')} onCancel={() => { if (!busy) onClose() }} onOk={() => form.submit()} confirmLoading={busy} destroyOnHidden
      afterOpenChange={o => o && form.setFieldsValue({ role: profile.role ?? '', summary: profile.summary ?? '', criticality: profile.criticality ?? 0 })}>
      <Form form={form} layout="vertical" disabled={busy} onFinish={submit}>
        <Form.Item label={<Space>{t('role')}{suffix('role')}</Space>} name="role" rules={[{ required: true, whitespace: true, max: 32 }]}><Input /></Form.Item>
        <Form.Item label={<Space>{t('criticality')}{suffix('criticality')}</Space>} name="criticality">
          <Rate count={5} tooltips={[1, 2, 3, 4, 5].map(n => t(CRIT_KEY[n]))} />
        </Form.Item>
        <Form.Item label={<Space>{t('summaryLabel')}{suffix('summary')}</Space>} name="summary" rules={[{ max: 300 }]}><Input.TextArea rows={3} /></Form.Item>
      </Form>
    </Modal>
  )
}
