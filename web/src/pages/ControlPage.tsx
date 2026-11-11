import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { App, Button, Card, Flex, Form, Input, InputNumber, Modal, Popconfirm, Segmented, Select, Table, Tabs, Tag, Tooltip, Typography, theme } from 'antd'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { createFact, endIntent, fetchAssets, fetchFacts, fetchIntents, retireFact, updateFact, type Fact, type FactKind, type Intent } from '../api'
import { useSession } from '../app/session'
import { Ago, EmptyHint } from '../components/Ago'
import { Clamp } from '../components/Clamp'
import { RefTag } from '../components/ControlRefs'
import { HostLink } from '../components/HostLink'
import { IntentModal } from '../components/IntentModal'
import { LoadError } from '../components/LoadError'
import { Page, STICKY_HEADER, TableCard } from '../components/Page'
import { TableActions } from '../components/TableActions'
import { FACT_KINDS, bareAddr, factLive } from '../components/control'
import { errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const TABS = ['overview', 'facts', 'intents'] as const
const PAGE = 20

const shortFp = (v: string) => (v.length > 24 ? `${v.slice(0, 15)}…${v.slice(-6)}` : v)

// 带 ?ref= 进来时翻到那一行所在的页、滚过去并高亮；resetKey 变了（换了类型或视图）回到第一页
function useRefRow<T extends { id: string; ref: string }>(rows: T[], ref: string, resetKey: string) {
  const idx = ref ? rows.findIndex(r => r.ref === ref) : -1
  const target = idx >= 0 ? rows[idx].id : ''
  const [picked, setPicked] = useState<{ key: string; page: number } | null>(null)
  useEffect(() => {
    if (!target) return
    requestAnimationFrame(() => document.querySelector(`[data-row-key="${target}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' }))
  }, [target])
  return {
    pagination: {
      current: picked?.key === resetKey ? picked.page : idx >= 0 ? Math.floor(idx / PAGE) + 1 : 1,
      pageSize: PAGE,
      showSizeChanger: false,
      hideOnSinglePage: true,
      onChange: (page: number) => setPicked({ key: resetKey, page }),
    },
    rowClassName: (r: T) => (r.ref === ref ? 'row-focus' : ''),
  }
}

// 自治总控：权威事实与运维意图。研判结论里的 F-/I- 编号都链到这里
export function ControlPage() {
  const { t } = useI18n()
  const { isAdmin, canWrite } = useSession()
  const [params, setParams] = useSearchParams()
  const tab = TABS.find(x => x === params.get('tab')) ?? 'overview'
  const ref = params.get('ref') ?? ''
  const [adding, setAdding] = useState(false)
  const [registering, setRegistering] = useState(false)
  // 带上已停用的：研判引用过的事实停用后，编号链接仍要能定位到
  const facts = useQuery({ queryKey: ['facts', 'withRetired'], queryFn: () => fetchFacts({ retired: true }) })
  const intents = useQuery({ queryKey: ['intents'], queryFn: () => fetchIntents() })

  const extra = tab === 'facts' && isAdmin
    ? <Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding(true)}>{t('factAdd')}</Button>
    : tab === 'intents' && canWrite
      ? <Button type="primary" icon={<PlusOutlined />} onClick={() => setRegistering(true)}>{t('intentRegister')}</Button>
      : undefined

  return (
    <Page title={t('navControl')} subtitle={t('controlSubtitle')} extra={extra}>
      <IntentModal open={registering} onClose={() => setRegistering(false)} />
      <Tabs activeKey={tab} onChange={k => setParams(k === 'overview' ? {} : { tab: k }, { replace: true })}
        items={[
          { key: 'overview', label: t('controlOverview'), children: <Overview facts={facts} intents={intents} /> },
          { key: 'facts', label: t('controlFacts'), children: <FactsTab facts={facts} refId={ref} adding={adding} onAdded={() => setAdding(false)} /> },
          { key: 'intents', label: t('controlIntents'), children: <IntentsTab intents={intents} refId={ref} /> },
        ]} />
    </Page>
  )
}

function Stat({ label, value, to }: { label: string; value: number | string; to: string }) {
  const { token } = theme.useToken()
  return (
    <Link to={to} style={{ flex: '1 1 150px', color: 'inherit' }}>
      <Card size="small" hoverable styles={{ body: { padding: '14px 18px' } }}>
        <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{label}</Typography.Text>
        <div style={{ fontSize: 24, fontWeight: 600, marginTop: 4, color: token.colorText, fontVariantNumeric: 'tabular-nums' }}>{value}</div>
      </Card>
    </Link>
  )
}

function Overview({ facts, intents }: { facts: UseQueryResult<Fact[]>; intents: UseQueryResult<Intent[]> }) {
  const { t } = useI18n()
  if (facts.isError) return <LoadError error={facts.error} onRetry={() => facts.refetch()} />
  if (intents.isError) return <LoadError error={intents.error} onRetry={() => intents.refetch()} />
  const now = Date.now()
  const live = (facts.data ?? []).filter(f => factLive(f, now))
  const n = (v: number) => (facts.isPending ? '-' : v)
  const cited = live.filter(f => f.lastCitedAt).sort((a, b) => b.lastCitedAt!.localeCompare(a.lastCitedAt!)).slice(0, 10)
  return (
    <Flex vertical gap={20}>
      <Typography.Text type="secondary">{t('controlOverviewHint')}</Typography.Text>
      <Flex wrap gap={14}>
        <Stat label={t('controlActiveIntents')} value={intents.isPending ? '-' : (intents.data ?? []).filter(i => i.active).length} to="/control?tab=intents" />
        <Stat label={t('controlLiveFacts')} value={n(live.length)} to="/control?tab=facts" />
        {FACT_KINDS.map(k => (
          <Stat key={k} label={t(`factKind_${k}` as MsgKey)} value={n(live.filter(f => f.kind === k).length)} to={`/control?tab=facts&kind=${k}`} />
        ))}
      </Flex>
      <TableCard title={t('controlRecentCited')}>
        <Table<Fact> rowKey="id" size="small" loading={facts.isPending} dataSource={cited} pagination={false}
          locale={{ emptyText: <EmptyHint title={t('controlNoCited')} /> }}
          columns={[
            { title: t('factRef'), dataIndex: 'ref', width: 130, render: v => <RefTag value={v} /> },
            { title: t('factKind'), dataIndex: 'kind', width: 120, render: (v: FactKind) => t(`factKind_${v}` as MsgKey) },
            { title: t('factSubject'), key: 'subject', width: 220, render: (_, f) => <FactSubject f={f} /> },
            { title: t('factContent'), dataIndex: 'content', render: v => <Clamp text={v} /> },
            { title: t('factCited'), dataIndex: 'citedCount', width: 100, align: 'right' },
            { title: t('factLastCited'), dataIndex: 'lastCitedAt', width: 140, render: v => <Ago iso={v} /> },
          ]} />
      </TableCard>
    </Flex>
  )
}

function FactSubject({ f }: { f: Fact }) {
  if (f.kind === 'key') {
    return <Tooltip title={f.subject}><Typography.Text className="mono" copyable={{ text: f.subject }} style={{ fontSize: 12 }}>{shortFp(f.subject)}</Typography.Text></Tooltip>
  }
  if (f.kind === 'channel') return <span className="mono" style={{ fontSize: 12.5 }}>{bareAddr(f.subject)}</span>
  if (f.kind === 'decision') return <>{f.subject}{f.assetId && <> · <HostLink id={f.assetId} fallback={f.hostname} /></>}</>
  return <HostLink id={f.assetId} fallback={f.hostname} />
}

interface FactDraft {
  kind: FactKind
  subject?: string
  assetId?: string
  groupId?: string
  holder?: string
  content: string
  expiresInDays: number
}

interface FactEditDraft {
  holder?: string
  content: string
  expiresInDays?: number | null
}

function FactsTab({ facts, refId, adding, onAdded }: { facts: UseQueryResult<Fact[]>; refId: string; adding: boolean; onAdded: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin, groups } = useSession()
  const [params, setParams] = useSearchParams()
  const [editing, setEditing] = useState<Fact | null>(null)
  const [busy, setBusy] = useState(false)
  const [addForm] = Form.useForm<FactDraft>()
  const [editForm] = Form.useForm<FactEditDraft>()
  const addKind = Form.useWatch('kind', addForm)
  const assets = useQuery({ queryKey: ['assets'], queryFn: () => fetchAssets(), enabled: adding })

  const all = facts.data ?? []
  const refFact = refId ? all.find(f => f.ref === refId) : undefined
  const kind = FACT_KINDS.find(k => k === params.get('kind')) ?? refFact?.kind ?? 'key'
  // 已停用的不列出，除非正是链接指向的那一条
  const rows = all.filter(f => f.kind === kind && (!f.retiredAt || f.ref === refId))
  const { pagination, rowClassName } = useRefRow(rows, refId, kind)
  const now = Date.now()

  const run = async (fn: () => Promise<unknown>, done?: () => void) => {
    setBusy(true)
    try {
      await fn()
      done?.()
      await client.invalidateQueries({ queryKey: ['facts'] })
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  const expiry = (f: Fact) => {
    if (!f.expiresAt) return t('longTerm')
    return Date.parse(f.expiresAt) <= now ? <Tag>{t('factExpired')}</Tag> : fmtTime(f.expiresAt)
  }

  if (facts.isError) return <LoadError error={facts.error} onRetry={() => facts.refetch()} />

  const withAsset = addKind === 'asset_role' || addKind === 'change'
  return (
    <>
      <Segmented style={{ marginBottom: 16 }} value={kind} onChange={v => setParams({ tab: 'facts', kind: String(v) }, { replace: true })}
        options={FACT_KINDS.map(k => ({ value: k, label: `${t(`factKind_${k}` as MsgKey)} ${all.filter(f => f.kind === k && factLive(f, now)).length}` }))} />
      <TableCard>
        <Table<Fact>
          sticky={STICKY_HEADER}
          rowKey="id"
          loading={facts.isPending}
          dataSource={rows}
          pagination={pagination}
          rowClassName={rowClassName}
          scroll={{ x: 1330 }}
          locale={{ emptyText: <EmptyHint title={t('factEmpty')} hint={t('factEmptyHint')} /> }}
          columns={[
            {
              title: t('factRef'), dataIndex: 'ref', width: 140,
              render: (v: string, f) => <Flex vertical gap={2} align="flex-start">
                <Typography.Text className="mono" copyable style={{ fontSize: 12.5 }}>{v}</Typography.Text>
                {f.retiredAt && <Tooltip title={`${f.retiredBy ?? ''} · ${fmtTime(f.retiredAt)}`}><Tag>{t('factRetired')}</Tag></Tooltip>}
              </Flex>,
            },
            { title: t('factSubject'), key: 'subject', width: 240, render: (_, f) => <FactSubject f={f} /> },
            { title: t('factHolder'), dataIndex: 'holder', width: 150, ellipsis: { showTitle: false }, render: (v: string, f) => (v ? <Tooltip title={v}><span>{f.holderName || v}</span></Tooltip> : '-') },
            { title: t('factContent'), dataIndex: 'content', render: v => <Clamp text={v} /> },
            {
              title: t('thSource'), dataIndex: 'source', width: 120,
              render: (v: string, f) => <Flex vertical gap={2} align="flex-start"><Tag variant="filled">{t(`factSource_${v}` as MsgKey)}</Tag><Typography.Text type="secondary" style={{ fontSize: 12 }}>{f.createdBy}</Typography.Text></Flex>,
            },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 110, sorter: (a, b) => (a.expiresAt ?? '9999').localeCompare(b.expiresAt ?? '9999'), render: (_, f) => expiry(f) },
            {
              title: t('factCited'), dataIndex: 'citedCount', width: 110, sorter: (a, b) => a.citedCount - b.citedCount,
              render: (v: number, f) => <Flex vertical gap={0}><span>{v}</span>{f.lastCitedAt && <Typography.Text type="secondary" style={{ fontSize: 12 }}><Ago iso={f.lastCitedAt} /></Typography.Text>}</Flex>,
            },
            ...(isAdmin ? [{
              title: t('actions'), key: 'act', width: 130,
              render: (_: unknown, f: Fact) => !f.retiredAt && (
                <TableActions>
                  <Button type="link" size="small" onClick={() => setEditing(f)}>{t('factEdit')}</Button>
                  <Popconfirm title={t('factConfirmRetire')} onConfirm={() => run(() => retireFact(f.id))}>
                    <Button type="link" size="small" danger disabled={busy}>{t('factRetire')}</Button>
                  </Popconfirm>
                </TableActions>
              ),
            }] : []),
          ]}
        />
      </TableCard>

      <Modal open={adding} title={t('factAdd')} onCancel={() => { if (!busy) onAdded() }} onOk={() => addForm.submit()} confirmLoading={busy} width={620} destroyOnHidden>
        <Form<FactDraft> form={addForm} layout="vertical" disabled={busy} initialValues={{ kind, expiresInDays: 0 }}
          onFinish={v => run(() => createFact({ ...v, subject: (v.subject ?? '').trim(), holder: (v.holder ?? '').trim() }), onAdded)}>
          <Form.Item name="kind" label={t('factKind')} rules={[{ required: true }]}>
            <Select options={FACT_KINDS.map(k => ({ value: k, label: t(`factKind_${k}` as MsgKey) }))} />
          </Form.Item>
          {addKind === 'key' && (
            <Form.Item name="subject" label={t('factKeySubject')} rules={[{ required: true, whitespace: true }]}>
              <Input className="mono" placeholder="SHA256:…" />
            </Form.Item>
          )}
          {addKind === 'channel' && (
            <Form.Item name="subject" label={t('factChannelSubject')} extra={t('factChannelHint')} rules={[{ required: true, whitespace: true }]}>
              <Input className="mono" placeholder="10.1.1.36 / 10.8.0.0/24" />
            </Form.Item>
          )}
          {addKind === 'decision' && (
            <Form.Item name="subject" label={t('factDecisionSubject')} rules={[{ required: true, whitespace: true, max: 200 }]}>
              <Input />
            </Form.Item>
          )}
          {(withAsset || addKind === 'decision') && (
            <Form.Item name="assetId" label={t('thHostname')} extra={withAsset ? undefined : t('factAssetOptional')} rules={[{ required: withAsset }]}>
              <Select showSearch allowClear optionFilterProp="label" loading={assets.isPending}
                options={(assets.data ?? []).map(a => ({ value: a.id, label: a.hostname }))} />
            </Form.Item>
          )}
          {!withAsset && (
            <Form.Item name="groupId" label={t('group')} extra={t('factGroupHint')}>
              <Select allowClear options={groups.map(g => ({ value: g.id, label: g.name }))} />
            </Form.Item>
          )}
          <Form.Item name="holder" label={t('factHolder')} extra={t('factHolderHint')}>
            <Input placeholder="user:alice" />
          </Form.Item>
          <Form.Item name="content" label={t('factContent')} rules={[{ required: true, whitespace: true, max: 1000 }]}>
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('factValidityHint')} rules={[{ required: true }]}>
            <InputNumber min={0} max={3650} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal open={editing !== null} title={t('factEdit')} onCancel={() => { if (!busy) setEditing(null) }} onOk={() => editForm.submit()} confirmLoading={busy} width={560} destroyOnHidden>
        {editing && (
          <Form<FactEditDraft> form={editForm} layout="vertical" disabled={busy} initialValues={{ holder: editing.holder, content: editing.content }}
            onFinish={v => run(() => updateFact(editing.id, {
              holder: (v.holder ?? '').trim(),
              content: v.content,
              ...(v.expiresInDays != null ? { expiresInDays: v.expiresInDays } : {}),
            }), () => setEditing(null))}>
            <Form.Item name="holder" label={t('factHolder')} extra={t('factHolderHint')}>
              <Input />
            </Form.Item>
            <Form.Item name="content" label={t('factContent')} rules={[{ required: true, whitespace: true, max: 1000 }]}>
              <Input.TextArea rows={3} />
            </Form.Item>
            <Form.Item name="expiresInDays" label={t('validityDays')}
              extra={t('factValidityKeep', { at: editing.expiresAt ? fmtTime(editing.expiresAt) : t('longTerm') })}>
              <InputNumber min={0} max={3650} />
            </Form.Item>
          </Form>
        )}
      </Modal>
    </>
  )
}

function IntentsTab({ intents, refId }: { intents: UseQueryResult<Intent[]>; refId: string }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { me, isAdmin } = useSession()
  const [params, setParams] = useSearchParams()
  const all = intents.data ?? []
  const refIntent = refId ? all.find(i => i.ref === refId) : undefined
  const view = params.get('view') === 'history' || (!params.get('view') && refIntent && !refIntent.active) ? 'history' : 'active'
  const rows = all.filter(i => (view === 'active') === i.active)
  const { pagination, rowClassName } = useRefRow(rows, refId, view)

  const end = async (id: string) => {
    try {
      await endIntent(id)
      await client.invalidateQueries({ queryKey: ['intents'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const status = (i: Intent) => {
    if (i.active) return <Tag color="green">{t('intentActive')}</Tag>
    if (i.endedAt) return <Tooltip title={`${i.endedBy ?? ''} · ${fmtTime(i.endedAt)}`}><Tag>{t('intentEnded')}</Tag></Tooltip>
    return <Tag>{t('intentExpired')}</Tag>
  }

  if (intents.isError) return <LoadError error={intents.error} onRetry={() => intents.refetch()} />
  return (
    <>
      <Segmented style={{ marginBottom: 16 }} value={view} onChange={v => setParams({ tab: 'intents', view: String(v) }, { replace: true })}
        options={[
          { value: 'active', label: `${t('intentActive')} ${all.filter(i => i.active).length}` },
          { value: 'history', label: t('intentHistory') },
        ]} />
      <TableCard>
        <Table<Intent>
          sticky={STICKY_HEADER}
          rowKey="id"
          loading={intents.isPending}
          dataSource={rows}
          pagination={pagination}
          rowClassName={rowClassName}
          scroll={{ x: 1200 }}
          locale={{ emptyText: <EmptyHint title={t(view === 'active' ? 'intentEmpty' : 'intentHistoryEmpty')} hint={view === 'active' ? t('intentEmptyHint') : undefined} /> }}
          columns={[
            { title: t('factRef'), dataIndex: 'ref', width: 130, render: (v: string) => <Typography.Text className="mono" copyable style={{ fontSize: 12.5 }}>{v}</Typography.Text> },
            { title: t('intentBy'), dataIndex: 'createdBy', width: 200, ellipsis: { showTitle: false }, render: (v: string, i) => <Tooltip title={v}><span>{i.createdByName || v}</span></Tooltip> },
            {
              title: t('intentHosts'), dataIndex: 'assetIds', width: 220,
              render: (v: string[], i) => <Flex wrap gap={6}>{v.map((id, n) => <HostLink key={id} id={id} fallback={i.hostnames?.[n]} />)}</Flex>,
            },
            {
              title: t('intentCategory'), dataIndex: 'category',
              render: (v: string, i) => <Flex vertical gap={2} align="flex-start">
                <Tag variant="filled" color="purple">{t(`intentCat_${v}` as MsgKey)}</Tag>
                {i.note && <Clamp text={i.note} />}
              </Flex>,
            },
            {
              title: t('intentWindow'), key: 'window', width: 260, sorter: (a, b) => a.startsAt.localeCompare(b.startsAt),
              render: (_, i) => <Flex wrap gap={6} align="center"><span>{fmtTime(i.startsAt)} – {fmtTime(i.expiresAt)}</span>{i.late && <Tooltip title={t('intentLateHint')}><Tag color="orange">{t('intentLate')}</Tag></Tooltip>}</Flex>,
            },
            { title: t('thStatus'), key: 'status', width: 110, render: (_, i) => status(i) },
            {
              title: t('actions'), key: 'act', width: 110,
              render: (_, i) => i.active && (isAdmin || i.createdBy === `user:${me.username}`) && (
                <Popconfirm title={t('intentConfirmEnd')} onConfirm={() => end(i.id)}>
                  <Button type="link" size="small" danger>{t('intentEnd')}</Button>
                </Popconfirm>
              ),
            },
          ]}
        />
      </TableCard>
    </>
  )
}
