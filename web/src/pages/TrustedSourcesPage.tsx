import { TableActions } from '../components/TableActions'
import { PlusOutlined, PushpinFilled } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Collapse, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import {
  createTrustedSource, deleteTrustedSource, fetchTrustedCandidates, fetchTrustedSources, updateTrustedSource,
  type TrustedCandidate, type TrustedSource,
} from '../api'
import { useSession } from '../app/session'
import { EmptyHint } from '../components/Ago'
import { LoadError } from '../components/LoadError'
import { FilterCard, Page, STICKY_HEADER } from '../components/Page'
import { errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

interface AddDraft {
  name: string
  reason?: string
  keyFingerprint?: string
  sourceCidr?: string
  loginUser?: string
  expiresInDays: number
}

interface EditDraft {
  name: string
  reason?: string
  expiresInDays?: number
  pinned: boolean
}

// 指纹太长，表格里只露头尾，悬停看全、可复制
const shortFp = (v: string) => (v.length > 24 ? `${v.slice(0, 15)}…${v.slice(-6)}` : v)
const fpText = (v: string | null) => (v
  ? <Tooltip title={v}><Typography.Text className="mono" copyable={{ text: v }} style={{ fontSize: 12 }}>{shortFp(v)}</Typography.Text></Tooltip>
  : null)

// 已知自动化：运维脚本、AI 运维插件这类日常自动化的 SSH 登录身份。平台自动识别，组管理员可以调整、停用、删除或手动添加；
// 它们的告警保留可查，但不生成事件、不推送。放宽检测只有人和平台的识别逻辑能做，AI 没有对应工具
export function TrustedSourcesPage() {
  const { t, locale } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { group, isAdmin } = useSession()
  const groupId = group?.id ?? ''
  const manage = isAdmin || group?.role === 'admin'
  const [recentOpen, setRecentOpen] = useState(false)
  const [q, setQ] = useState('')
  const [originFilter, setOriginFilter] = useState('')
  const [stateFilter, setStateFilter] = useState('')
  const sources = useQuery({ queryKey: ['trustedSources', groupId], queryFn: () => fetchTrustedSources(groupId), enabled: !!groupId })
  const candidates = useQuery({
    queryKey: ['trustedCandidates', groupId], queryFn: () => fetchTrustedCandidates(groupId), enabled: !!groupId && manage && recentOpen,
  })
  const [adding, setAdding] = useState<Partial<AddDraft> | null>(null)
  const [editing, setEditing] = useState<TrustedSource | null>(null)
  const [busy, setBusy] = useState(false)
  const [addForm] = Form.useForm<AddDraft>()
  const [editForm] = Form.useForm<EditDraft>()
  const now = Date.now()

  const refresh = () => Promise.all([
    client.invalidateQueries({ queryKey: ['trustedSources', groupId] }),
    client.invalidateQueries({ queryKey: ['trustedCandidates', groupId] }),
  ])
  const run = async (fn: () => Promise<unknown>, done?: () => void) => {
    setBusy(true)
    try {
      await fn()
      done?.()
      await refresh()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }
  const expired = (s: TrustedSource) => Date.parse(s.expiresAt) <= now
  const sourceState = (s: TrustedSource): 'active' | 'disabled' | 'expired' => {
    if (s.revokedAt) return 'disabled'
    if (expired(s)) return 'expired'
    return 'active'
  }

  const activeQ = q.trim().toLowerCase()
  const hasFilters = Boolean(activeQ || originFilter || stateFilter)
  const rows = (sources.data ?? []).filter(s =>
    (!originFilter || s.origin === originFilter) &&
    (!stateFilter || sourceState(s) === stateFilter) &&
    (!activeQ ||
      s.name.toLowerCase().includes(activeQ) ||
      (s.loginUser ?? '').toLowerCase().includes(activeQ) ||
      (s.sourceCidr ?? '').toLowerCase().includes(activeQ) ||
      (s.keyFingerprint ?? '').toLowerCase().includes(activeQ) ||
      (s.reason ?? '').toLowerCase().includes(activeQ))
  )

  const status = (s: TrustedSource) => {
    if (s.revokedAt && s.revokeCause) {
      const tag = <Tag color="red">{t('tsAutoDisabled')}</Tag>
      return <Tooltip title={t('tsAutoDisabledHint')}>{s.revokeIncidentId ? <Link to={`/incidents/${s.revokeIncidentId}`}>{tag}</Link> : tag}</Tooltip>
    }
    if (s.revokedAt) return <Tooltip title={`${s.revokedBy ?? ''} · ${fmtTime(s.revokedAt)}`}><Tag>{t('tsDisabled')}</Tag></Tooltip>
    if (expired(s)) return <Tag>{t('tsExpired')}</Tag>
    return <Tag color="green">{t('tsActive')}</Tag>
  }

  const identity = (s: TrustedSource) => (
    <Space orientation="vertical" size={0}>
      <span className="mono" style={{ fontSize: 12 }}>{[s.loginUser, s.sourceCidr?.replace(/\/(32|128)$/, '')].filter(Boolean).join('@') || '-'}</span>
      {fpText(s.keyFingerprint)}
    </Space>
  )

  const evidence = (s: TrustedSource) => {
    const e = s.evidence
    if (s.origin !== 'auto' || !e) {
      return <Typography.Text type="secondary">{t('tsEvidenceManual', { by: s.createdBy })}</Typography.Text>
    }
    return (
      <Space orientation="vertical" size={0}>
        <span>{t('tsEvidenceLogins', { window: e.windowDays, days: e.days, logins: e.logins, hosts: e.hosts })}</span>
        {e.alerts > 0 && <Typography.Text type="secondary">{t('tsEvidenceVerdicts', { parts: parts(e.humanBenign, e.aiBenign) })}</Typography.Text>}
      </Space>
    )
  }

  const actions = (s: TrustedSource) => (
    <TableActions>
      <Button type="link" size="small" onClick={() => setEditing(s)}>{t('tsEdit')}</Button>
      {s.revokedAt
        ? (
            <Tooltip title={expired(s) ? t('tsEnableExpired') : undefined}>
              <Button type="link" size="small" disabled={busy || expired(s)} onClick={() => run(() => updateTrustedSource(s.id, { enabled: true }))}>{t('tsEnable')}</Button>
            </Tooltip>
          )
        : (
            <Popconfirm title={t('tsConfirmDisable')} onConfirm={() => run(() => updateTrustedSource(s.id, { enabled: false }))}>
              <Button type="link" size="small" disabled={busy}>{t('tsDisable')}</Button>
            </Popconfirm>
          )}
      <Popconfirm title={t('tsConfirmDelete')} onConfirm={() => run(() => deleteTrustedSource(s.id))}>
        <Button type="link" size="small" danger disabled={busy}>{t('tsDelete')}</Button>
      </Popconfirm>
    </TableActions>
  )

  // 结论按事件计，只列非零的几项
  const parts = (human: number, ai: number, pending = 0) => [
    human ? t('tsPartHuman', { n: human }) : '',
    ai ? t('tsPartAI', { n: ai }) : '',
    pending ? t('tsPartPending', { n: pending }) : '',
  ].filter(Boolean).join(locale === 'zh' ? '、' : ', ')

  const how: MsgKey[] = ['tsHowRecognize', 'tsHowNoCommand', 'tsHowException', 'tsHowAdjust', 'tsHowScope']

  return (
    <Page
      title={t('navTrustedSources')}
      subtitle={t('tsSubtitle')}
      extra={manage && <Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding({})}>{t('tsAdd')}</Button>}
    >
      <Collapse
        size="small"
        style={{ marginBottom: 20 }}
        items={[{
          key: 'how',
          label: t('tsHowTitle'),
          children: <Space orientation="vertical" size={8}>{how.map(k => <Typography.Text key={k}>{t(k)}</Typography.Text>)}</Space>,
        }]}
      />
      <FilterCard
        onReset={hasFilters ? () => { setQ(''); setOriginFilter(''); setStateFilter('') } : undefined}
        extra={hasFilters && sources.data ? <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total: sources.data.length })}</Typography.Text> : undefined}
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 280 }} placeholder={t('searchTrustedSources')} value={q} onChange={e => setQ(e.target.value)} />
            <Select aria-label={t('tsStatus')} style={{ width: 140 }} value={stateFilter} onChange={setStateFilter}
              options={[
                { value: '', label: t('allStatuses') },
                { value: 'active', label: t('tsActive') },
                { value: 'disabled', label: t('tsDisabled') },
                { value: 'expired', label: t('tsExpired') },
              ]}
            />
            <Select aria-label={t('thSource')} style={{ width: 145 }} value={originFilter} onChange={setOriginFilter}
              options={[
                { value: '', label: t('allOrigins') },
                { value: 'auto', label: t('tsOriginAuto') },
                { value: 'manual', label: t('tsOriginManual') },
              ]}
            />
          </Space>
        }
      >
        {sources.isError ? <LoadError error={sources.error} onRetry={() => sources.refetch()} /> : <Table<TrustedSource>
          sticky={STICKY_HEADER}
          rowKey="id"
          loading={sources.isPending && !!groupId}
          dataSource={rows}
          pagination={{ defaultPageSize: 20, showSizeChanger: true, hideOnSinglePage: true }}
          scroll={{ x: 1180 }}
          locale={{ emptyText: <EmptyHint title={t(hasFilters ? 'noMatch' : 'tsEmpty')} hint={hasFilters ? undefined : t('tsEmptyHint')} /> }}
          columns={[
            {
              title: t('tsName'), dataIndex: 'name', width: 220,
              sorter: (a, b) => a.name.localeCompare(b.name),
              render: (v: string, s) => (
                <Space orientation="vertical" size={2}>
                  <Tooltip title={s.reason}><Typography.Text strong>{v}</Typography.Text></Tooltip>
                  <Space size={4} wrap>
                    <Tag variant="filled" color={s.origin === 'auto' ? 'blue' : undefined}>{t(s.origin === 'auto' ? 'tsOriginAuto' : 'tsOriginManual')}</Tag>
                    {s.pinned && <Tooltip title={t('tsPinnedHint')}><Tag variant="filled" icon={<PushpinFilled />}>{t('tsPinned')}</Tag></Tooltip>}
                  </Space>
                </Space>
              ),
            },
            { title: t('tsStatus'), key: 'state', width: 110, sorter: (a, b) => sourceState(a).localeCompare(sourceState(b)), render: (_, s) => status(s) },
            { title: t('tsIdentity'), key: 'identity', width: 260, render: (_, s) => identity(s) },
            { title: t('tsEvidence'), key: 'evidence', width: 300, render: (_, s) => evidence(s) },
            {
              title: <Tooltip title={t('tsMatchedHint')}>{t('tsMatched')}</Tooltip>, dataIndex: 'matchedCount', width: 130, align: 'right',
              sorter: (a, b) => a.matchedCount - b.matchedCount,
              // 放过的告警按指纹或来源在日志检索里翻
              render: (v: number, s) => (v && (s.keyFingerprint || s.sourceCidr)
                ? <Link to={`/events?${new URLSearchParams({ q: s.keyFingerprint ?? s.sourceCidr!.replace(/\/\d+$/, ''), hours: '168' })}`}>{v}</Link>
                : v),
            },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 155, sorter: (a, b) => (a.lastMatchedAt ?? '').localeCompare(b.lastMatchedAt ?? ''), render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 155, sorter: (a, b) => a.expiresAt.localeCompare(b.expiresAt), render: fmtTime },
            ...(manage ? [{ title: t('actions'), key: 'act', width: 170, render: (_: unknown, s: TrustedSource) => actions(s) }] : []),
          ]}
        />}
      </FilterCard>

      {manage && (
        <Collapse
          style={{ marginTop: 20 }}
          onChange={keys => setRecentOpen(keys.length > 0)}
          items={[{
            key: 'recent',
            label: <Space wrap size={8}><span>{t('tsRecent')}</span><Typography.Text type="secondary">{t('tsRecentHint')}</Typography.Text></Space>,
            styles: { body: { padding: '8px 18px 16px' } },
            children: candidates.isError ? <LoadError error={candidates.error} onRetry={() => candidates.refetch()} /> : <Table<TrustedCandidate>
              rowKey={c => `${c.user}|${c.keyFingerprint ?? c.addresses.join(',')}`}
              size="small"
              loading={candidates.isPending}
              dataSource={candidates.data ?? []}
              pagination={{ pageSize: 10, hideOnSinglePage: true }}
              scroll={{ x: 1080 }}
              locale={{ emptyText: <EmptyHint title={t('tsNoCandidates')} hint={t('tsNoCandidatesHint')} /> }}
              columns={[
                {
                  title: t('tsIdentity'), key: 'id', width: 260,
                  sorter: (a, b) => a.user.localeCompare(b.user),
                  render: (_, c) => (
                    <Space orientation="vertical" size={0}>
                      <span className="mono" style={{ fontSize: 12 }}>{c.user}@{c.addresses.join(', ')}</span>
                      {c.keyFingerprint
                        ? <Space size={4}>{c.keyType && <Tag variant="filled">{c.keyType}</Tag>}{fpText(c.keyFingerprint)}</Space>
                        : <Typography.Text type="secondary">{t('tsNoKey')}</Typography.Text>}
                    </Space>
                  ),
                },
                { title: t('tsLoginStats'), key: 'logins', width: 160, sorter: (a, b) => a.logins - b.logins, render: (_, c) => t('tsLoginStatsValue', { days: c.days, logins: c.logins, hosts: c.hosts }) },
                {
                  title: t('tsVerdicts'), key: 'verdicts', width: 250,
                  sorter: (a, b) => a.alerts - b.alerts,
                  render: (_, c) => (c.alerts
                    ? t('tsVerdictsValue', { alerts: c.alerts, parts: parts(c.humanBenign, c.aiBenign, c.pending) })
                    : <Typography.Text type="secondary">{t('tsVerdictsNone')}</Typography.Text>),
                },
                { title: t('tsLastSeen'), dataIndex: 'lastSeen', width: 155, sorter: (a, b) => a.lastSeen.localeCompare(b.lastSeen), render: fmtTime },
                {
                  title: t('tsStatus'), key: 'reason', width: 260,
                  render: (_, c) => (
                    <Space size={4} wrap>
                      <Typography.Text type={c.reason === 'covered' || c.reason === 'eligible' ? 'success' : undefined}>{t(`tsReason_${c.reason}` as MsgKey)}</Typography.Text>
                      {c.reason !== 'covered' && (
                        <Button size="small" type="link" onClick={() => setAdding({
                          keyFingerprint: c.keyFingerprint ?? undefined,
                          sourceCidr: c.addresses.length === 1 ? c.addresses[0] : undefined,
                          loginUser: c.user,
                        })}>{t('tsAdd')}</Button>
                      )}
                    </Space>
                  ),
                },
              ]}
            />,
          }]}
        />
      )}

      <Modal
        open={adding !== null}
        title={t('tsAdd')}
        onCancel={() => { if (!busy) setAdding(null) }}
        onOk={() => addForm.submit()}
        confirmLoading={busy}
        width={620}
        destroyOnHidden
      >
        <Form<AddDraft> form={addForm} layout="vertical" disabled={busy} initialValues={{ expiresInDays: 90, ...adding }}
          onFinish={v => run(() => createTrustedSource({ ...v, groupId }), () => setAdding(null))}>
          <Form.Item name="name" label={t('tsName')} rules={[{ required: true, whitespace: true, max: 100 }]}>
            <Input placeholder="Termix AI Ops" />
          </Form.Item>
          <Form.Item name="reason" label={t('reason')} rules={[{ max: 1000 }]}>
            <Input.TextArea rows={2} placeholder={t('tsReasonHint')} />
          </Form.Item>
          <Form.Item name="keyFingerprint" label={t('tsKeyFingerprint')} extra={t('tsKeyFingerprintHint')}>
            <Input className="mono" placeholder="SHA256:…" />
          </Form.Item>
          <Form.Item name="sourceCidr" label={t('tsSourceCidr')} extra={t('tsSourceCidrHint')}>
            <Input className="mono" placeholder="10.1.1.35" />
          </Form.Item>
          <Form.Item name="loginUser" label={t('tsLoginUser')}>
            <Input placeholder="root" />
          </Form.Item>
          <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('tsValidityHint')} rules={[{ required: true }]}>
            <InputNumber min={1} max={365} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={editing !== null}
        title={t('tsEdit')}
        onCancel={() => { if (!busy) setEditing(null) }}
        onOk={() => editForm.submit()}
        confirmLoading={busy}
        width={560}
        destroyOnHidden
      >
        {editing && (
          <Form<EditDraft> form={editForm} layout="vertical" disabled={busy}
            initialValues={{ name: editing.name, reason: editing.reason ?? '', pinned: editing.pinned }}
            onFinish={v => run(() => updateTrustedSource(editing.id, {
              name: v.name,
              reason: v.reason ?? '',
              pinned: v.pinned,
              ...(v.expiresInDays ? { expiresInDays: v.expiresInDays } : {}),
            }), () => setEditing(null))}>
            <Form.Item name="name" label={t('tsName')} rules={[{ required: true, whitespace: true, max: 100 }]}>
              <Input />
            </Form.Item>
            <Form.Item name="reason" label={t('reason')} rules={[{ max: 1000 }]}>
              <Input.TextArea rows={2} />
            </Form.Item>
            <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('tsValidityKeep', { at: fmtTime(editing.expiresAt) })}>
              <InputNumber min={1} max={365} />
            </Form.Item>
            <Form.Item name="pinned" label={t('tsPinned')} extra={t('tsPinnedHint')} valuePropName="checked">
              <Switch />
            </Form.Item>
          </Form>
        )}
      </Modal>
    </Page>
  )
}
