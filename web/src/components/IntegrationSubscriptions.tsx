import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, DatePicker, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import type { Dayjs } from 'dayjs'
import { useRef, useState } from 'react'
import { deleteIntegrationSubscription, fetchIntegrationAttempts, fetchIntegrationDeliveries, fetchIntegrationSubscriptions, retryIntegrationDelivery, rotateIntegrationSecret, saveIntegrationSubscription, testIntegrationSubscription, type IntegrationDelivery, type IntegrationRow, type IntegrationSubscription, type SubscriptionInput } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { LoadError } from './LoadError'
import { errText, fmtTime } from './format'

const deliveryLabels: Record<string, MsgKey> = { pending: 'integrationPending', sending: 'integrationSending', delivered: 'integrationDelivered', dead: 'integrationDead', cancelled_scope: 'integrationCancelled' }

export function IntegrationSubscriptions({ integration }: { integration: IntegrationRow }) {
  const { t } = useI18n()
  const { groups } = useSession()
  const { message } = App.useApp()
  const client = useQueryClient()
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<IntegrationSubscription | 'new' | null>(null)
  const [secret, setSecret] = useState<IntegrationSubscription | null>(null)
  const [status, setStatus] = useState('')
  const [subscriptionId, setSubscriptionId] = useState('')
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null)
  const [page, setPage] = useState(1)
  const [inspecting, setInspecting] = useState<IntegrationDelivery | null>(null)
  const [form] = Form.useForm<SubscriptionInput>()
  const subscriptions = useQuery({ queryKey: ['integrationSubscriptions', integration.id], queryFn: () => fetchIntegrationSubscriptions(integration.id) })
  const filters = { status, subscriptionId, from: range?.[0]?.toISOString() ?? '', to: range?.[1]?.toISOString() ?? '', offset: String((page - 1) * 50) }
  const deliveries = useQuery({ queryKey: ['integrationDeliveries', integration.id, filters], queryFn: () => fetchIntegrationDeliveries(integration.id, filters), refetchInterval: 10_000 })
  const attempts = useQuery({ queryKey: ['integrationAttempts', integration.id, inspecting?.id], queryFn: () => fetchIntegrationAttempts(integration.id, inspecting!.id), enabled: !!inspecting })
  const statusText = (value: string) => deliveryLabels[value] ? t(deliveryLabels[value]) : value
  const summary = deliveries.data?.summary
  const kinds = ['incident.created', 'incident.triaged', 'incident.evidence_updated', 'incident.status_changed']
  const run = async (fn: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true; setBusy(true)
    try { await fn(); await client.invalidateQueries({ queryKey: ['integrationSubscriptions', integration.id] }); await client.invalidateQueries({ queryKey: ['integrationDeliveries', integration.id] }) }
    catch (e) { message.error(errText(e, t)) } finally { lock.current = false; setBusy(false) }
  }
  const edit = (row?: IntegrationSubscription) => {
    form.resetFields()
    form.setFieldsValue(row ? { name: row.name, url: row.url, groupIds: row.groupIds, kinds: row.kinds, enabled: row.enabled, movePending: false } : { name: '', url: '', groupIds: integration.groupIds, kinds: ['incident.triaged'], enabled: false, movePending: false })
    setEditing(row ?? 'new')
  }
  return <Space orientation="vertical" size={20} style={{ width: '100%' }}>
    <Typography.Paragraph style={{ marginBottom: 0 }}>{t('integrationWebhookHint')}</Typography.Paragraph>
    <div>
      <Button type="primary" disabled={!integration.scopes.includes('incidents:read')} onClick={() => edit()}>{t('integrationNewSubscription')}</Button>
    </div>
    {secret && <Alert type="warning" title={t('integrationSecretOnce')} description={<><Typography.Text>Key ID: {secret.keyId}</Typography.Text><Typography.Paragraph copyable style={{ overflowWrap: 'anywhere' }}>{secret.secret}</Typography.Paragraph></>} closable onClose={() => setSecret(null)} />}
    {subscriptions.isError ? <LoadError error={subscriptions.error} onRetry={() => subscriptions.refetch()} /> : <Table<IntegrationSubscription> rowKey="id" dataSource={subscriptions.data} loading={subscriptions.isPending} scroll={{ x: 750 }} columns={[
      { title: t('integrationName'), dataIndex: 'name' },
      { title: 'URL', dataIndex: 'url', ellipsis: true },
      { title: t('integrationEnabled'), render: (_, s) => <Tag>{t(s.enabled ? 'integrationOn' : 'integrationOff')}</Tag> },
      { title: t('integrationActions'), render: (_, s) => <div className="table-actions">
        <Button size="small" onClick={() => edit(s)}>{t('integrationEdit')}</Button>
        <Button size="small" disabled={busy || !s.enabled} onClick={() => run(async () => { await testIntegrationSubscription(integration.id, s.id); message.success(t('integrationTestQueued')) })}>{t('integrationTest')}</Button>
        <Popconfirm title={t('integrationRotateHint')} onConfirm={() => run(async () => { setSecret(await rotateIntegrationSecret(integration.id, s.id)) })}><Button size="small" disabled={busy || s.enabled}>{t('integrationRotate')}</Button></Popconfirm>
        <Popconfirm title={t('integrationDeleteSubscriptionHint')} onConfirm={() => run(async () => { await deleteIntegrationSubscription(integration.id, s.id) })}><Button size="small" danger disabled={busy}>{t('integrationDeleteSubscription')}</Button></Popconfirm>
      </div> },
    ]} />}
    <Typography.Title level={5} style={{ margin: '4px 0 0' }}>{t('integrationDeliveries')}</Typography.Title>
    {summary && <Space wrap>
      {['pending', 'sending', 'delivered', 'dead'].map(state => <Tag key={state} color={state === 'dead' && summary.counts[state] ? 'error' : undefined}>{statusText(state)}: {summary.counts[state] ?? 0}</Tag>)}
      {summary.oldestPendingAt && <Typography.Text>{t('integrationOldestPending')}: {fmtTime(summary.oldestPendingAt)}</Typography.Text>}
    </Space>}
    {!!summary?.counts.dead && <Alert type="warning" title={t('integrationDeadHint')} />}
    <div className="filter-bar" style={{ padding: '12px 18px' }}>
      <Space wrap size={12} className="filter-controls">
        <Select aria-label={t('thStatus')} value={status} onChange={v => { setStatus(v); setPage(1) }} style={{ width: 180 }} options={[{ value: '', label: t('integrationAllDeliveries') }, ...Object.keys(deliveryLabels).map(value => ({ value, label: statusText(value) }))]} />
        <Select aria-label={t('integrationSubscription')} value={subscriptionId} onChange={v => { setSubscriptionId(v); setPage(1) }} style={{ width: 200 }} options={[{ value: '', label: t('integrationAllSubscriptions') }, ...(subscriptions.data ?? []).map(s => ({ value: s.id, label: s.name }))]} />
        <DatePicker.RangePicker showTime value={range} onChange={v => { setRange(v); setPage(1) }} />
      </Space>
    </div>
    {deliveries.isError ? <LoadError error={deliveries.error} onRetry={() => deliveries.refetch()} /> : <Table<IntegrationDelivery> rowKey="id" dataSource={deliveries.data?.items} loading={deliveries.isPending} pagination={{ current: page, pageSize: 50, total: deliveries.data?.total ?? 0, showSizeChanger: false, onChange: setPage }} scroll={{ x: 850 }} columns={[
      { title: t('thCreatedAt'), render: (_, d) => fmtTime(d.createdAt) },
      { title: t('integrationSubscription'), render: (_, d) => subscriptions.data?.find(s => s.id === d.subscriptionId)?.name ?? d.subscriptionId },
      { title: t('thStatus'), dataIndex: 'status', render: value => <Tag>{statusText(value)}</Tag> },
      { title: t('integrationAttempts'), dataIndex: 'attempts' },
      { title: t('integrationNextAttempt'), render: (_, d) => d.status === 'pending' ? fmtTime(d.nextAt) : '—' },
      { title: t('integrationDeliveryError'), dataIndex: 'lastError' },
      { title: t('integrationActions'), render: (_, d) => <div className="table-actions"><Button size="small" onClick={() => setInspecting(d)}>{t('integrationDeliveryDetail')}</Button><Popconfirm title={t('integrationReplayHint')} onConfirm={() => run(async () => { await retryIntegrationDelivery(integration.id, d.id) })}><Button size="small" disabled={busy || d.status !== 'dead'}>{t('integrationReplay')}</Button></Popconfirm></div> },
    ]} />}
    <Modal open={!!inspecting} title={t('integrationDeliveryDetail')} onCancel={() => setInspecting(null)} footer={null} width={800}>
      <Typography.Paragraph copyable>{inspecting?.eventId}</Typography.Paragraph>
      <Typography.Paragraph>{inspecting?.targetUrl} · {t('integrationTargetVersion', { n: inspecting?.targetVersion ?? 0 })}</Typography.Paragraph>
      {inspecting?.completedAt && <Typography.Paragraph>{t('integrationHistoryExpires', { at: fmtTime(new Date(Date.parse(inspecting.completedAt) + 30 * 86400_000).toISOString()) })}</Typography.Paragraph>}
      <Typography.Paragraph type="secondary">{t('integrationAttemptsLimit')}</Typography.Paragraph>
      {attempts.isError ? <LoadError error={attempts.error} onRetry={() => attempts.refetch()} /> : <Table rowKey="leaseGeneration" dataSource={attempts.data} loading={attempts.isPending} columns={[
        { title: t('thCreatedAt'), dataIndex: 'startedAt', render: fmtTime },
        { title: t('integrationAttemptEnded'), dataIndex: 'endedAt', render: fmtTime },
        { title: 'HTTP', dataIndex: 'httpStatus', render: n => n || '—' },
        { title: t('thStatus'), dataIndex: 'result', render: statusText },
      ]} />}
    </Modal>
    <Modal open={!!editing} title={t('integrationSubscription')} onCancel={() => setEditing(null)} onOk={() => form.submit()} confirmLoading={busy} okText={t('save')}>
      <Form form={form} layout="vertical" onFinish={body => run(async () => { const row = await saveIntegrationSubscription(integration.id, body, editing && editing !== 'new' ? editing.id : undefined); if (row.secret) setSecret(row); setEditing(null) })}>
        <Form.Item name="name" label={t('integrationName')} rules={[{ required: true, whitespace: true, max: 100 }]}><Input maxLength={100} /></Form.Item>
        <Form.Item name="url" label="HTTPS URL" rules={[{ required: true }]}><Input maxLength={2048} /></Form.Item>
        <Form.Item name="groupIds" label={t('group')} rules={[{ required: true, type: 'array', min: 1 }]}><Select mode="multiple" options={integration.groupIds.map(id => ({ value: id, label: groups.find(g => g.id === id)?.name ?? id }))} /></Form.Item>
        <Form.Item name="kinds" label={t('integrationEventTypes')} rules={[{ required: true, type: 'array', min: 1 }]}><Select mode="multiple" options={kinds.map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="enabled" label={t('integrationEnabled')} valuePropName="checked"><Switch /></Form.Item>
        {editing !== 'new' && <Form.Item name="movePending" label={t('integrationMovePending')} extra={t('integrationMovePendingHint')} valuePropName="checked"><Switch /></Form.Item>}
      </Form>
    </Modal>
  </Space>
}
