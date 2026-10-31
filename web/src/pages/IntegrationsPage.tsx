import { TableActions } from '../components/TableActions'
import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Drawer, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import { useRef, useState } from 'react'
import { fetchIntegrations, fetchIntegrationTokens, fetchOutboundAllow, fetchUsers, issueIntegrationToken, revokeIntegrationToken, saveIntegration, saveOutboundAllow, type IntegrationInput, type IntegrationRow, type IntegrationTokenRow } from '../api'
import { useSession } from '../app/session'
import { IntegrationSubscriptions } from '../components/IntegrationSubscriptions'
import { LoadError } from '../components/LoadError'
import { Page, TableCard } from '../components/Page'
import { errText, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

export function IntegrationsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { groups, me } = useSession()
  const client = useQueryClient()
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<IntegrationRow | 'new' | null>(null)
  const [tokensFor, setTokensFor] = useState<IntegrationRow | null>(null)
  const [plain, setPlain] = useState<string | null>(null)
  const [subscriptionsFor, setSubscriptionsFor] = useState<IntegrationRow | null>(null)
  const [days, setDays] = useState(90)
  const [tokenScopes, setTokenScopes] = useState<string[]>([])
  const [allowOpen, setAllowOpen] = useState(false)
  const [allowText, setAllowText] = useState<string>()
  const [form] = Form.useForm<IntegrationInput>()
  const query = useQuery({ queryKey: ['integrations'], queryFn: fetchIntegrations })
  const users = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const outbound = useQuery({ queryKey: ['outboundAllow'], queryFn: fetchOutboundAllow, enabled: allowOpen })
  const tokens = useQuery({ queryKey: ['integrationTokens', tokensFor?.id], queryFn: () => fetchIntegrationTokens(tokensFor!.id), enabled: !!tokensFor })
  const scopeOptions = [{ value: 'assets:read', label: t('integrationAssetsRead') }, { value: 'incidents:read', label: t('integrationIncidentsRead') }, { value: 'tickets:write', label: t('integrationTicketsWrite') }, { value: 'incidents:resolve', label: t('integrationResolve') }, { value: 'suricata:write', label: t('integrationSuricataWrite') }]
  const run = async (fn: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true; setBusy(true)
    try { await fn(); await client.invalidateQueries({ queryKey: ['integrations'] }); await client.invalidateQueries({ queryKey: ['integrationTokens'] }) }
    catch (e) { message.error(errText(e, t)) }
    finally { lock.current = false; setBusy(false) }
  }
  const edit = (row?: IntegrationRow) => {
    form.resetFields()
    form.setFieldsValue(row ?? { name: '', purpose: '', ownerId: users.data?.find(u => u.username === me.username)?.id, enabled: false, scopes: ['assets:read'], groupIds: [], resolutionEnabled: false, allowedResolutions: ['closed'], allowMaliciousFalsePositive: false })
    setEditing(row ?? 'new')
  }
  const openTokens = (row: IntegrationRow) => { setTokensFor(row); setTokenScopes(row.scopes); setPlain(null); setDays(90) }
  return <Page title={t('navIntegrations')} subtitle={t('integrationHint')} extra={<Space><Button onClick={() => { setAllowText(undefined); setAllowOpen(true) }}>{t('integrationOutboundAllow')}</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => edit()}>{t('create')}</Button></Space>}>
    <TableCard>
      {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <Table<IntegrationRow> rowKey="id" dataSource={query.data} loading={query.isPending} scroll={{ x: 800 }} pagination={false} columns={[
        { title: t('integrationName'), dataIndex: 'name' },
        { title: t('integrationPurpose'), dataIndex: 'purpose' },
        { title: t('integrationEnabled'), render: (_, row) => <Tag>{t(row.enabled ? 'integrationOn' : 'integrationOff')}</Tag> },
        { title: t('group'), render: (_, row) => row.groupIds.map(id => groups.find(g => g.id === id)?.name ?? id).join(', ') || '—' },
        { title: t('integrationScopes'), render: (_, row) => row.scopes.map(s => <Tag key={s}>{s}</Tag>) },
        { title: t('integrationActions'), render: (_, row) => <TableActions><Button size="small" onClick={() => edit(row)}>{t('integrationEdit')}</Button><Button size="small" onClick={() => openTokens(row)}>{t('integrationTokens')}</Button><Button size="small" onClick={() => setSubscriptionsFor(row)}>{t('integrationSubscriptions')}</Button></TableActions> },
      ]} />}
    </TableCard>
    <Modal title={t('navIntegrations')} open={!!editing} onCancel={() => setEditing(null)} confirmLoading={busy} okText={t('save')} onOk={() => form.submit()}>
      <Form form={form} layout="vertical" onFinish={body => run(async () => { await saveIntegration(body, editing && editing !== 'new' ? editing.id : undefined); setEditing(null) })}>
        <Form.Item name="name" label={t('integrationName')} rules={[{ required: true, whitespace: true, max: 100 }]}><Input maxLength={100} /></Form.Item>
        <Form.Item name="purpose" label={t('integrationPurpose')}><Input.TextArea maxLength={1000} /></Form.Item>
        <Form.Item name="ownerId" label={t('integrationOwner')} rules={[{ required: true }]}><Select loading={users.isPending} options={users.data?.map(u => ({ value: u.id, label: u.username }))} /></Form.Item>
        {users.isError && <LoadError error={users.error} onRetry={() => users.refetch()} />}
        <Form.Item name="groupIds" label={t('group')} extra={t('integrationEmptyGroups')}><Select mode="multiple" options={groups.map(g => ({ value: g.id, label: g.name }))} /></Form.Item>
        <Form.Item name="scopes" label={t('integrationScopes')} rules={[{ required: true, type: 'array', min: 1 }]}><Select mode="multiple" options={scopeOptions} /></Form.Item>
        <Form.Item name="resolutionEnabled" label={t('integrationEnableResolve')} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="allowedResolutions" label={t('integrationResolutionActions')}><Select mode="multiple" options={['closed', 'false_positive', 'open'].map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="allowMaliciousFalsePositive" label={t('integrationMaliciousFalsePositive')} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="enabled" label={t('integrationEnabled')} valuePropName="checked"><Switch /></Form.Item>
      </Form>
    </Modal>
    <Drawer title={`${tokensFor?.name ?? ''} · ${t('integrationTokens')}`} open={!!tokensFor} onClose={() => { setTokensFor(null); setPlain(null) }} size="large">
      <Space orientation="vertical" style={{ width: '100%' }} size="middle">
        <Typography.Paragraph>{t('integrationTokenHint')}</Typography.Paragraph>
        <Space wrap>
          <InputNumber aria-label={t('integrationDays')} min={1} max={365} value={days} onChange={v => setDays(v ?? 90)} addonAfter={t('integrationDays')} />
          <Select aria-label={t('integrationScopes')} mode="multiple" style={{ minWidth: 220 }} value={tokenScopes} onChange={setTokenScopes} options={scopeOptions.filter(s => tokensFor?.scopes.includes(s.value))} />
          <Button loading={busy} disabled={tokenScopes.length === 0 || !!plain} onClick={() => run(async () => { const result = await issueIntegrationToken(tokensFor!.id, days, tokenScopes); setPlain(result.token ?? null) })}>{t('integrationIssue')}</Button>
        </Space>
        {plain && <Alert type="warning" title={t('integrationSecretOnce')} description={<Typography.Paragraph copyable style={{ overflowWrap: 'anywhere' }}>{plain}</Typography.Paragraph>} closable onClose={() => setPlain(null)} />}
        {tokens.isError ? <LoadError error={tokens.error} onRetry={() => tokens.refetch()} /> : <Table<IntegrationTokenRow> rowKey="id" dataSource={tokens.data} loading={tokens.isPending} scroll={{ x: 650 }} columns={[
          { title: t('integrationTokenPrefix'), dataIndex: 'prefix' },
          { title: t('integrationExpires'), render: (_, row) => fmtTime(row.expiresAt) },
          { title: t('integrationLastUsed'), render: (_, row) => <>{row.lastUsedAt ? fmtTime(row.lastUsedAt) : '—'}<br />{row.lastRemoteAddr}</> },
          { title: t('integrationScopes'), render: (_, row) => row.scopes.join(', ') },
          { title: t('integrationActions'), render: (_, row) => row.revoked ? <Tag>{t('integrationRevoked')}</Tag> : <Popconfirm title={t('integrationRevokeConfirm')} onConfirm={() => run(async () => { await revokeIntegrationToken(tokensFor!.id, row.id) })}><Button danger disabled={busy}>{t('integrationRevoke')}</Button></Popconfirm> },
        ]} />}
      </Space>
    </Drawer>
    <Modal title={t('integrationOutboundAllow')} open={allowOpen} onCancel={() => setAllowOpen(false)} confirmLoading={busy} okText={t('save')}
      okButtonProps={{ disabled: !outbound.data || outbound.data.locked }}
      onOk={() => run(async () => { await saveOutboundAllow((allowText ?? outbound.data!.entries.join('\n')).split('\n')); await client.invalidateQueries({ queryKey: ['outboundAllow'] }); setAllowOpen(false) })}>
      <Typography.Paragraph type="secondary">{t('integrationOutboundHint')}</Typography.Paragraph>
      {outbound.data?.locked && <Alert type="info" title={t('integrationOutboundLocked')} style={{ marginBottom: 12 }} />}
      {outbound.isError ? <LoadError error={outbound.error} onRetry={() => outbound.refetch()} /> :
        <Input.TextArea aria-label={t('integrationOutboundAllow')} rows={6} disabled={!outbound.data || outbound.data.locked}
          value={allowText ?? outbound.data?.entries.join('\n') ?? ''} placeholder={'desk.internal\n10.20.0.0/16'} onChange={e => setAllowText(e.target.value)} />}
    </Modal>
    <Drawer open={!!subscriptionsFor} title={t('integrationSubscriptions')} size="large" onClose={() => setSubscriptionsFor(null)} destroyOnHidden>
      {subscriptionsFor && <IntegrationSubscriptions integration={subscriptionsFor} />}
    </Drawer>
  </Page>
}
