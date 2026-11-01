import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { fetchDecoyInstallStatus, installDecoy, fetchHostCredentials, fetchAssets, fetchDecoyProfiles, fetchDecoys, registerDecoy, revokeDecoy, type DecoyDeployment, type DecoyKind, issueDecoyToken, fetchDecoyObservations, reviewDecoyObservation } from '../api'
import { useSession } from '../app/session'
import { Ago } from '../components/Ago'
import { HostLink } from '../components/HostLink'
import { LoadError } from '../components/LoadError'
import { Page, TableCard } from '../components/Page'
import { DeceptionEngine, DeceptionReleases, DeceptionStatus } from '../components/DeceptionEngine'
import { errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const runtimeErrors: Record<string, MsgKey> = { delivery_failed: 'deceptionDeliveryFailed', platform_unavailable: 'deceptionPlatformUnavailable', startup_failed: 'deceptionStartupFailed', pending_on_stop: 'deceptionPendingOnStop' }

export function DecoysPage() {
  const { group } = useSession()
  const { t } = useI18n()
  return group ? <GroupDecoys key={group.id} groupId={group.id} /> : <Page title={t('navDecoys')}><Alert title={t('noGroups')} type="info" /></Page>
}

function GroupDecoys({ groupId }: { groupId: string }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { group, isAdmin, canWrite } = useSession()
  const canReview = isAdmin || (canWrite && (group?.role === 'admin' || group?.role === 'analyst'))
  const canManage = isAdmin || (canWrite && group?.role === 'admin')
  const client = useQueryClient()
  const [installTarget, setInstallTarget] = useState<DecoyDeployment | null>(null)
  const [installForm] = Form.useForm<{ fingerprint: string; arch: string; listenHost: string; fileRoot?: string }>()
  const installStatus = useQuery({ queryKey: ['decoy-install-status'], queryFn: fetchDecoyInstallStatus, enabled: canManage })
  const credentials = useQuery({ queryKey: ['host-credentials', groupId], queryFn: () => fetchHostCredentials(groupId), enabled: canManage && !!installTarget })
  const [offset, setOffset] = useState(0)
  const [open, setOpen] = useState(false)
  const [token, setToken] = useState<{ token: string; expiresAt: string; id: string } | null>(null)
  const [issuing, setIssuing] = useState(false)
  const [observing, setObserving] = useState<string | null>(null)
  const observations = useQuery({ queryKey: ['decoy-observations', observing], queryFn: () => fetchDecoyObservations(observing!), enabled: !!observing })
  const issue = async (id: string) => {
    if (issuing) return
    setIssuing(true)
    try { setToken({ ...await issueDecoyToken(id), id }) } catch (e) { message.error(errText(e, t)) } finally { setIssuing(false) }
  }
  const [form] = Form.useForm<{ assetId: string; profile: string; port: number; kind: DecoyKind; resource: string }>()
  const selected = Form.useWatch('profile', form)
  const kind = Form.useWatch('kind', form) ?? 'ssh'
  const rows = useQuery({ queryKey: ['ssh-decoys', groupId, offset], queryFn: () => fetchDecoys(groupId, offset), refetchInterval: 15000 })
  const profiles = useQuery({ queryKey: ['ssh-decoy-profiles'], queryFn: fetchDecoyProfiles })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, enabled: open })
  const refresh = () => client.invalidateQueries({ queryKey: ['ssh-decoys', groupId] })
  const onError = (e: Error) => message.error(errText(e, t))
  const review = useMutation({ mutationFn: (observation: string) => reviewDecoyObservation(observing!, observation), onError, onSuccess: () => { void client.invalidateQueries({ queryKey: ['decoy-observations'] }); void client.invalidateQueries({ queryKey: ['incidents'] }); void client.invalidateQueries({ queryKey: ['stats'] }) } })
  const reviewable = new Set(['dygk_triggered', 'marker_used', 'ssh_marker_followed', 'http_page', 'file_opened', 'shell_started', 'shell_action', 'ssh_authentication_attempt', 'ssh_marker_rejected'])
  const create = useMutation({ mutationFn: registerDecoy, onError, onSuccess: () => { setOpen(false); form.resetFields(); setOffset(0); void refresh() } })
  const revoke = useMutation({ mutationFn: revokeDecoy, onError, onSuccess: () => { void refresh() } })
  const install = useMutation({ mutationFn: (values: { fingerprint: string; arch: string; listenHost: string; fileRoot?: string }) => installDecoy(installTarget!.id, values), onError, onSuccess: () => { message.success(t('decoysInstallCompleted')); setInstallTarget(null) }, onSettled: () => { void refresh() } })
  const installCredential = credentials.data?.find(c => c.assetId === installTarget?.asset_id)
  const profile = profiles.data?.find(p => p.id === selected && p.kind === kind)
  return <Page title={t('navDecoys')} subtitle={t('decoysSubtitle')} extra={<Space><DeceptionReleases isAdmin={isAdmin} />{canManage && <Button type="primary" onClick={() => setOpen(true)}>{t('decoysRegister')}</Button>}</Space>}>
    <Space orientation="vertical" style={{ width: '100%' }} size={20}>
      <Alert type="info" showIcon title={t('decoysBoundary')} />
      {installStatus.isError && <LoadError error={installStatus.error} onRetry={() => installStatus.refetch()} />}
      {canManage && installStatus.data && !installStatus.data.enabled && <Alert type="info" title={t('decoysInstallDisabled')} />}
      {profiles.isError && <LoadError error={profiles.error} onRetry={() => profiles.refetch()} />}
      <DeceptionStatus />
      <TableCard extra={
        <Space>
          <Button size="small" disabled={offset === 0 || rows.isFetching} onClick={() => setOffset(n => Math.max(0, n - 50))}>{t('decoysPrevious')}</Button>
          <Button size="small" disabled={!rows.data?.more || rows.isFetching || rows.isError} onClick={() => setOffset(n => n + 50)}>{t('decoysNext')}</Button>
          <Button size="small" loading={rows.isFetching} onClick={() => rows.refetch()}>{t('decoysRefresh')}</Button>
        </Space>
      }>
        {rows.isError ? <LoadError error={rows.error} onRetry={() => rows.refetch()} /> :
        <Table<DecoyDeployment>
          rowKey="id" loading={rows.isPending} dataSource={rows.data?.items ?? []} pagination={false} scroll={{ x: 850 }}
          columns={[
            { title: t('thHostname'), dataIndex: 'asset_id', render: id => <HostLink id={id} /> },
            { title: t('decoysKind'), dataIndex: 'kind' },
            { title: t('decoysResource'), dataIndex: 'resource', render: (v, row) => v || row.port },
            { title: t('decoysProfile'), dataIndex: 'profile', render: id => t(id === 'decoy' ? 'decoysIdentify' : id === 'pause' ? 'decoysPause' : 'decoysPadding') },
            { title: t('decoysTemplate'), dataIndex: 'template' },
            { title: t('deceptionEngine'), render: (_, row) => <Tag>{t(row.active_revision_id ? 'deceptionManaged' : 'deceptionLegacy')}</Tag> },
            { title: t('decoysStatus'), dataIndex: 'status', render: status => <Tag color={status === 'registered' ? 'blue' : 'default'}>{t(status === 'registered' ? 'decoysRegistered' : 'decoysRevoked')}</Tag> },
            { title: t('decoysRuntime'), render: (_, row) => <Space orientation="vertical" size={0}><Tag>{t(({ unreported: 'decoysUnreported', starting: 'decoysStarting', running: 'decoysRunning', stopped: 'decoysStopped', failed: 'decoysFailed', stale: 'decoysStale', stopping: 'decoysStopping' } as const)[row.runtime_status ?? 'unreported'])}</Tag>{row.runtime_seen_at && <Ago iso={row.runtime_seen_at} />}{row.active_revision_id && <><Typography.Text type="secondary">{t('deceptionPending')}: {row.runtime_pending ?? t('deceptionNotReported')}</Typography.Text>{row.runtime_error && <Typography.Text type="danger">{t(runtimeErrors[row.runtime_error] ?? 'deceptionLoadFailed')}</Typography.Text>}<Typography.Text type="secondary">{t('deceptionEntranceUnverified')}</Typography.Text></>}</Space> },
            { title: t('decoysInstallState'), render: (_, row) => <Tag>{t(({ idle: 'decoysInstallIdle', installing: 'decoysInstalling', installed: 'decoysInstalled', unconfirmed: 'decoysInstallUnconfirmed' } as const)[row.install_state ?? 'idle'])}</Tag> },
            { title: t('decoysCreated'), dataIndex: 'created_at', render: at => <Ago iso={at} /> },
            { title: t('decoysOperator'), dataIndex: 'created_by' },
            { title: t('actions'), render: (_, row) => <Space wrap>
              <Button size="small" onClick={() => setObserving(row.id)}>{t('decoysEvents')}</Button>
              {canManage && row.status === 'registered' && <>
                <DeceptionEngine row={row} refresh={refresh} />
                {row.kind !== 'shell' && <Button size="small" disabled={!installStatus.data?.enabled || !row.remote_installable} onClick={() => { installForm.resetFields(); setInstallTarget(row) }}>{t('decoysInstall')}</Button>}
                {!row.hosted && <Popconfirm title={t('decoysTokenConfirm')} onConfirm={() => issue(row.id)}><Button size="small" disabled={issuing || row.install_state === 'installing'}>{t('decoysToken')}</Button></Popconfirm>}
                <Popconfirm title={t('decoysRevokeHint')} onConfirm={() => revoke.mutateAsync(row.id)}><Button danger size="small" loading={revoke.isPending && revoke.variables === row.id} disabled={revoke.isPending}>{t('decoysRevoke')}</Button></Popconfirm>
              </>}
            </Space> },
          ]} />}
      </TableCard>
    </Space>
    <Modal open={open} title={t('decoysRegister')} onCancel={() => { if (!create.isPending) setOpen(false) }} confirmLoading={create.isPending}
      okButtonProps={{ disabled: profiles.isPending || profiles.isError || assets.isPending || assets.isError }}
      onOk={() => form.submit()} cancelButtonProps={{ disabled: create.isPending }} closable={!create.isPending} maskClosable={!create.isPending}>
      {assets.isError && <LoadError error={assets.error} onRetry={() => assets.refetch()} />}
      <Form form={form} layout="vertical" initialValues={{ kind: 'ssh', profile: 'decoy', port: 2222 }} onFinish={v => { if (!create.isPending) create.mutate({ ...v, port: v.kind === 'file' || v.kind === 'shell' ? 0 : v.port, resource: v.kind === 'file' ? v.resource : v.kind === 'shell' ? 'simulated-shell' : '' }) }} disabled={create.isPending}>
        <Form.Item name="assetId" label={t('thHostname')} rules={[{ required: true }]}><Select showSearch optionFilterProp="label" loading={assets.isFetching} options={(assets.data ?? []).filter(a => a.groupId === groupId).map(a => ({ value: a.id, label: a.hostname }))} /></Form.Item>
        <Form.Item name="kind" label={t('decoysKind')} rules={[{ required: true }]}><Select onChange={value => form.setFieldsValue({ port: value === 'http' ? 18080 : 2222, resource: 'README.md' })} options={['ssh', 'http', 'file', 'shell'].map(value => ({ value, label: value === 'http' ? 'HTTP / HTML' : value.toUpperCase() }))} /></Form.Item>
        <Form.Item name="profile" label={t('decoysProfile')} rules={[{ required: true }]}><Select options={(profiles.data ?? []).filter(p => p.kind === kind).map(p => ({ value: p.id, label: t(p.id === 'decoy' ? 'decoysIdentify' : p.id === 'pause' ? 'decoysPause' : 'decoysPadding') }))} /></Form.Item>
        {profile && <Typography.Paragraph type="secondary">{profile.template} · {t(kind !== 'ssh' ? 'decoysUntested' : profile.id === 'decoy' ? 'decoysIdentifyHint' : profile.id === 'pause' ? 'decoysPauseHint' : 'decoysPaddingHint')}</Typography.Paragraph>}
        {(kind === 'ssh' || kind === 'http') && <Form.Item name="port" label={t('decoysPort')} rules={[{ required: true }, { type: 'integer', min: 1, max: 65535 }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item>}
        {kind === 'file' && <Form.Item name="resource" label={t('decoysFilename')} rules={[{ required: true }, { pattern: /^[^/\\:]+\.md$/, max: 128 }]}><Input placeholder="README.md" /></Form.Item>}
        {(kind === 'file' || kind === 'shell') && <Alert type="info" title={t(kind === 'file' ? 'decoysFileHint' : 'decoysShellHint')} />}
      </Form>
    </Modal>
    <Modal open={!!token} title={t('decoysToken')} footer={null} onCancel={() => setToken(null)} destroyOnHidden>
      {token && <Space orientation="vertical" style={{ width: '100%' }}>
        <Alert type="warning" title={t('decoysTokenHint')} />
        <Typography.Text copyable>{token.token}</Typography.Text>
        <Typography.Text>{token.expiresAt}</Typography.Text>
        <Typography.Text code copyable>{`decoyhost -platform ${window.location.origin} -deployment ${token.id}${rows.data?.items.find(r => r.id === token.id)?.active_revision_id ? ' -managed' : ''}`}</Typography.Text>
<Typography.Paragraph type="secondary">{t('deceptionRuntimeHint')}</Typography.Paragraph>
      </Space>}
    </Modal>
    <Modal open={!!observing} title={t('decoysEvents')} footer={null} onCancel={() => setObserving(null)} destroyOnHidden>
      <Alert type="info" title={t('decoysEventsHint')} style={{ marginBottom: 14 }} />
      {observations.isError ? <LoadError error={observations.error} onRetry={() => observations.refetch()} /> : <>
        <Table rowKey="id" loading={observations.isPending} dataSource={observations.data?.items ?? []} pagination={{ pageSize: 10 }} columns={[{ title: t('decoysStatus'), dataIndex: 'kind' }, { title: t('decoysReceived'), dataIndex: 'received_at', render: at => <Ago iso={at} /> }, { title: t('deceptionSession'), dataIndex: 'session_id', render: (value: string) => value?.slice(0, 12) || '—' }, { title: t('actions'), render: (_, row) => row.incident_id ? <Link to={`/incidents/${row.incident_id}`}>{t('decoysOpenReview')}</Link> : canReview && reviewable.has(row.kind) && <Popconfirm title={t('decoysReviewConfirm')} onConfirm={() => review.mutateAsync(row.id)}><Button size="small" disabled={review.isPending} loading={review.isPending && review.variables === row.id}>{t('decoysReview')}</Button></Popconfirm> }]} />
        {observations.data?.more && <Typography.Text>{t('decoysEventsTruncated')}</Typography.Text>}
        <Button style={{ marginTop: 12 }} onClick={() => observations.refetch()} loading={observations.isFetching}>{t('decoysRefresh')}</Button>
      </>}
    </Modal>
  <Modal title={t('decoysInstall')} open={!!installTarget} confirmLoading={install.isPending} closable={!install.isPending} maskClosable={false} cancelButtonProps={{ disabled: install.isPending }} okButtonProps={{ disabled: credentials.isPending || credentials.isError || !installCredential || installCredential.os !== 'linux' }} onCancel={() => setInstallTarget(null)} onOk={() => installForm.submit()}>
      <Alert type="warning" showIcon title={t('decoysInstallHint')} style={{ marginBottom: 14 }} />
      {credentials.isError && <LoadError error={credentials.error} onRetry={() => credentials.refetch()} />}
      {!credentials.isPending && !credentials.isError && (!installCredential || installCredential.os !== 'linux') && <Alert type="error" title={t('decoysInstallNoCredential')} />}
      {installCredential && <Typography.Paragraph>{installCredential.username}@{installCredential.address}:{installCredential.port}</Typography.Paragraph>}
      <Form form={installForm} layout="vertical" initialValues={{ arch: 'amd64', listenHost: '127.0.0.1' }} onFinish={values => install.mutate(values)} disabled={install.isPending}>
        <Form.Item name="fingerprint" label={t('decoysFingerprint')} rules={[{ required: true }, { pattern: /^SHA256:[A-Za-z0-9+/]{43}$/, message: t('decoysFingerprint') }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="arch" label={t('decoysArch')} rules={[{ required: true }]}><Select options={[{ value: 'amd64', label: 'Linux amd64' }, { value: 'arm64', label: 'Linux arm64' }]} /></Form.Item>
        {installTarget?.kind === 'file'
          ? <Form.Item name="fileRoot" label={t('decoysFileRoot')} extra={t('decoysFileRootHint')} rules={[{ required: true }, { pattern: /^\/[A-Za-z0-9._/-]+$/, message: t('decoysFileRoot') }]}><Input placeholder="/srv/share" autoComplete="off" /></Form.Item>
          : <Form.Item name="listenHost" label={t('decoysListenHost')} rules={[{ required: true }]}><Input /></Form.Item>}
      </Form>
    </Modal></Page>
}
