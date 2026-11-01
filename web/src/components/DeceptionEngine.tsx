import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { admitDeceptionRelease, disableDeceptionRelease, fetchDeceptionReleases, fetchDeceptionRevisions, fetchHostedDeceptionRelease, fetchHostedDeceptionStatus, selectDeceptionRevision, stopDeceptionRuntime, type DecoyDeployment, type DeceptionConfig, type DeceptionReleaseInput } from '../api'
import { Ago } from './Ago'
import { errText } from './format'
import { useI18n } from '../i18n'

const defaults: DeceptionConfig = { hosted: true, attachment: 'standalone', mode: 'observe', origin: '', prefix: '/_dygk', entries: 3, branches: 4, depth: 4, maxNodes: 256, requestLimit: 120 }

export function DeceptionReleases({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [open, setOpen] = useState(false)
  const [info, setInfo] = useState('')
  const releases = useQuery({ queryKey: ['deception-releases'], queryFn: fetchDeceptionReleases, enabled: open })
  const admit = useMutation({ mutationFn: async () => { const value = JSON.parse(info) as DeceptionReleaseInput; await admitDeceptionRelease(value) }, onSuccess: () => { setInfo(''); void releases.refetch() }, onError: e => message.error(errText(e, t)) })
  const disable = useMutation({ mutationFn: disableDeceptionRelease, onSuccess: () => { void releases.refetch() }, onError: e => message.error(errText(e, t)) })
  if (!isAdmin) return null
  return <>
    <Button onClick={() => setOpen(true)}>{t('deceptionReleases')}</Button>
    <Modal open={open} title={t('deceptionReleases')} onCancel={() => setOpen(false)} footer={null} width={850}>
      <Space orientation="vertical" style={{ width: '100%' }}>
        <Typography.Paragraph>{t('deceptionReleaseHint')}</Typography.Paragraph>
        <Input.TextArea value={info} onChange={e => setInfo(e.target.value)} rows={4} aria-label={t('deceptionReleaseInfo')} />
        <Button type="primary" disabled={!info.trim()} loading={admit.isPending} onClick={() => admit.mutate()}>{t('deceptionAdmit')}</Button>
        {releases.isError && <Alert type="error" title={errText(releases.error, t)} />}
        <Table rowKey="id" size="small" loading={releases.isPending} dataSource={releases.data ?? []} pagination={{ pageSize: 5 }} columns={[
          { title: t('deceptionEngine'), dataIndex: 'engine' },
          { title: t('deceptionVersion'), dataIndex: 'version', ellipsis: true },
          { title: t('deceptionDigest'), dataIndex: 'digest', ellipsis: true },
          { title: t('actions'), render: (_, row) => row.enabled ? <Popconfirm title={t('deceptionDisableHint')} onConfirm={() => disable.mutateAsync(row.id)}><Button size="small" danger loading={disable.isPending}>{t('deceptionDisable')}</Button></Popconfirm> : <Tag>{t('deceptionDisabled')}</Tag> },
        ]} />
      </Space>
    </Modal>
  </>
}

export function DeceptionEngine({ row, refresh }: { row: DecoyDeployment; refresh: () => unknown }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm<DeceptionConfig & { releaseId: string; proxyList: string }>()
  const releases = useQuery({ queryKey: ['deception-releases'], queryFn: fetchDeceptionReleases, enabled: open })
  const revisions = useQuery({ queryKey: ['deception-revisions', row.id], queryFn: () => fetchDeceptionRevisions(row.id), enabled: open })
  const attachment = Form.useWatch('attachment', form)
  const onError = (e: Error) => message.error(errText(e, t))
  const select = useMutation({ mutationFn: async () => {
    const values = await form.validateFields()
    const { releaseId, proxyList, ...config } = values
    await selectDeceptionRevision(row.id, { releaseId, expectedRevision: row.active_revision_id, config: { ...defaults, ...config, upstream: config.attachment === 'gateway' ? config.upstream : undefined, trustedProxies: proxyList?.split(',').map(v => v.trim()).filter(Boolean) ?? [] } })
  }, onSuccess: () => { setOpen(false); void refresh(); message.success(t('deceptionRevisionSaved')) }, onError })
  const stop = useMutation({ mutationFn: () => stopDeceptionRuntime(row.id), onSuccess: () => { void refresh(); message.info(t('deceptionStopPending')) }, onError })
  const show = async () => {
    setOpen(true)
    form.resetFields()
    form.setFieldsValue(defaults)
    try {
      const history = await fetchDeceptionRevisions(row.id)
      const active = history.items.find(v => v.id === row.active_revision_id)
      if (active) form.setFieldsValue({ ...active.spec, releaseId: active.release_id, proxyList: active.spec.trustedProxies?.join(',') ?? '' })
      else if (row.kind === 'http' && row.profile === 'decoy') { const hosted = await fetchHostedDeceptionRelease(); if (hosted) form.setFieldsValue({ releaseId: hosted.id }) }
      else form.setFieldsValue({ hosted: false })
    } catch (e) { onError(e as Error) }
  }
  return <>
    <Button size="small" disabled={row.status !== 'registered'} onClick={() => { void show() }}>{t('deceptionConfigure')}</Button>
    {row.active_revision_id && <Popconfirm title={t('deceptionStopHint')} onConfirm={() => stop.mutateAsync()}><Button size="small" disabled={row.stop_requested} loading={stop.isPending}>{t('deceptionStop')}</Button></Popconfirm>}
    <Modal open={open} title={t('deceptionConfigure')} onCancel={() => setOpen(false)} onOk={() => select.mutate()} confirmLoading={select.isPending} width={760}>
      <Alert type="info" showIcon title={t('deceptionRevisionHint')} />
      <Typography.Paragraph type="secondary">{t('deceptionHostedHint')}</Typography.Paragraph>
      {(releases.isError || revisions.isError) && <Alert type="error" title={t('deceptionLoadFailed')} />}
      <Form form={form} layout="vertical" initialValues={defaults} style={{ marginTop: 16 }}>
        <Form.Item name="releaseId" label={t('deceptionVersion')} rules={[{ required: true }]}><Select onChange={id => form.setFieldsValue({ hosted: releases.data?.find(v => v.id === id)?.engine === 'dygk' })} options={(releases.data ?? []).filter(v => v.enabled && (v.engine === 'native' || row.kind === 'http' && row.profile === 'decoy')).map(v => ({ value: v.id, label: `${v.engine} · ${v.version} · ${v.digest.slice(7, 19)}` }))} /></Form.Item>
        <Form.Item name="hosted" label={t('deceptionHosted')} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="attachment" label={t('deceptionAttachment')}><Select options={[{ value: 'standalone', label: t('deceptionStandalone') }, { value: 'gateway', label: t('deceptionGateway') }]} /></Form.Item>
        <Form.Item name="mode" label={t('deceptionMode')}><Select options={[{ value: 'observe', label: t('deceptionObserve') }, { value: 'block', label: t('deceptionBlock') }, { value: 'quarantine', label: t('deceptionQuarantine') }]} /></Form.Item>
        <Form.Item name="origin" label={t('deceptionOrigin')}><Input placeholder="https://service.example" /></Form.Item>
        {attachment === 'gateway' && <><Alert type="warning" title={t('deceptionGatewayHint')} /><Form.Item name="upstream" label={t('deceptionUpstream')} rules={[{ required: true }]}><Input placeholder="http://business:8080" /></Form.Item></>}
        <Form.Item name="prefix" label={t('deceptionPrefix')}><Input /></Form.Item>
        <Form.Item name="proxyList" label={t('deceptionProxies')}><Input /></Form.Item>
        <Space><Form.Item name="maxNodes" label={t('deceptionNodeLimit')}><InputNumber min={1} max={4096} /></Form.Item><Form.Item name="requestLimit" label={t('deceptionRequestLimit')}><InputNumber min={4} max={1000} /></Form.Item></Space>
      </Form>
      <Typography.Paragraph type="secondary">{t('deceptionHistoryHint')}</Typography.Paragraph>
      <Table rowKey="id" size="small" dataSource={revisions.data?.items ?? []} pagination={{ pageSize: 4 }} columns={[{ title: t('deceptionRevision'), dataIndex: 'number' }, { title: t('deceptionMode'), render: (_, rev) => rev.spec.mode }, { title: t('actions'), render: (_, rev) => <Button size="small" onClick={() => form.setFieldsValue({ ...rev.spec, releaseId: rev.release_id, proxyList: rev.spec.trustedProxies?.join(',') ?? '' })}>{t('deceptionUseRevision')}</Button> }]} />
      {revisions.data?.more && <Alert type="info" title={t('deceptionHistoryTruncated')} />}
    </Modal>
  </>
}

export function DeceptionStatus() {
  const { t } = useI18n()
  const status = useQuery({ queryKey: ['deception-hosted-status'], queryFn: fetchHostedDeceptionStatus, refetchInterval: 10000 })
  return <Alert type={status.data?.online ? 'success' : 'warning'} showIcon title={<Space wrap>
    <span>{t('deceptionManager')}: {status.isError ? t('deceptionLoadFailed') : status.data?.online ? t('deceptionManagerOnline') : t('deceptionManagerOffline')}</span>
    {status.data?.seenAt && <Ago iso={status.data.seenAt} />}
  </Space>} description={t('deceptionReachabilityUnknown')} />
}
