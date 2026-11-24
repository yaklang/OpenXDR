import { CheckOutlined, DeleteOutlined, EyeOutlined, FileTextOutlined, KeyOutlined, LoadingOutlined, ReloadOutlined, RocketOutlined, UploadOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Flex, Image, Input, InputNumber, Modal, Popconfirm, Select, Space, Table, Tabs, Tag, Typography, Upload } from 'antd'
import { useEffect, useRef, useState } from 'react'
import { extractHostDocument, commitHostImport, deleteHostCredential, enrollHostCredential, fetchHostCredentials, discardHostImportJob, fetchHostImportJob, fetchHostImportStatus, startHostImport, type AIJob, type HostDocumentImage, type HostCredential, type HostImportPreview, type ImportedHost, type ReviewedHost } from '../api'
import { useSession } from '../app/session'
import { errText, uuid4 } from './format'
import { useI18n } from '../i18n'

export function ImportHostsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups, group } = useSession()
  const adminGroups = groups.filter(g => g.role === 'admin')
  const [groupId, setGroupId] = useState<string>()
  const selectedGroup = adminGroups.some(g => g.id === groupId) ? groupId : (group?.role === 'admin' ? group.id : adminGroups[0]?.id)
  const [document, setDocument] = useState('')
  const [images, setImages] = useState<HostDocumentImage[]>([])
  const [imageIndex, setImageIndex] = useState(0)
  const [imageOpen, setImageOpen] = useState(false)
  const sourceRef = useRef<HTMLDivElement>(null)
  const [reading, setReading] = useState(false)
  const [filename, setFilename] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [preview, setPreview] = useState<HostImportPreview>()
  const [tab, setTab] = useState('import')
  const [target, setTarget] = useState<HostCredential>()
  const [fingerprint, setFingerprint] = useState('')
  const status = useQuery({ queryKey: ['host-import-status'], queryFn: fetchHostImportStatus, enabled: open })
  const credentials = useQuery({ queryKey: ['host-credentials', selectedGroup], queryFn: () => fetchHostCredentials(selectedGroup!), enabled: open && !!selectedGroup })
  const refresh = () => {
    client.invalidateQueries({ queryKey: ['assets'] })
    client.invalidateQueries({ queryKey: ['groups'] })
    client.invalidateQueries({ queryKey: ['host-credentials'] })
  }
  // AI 提取在服务端后台跑：这里发起后轮询本组最近一次的结果。关掉窗口、换页都不打断，
  // 回来时自动带回结果（原文不在服务端保存，需要对照原文时重新粘贴或上传）
  const jobKey = ['host-import-job', selectedGroup]
  const job = useQuery({
    queryKey: jobKey, queryFn: () => fetchHostImportJob(selectedGroup!), enabled: open && !!selectedGroup,
    refetchInterval: q => (q.state.data?.status === 'running' ? 2000 : false),
  })
  const running = job.data?.status === 'running'
  const applied = useRef<string | null>(null)
  useEffect(() => {
    const j = job.data
    if (!open || j?.status !== 'done' || !j.result || !j.id || applied.current === j.id) return
    applied.current = j.id
    setConfirmed(false)
    setPreview({ hosts: j.result.hosts.map(h => ({ ...h, reviewId: uuid4() })) })
  }, [open, job.data])
  const parse = useMutation({
    mutationFn: () => startHostImport(selectedGroup!, document, images),
    onSuccess: (j: AIJob<HostImportPreview>) => { setPreview(undefined); setConfirmed(false); client.setQueryData(jobKey, j) },
    onError: e => message.error(errText(e, t)),
  })
  const discard = () => {
    setPreview(undefined); setConfirmed(false)
    client.setQueryData(jobKey, { status: 'none' })
    void discardHostImportJob(selectedGroup!).catch(e => message.error(errText(e, t)))
  }
  const save = useMutation({
    mutationFn: () => commitHostImport(selectedGroup!, preview!.hosts),
    onSuccess: result => { setFilename(''); setDocument(''); setImages([]); setImageOpen(false); setPreview(undefined); setConfirmed(false); setTab('credentials'); client.setQueryData(jobKey, { status: 'none' }); refresh(); message.success(t('hostImportSaved', { n: result.assetIds.length })) },
    onError: e => message.error(errText(e, t)),
  })
  const install = useMutation({
    mutationFn: () => enrollHostCredential(target!.id, fingerprint),
    onSuccess: () => { message.success(t('hostInstallDone')); setTarget(undefined); setFingerprint(''); refresh() },
    onError: e => { message.error(errText(e, t)); refresh() },
  })
  const remove = useMutation({ mutationFn: deleteHostCredential, onSuccess: refresh, onError: e => message.error(errText(e, t)) })
  const busy = reading || parse.isPending || save.isPending || install.isPending || remove.isPending
  const secure = window.location.protocol === 'https:'
  const close = () => {
    if (busy) return
    setFilename(''); setDocument(''); setImages([]); setImageOpen(false); setPreview(undefined); setConfirmed(false); setTarget(undefined); setFingerprint('')
    setTab('import'); parse.reset(); save.reset(); install.reset(); applied.current = null; onClose()
  }
  const edit = (id: string | undefined, patch: Partial<ReviewedHost>) => {
    setConfirmed(false)
    setPreview(current => current && ({ hosts: current.hosts.map(h => h.reviewId === id ? { ...h, ...patch } : h) }))
  }
  const showSource = (lines: number[]) => {
    const input = sourceRef.current?.querySelector('textarea')
    if (!input || !lines.length) return
    const textLines = document.split('\n')
    const first = Math.max(0, Math.min(...lines) - 1)
    const last = Math.min(textLines.length, Math.max(...lines))
    const start = textLines.slice(0, first).reduce((n, line) => n + line.length + 1, 0)
    const end = start + textLines.slice(first, last).join('\n').length
    input.focus()
    input.setSelectionRange(start, end)
    input.scrollTop = first * (parseFloat(getComputedStyle(input).lineHeight) || 22)
    input.scrollIntoView({ block: 'center', behavior: 'smooth' })
  }
  const reviewColumns = [
    ...(['hostname', 'address', 'username', 'hostKey'] as const).map(field => ({
      title: t(field === 'hostname' ? 'thHostname' : field === 'address' ? 'hostAddress' : field === 'username' ? 'hostUsername' : 'hostFingerprint'),
      width: field === 'hostKey' ? 220 : 170,
      render: (_: unknown, h: ReviewedHost) => <Input aria-label={field} value={h[field]} disabled={busy} onChange={e => edit(h.reviewId, { [field]: e.target.value })} />,
    })),
    { title: 'OS', width: 130, render: (_: unknown, h: ReviewedHost) => <Space orientation="vertical" size={0}><Select aria-label="OS" value={h.os || undefined} placeholder={t('hostChooseOS')} disabled={busy} style={{ width: 110 }} options={[{ value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }]} onChange={os => edit(h.reviewId, { os })} />{h.osDisplay && h.osDisplay.toLowerCase() !== h.os.toLowerCase() ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{h.osDisplay}</Typography.Text> : null}</Space> },
    { title: t('hostPort'), width: 110, render: (_: unknown, h: ReviewedHost) => <InputNumber aria-label={t('hostPort')} min={1} max={65535} precision={0} value={h.port} disabled={busy} onChange={port => edit(h.reviewId, { port: port ?? 0 })} /> },
    { title: t('hostCredential'), width: 160, render: (_: unknown, h: ReviewedHost) => <Space orientation="vertical"><Tag>{t(h.credentialToken ? 'hostCredentialDetected' : 'hostNoCredential')}</Tag>{h.credentialToken && <Button size="small" disabled={busy} onClick={() => edit(h.reviewId, { credentialToken: undefined, kind: 'none' })}>{t('hostDiscardCredential')}</Button>}</Space> },
    { title: t('hostReviewEvidence'), width: 260, render: (_: unknown, h: ReviewedHost) => <Space orientation="vertical"><Button type="link" size="small" disabled={!h.lines?.length} onClick={() => showSource(h.lines)}>{t('hostSourceLines', { lines: h.lines?.join(', ') || '—' })}</Button>{h.images?.map(n => <Button key={n} type="link" size="small" onClick={() => { setImageIndex(n - 1); setImageOpen(true) }}>{t('hostSourceImage', { n })}</Button>)}{h.issues?.map((issue, i) => <Typography.Text type="warning" key={i}>{issue}</Typography.Text>)}</Space> },
    { title: t('actions'), width: 90, render: (_: unknown, h: ReviewedHost) => <Button danger disabled={busy} onClick={() => { setConfirmed(false); setPreview(current => current && ({ hosts: current.hosts.filter(row => row.reviewId !== h.reviewId) })) }}>{t('remove')}</Button> },
  ]
  const columns = [
    { title: t('thHostname'), dataIndex: 'hostname' },
    { title: t('hostAddress'), render: (_: unknown, h: ImportedHost) => `${h.address}:${h.port}` },
    { title: 'OS', width: 140, render: (_: unknown, h: ImportedHost) => h.osDisplay || h.os },
    { title: t('hostUsername'), dataIndex: 'username' },
    { title: t('hostCredential'), render: (_: unknown, h: ImportedHost) => <Tag>{t(h.kind === 'none' ? 'hostNoCredential' : h.kind === 'password' ? 'hostPasswordStored' : 'hostKeyStored')}</Tag> },
  ]
  return <>
    <Modal title={t('hostImport')} open={open} onCancel={close} footer={null} width={960} closable={!busy} maskClosable={!busy} keyboard={!busy}>
      <Flex vertical gap={16}>
        {!secure && <Alert type="warning" title={t('hostHTTPSRequired')} />}
        <Select showSearch optionFilterProp="label" aria-label={t('addHostGroup')} value={selectedGroup} disabled={busy} options={adminGroups.map(g => ({ value: g.id, label: g.name }))}
          onChange={v => { setGroupId(v); applied.current = null; setPreview(undefined); setConfirmed(false) }} />
        {status.isError && <Alert type="error" title={t('hostImportStatusError')} action={<Button size="small" icon={<ReloadOutlined aria-hidden />} loading={status.isFetching} onClick={() => status.refetch()}>{t('retry')}</Button>} />}
        {status.data && !status.data.credentialStorage && <Alert type="warning" title={t('hostVaultDisabled')} />}
        {status.data && !status.data.aiParsing && <Alert type="warning" title={t('hostAIUnavailable')} />}
        <Tabs activeKey={tab} onChange={value => { if (!busy) setTab(value) }} items={[
          { key: 'import', icon: <FileTextOutlined aria-hidden />, label: t('hostImportDocument'), children: <Flex vertical gap={12}>
            <Typography.Text type="secondary">{t('hostImportHint')}</Typography.Text>
            <Upload accept=".md,.txt,.yaml,.yml,.json,.csv,.log,.conf,.html,.docx,.xlsx,.pdf,.png,.jpg,.jpeg,.gif,.webp" showUploadList={false} disabled={busy || !secure || !selectedGroup} beforeUpload={async file => {
              if (file.size > 20 * 1024 * 1024) { message.error(t('hostImportTooLarge')); return false }
              setPreview(undefined); setConfirmed(false); setDocument(''); setImages([]); setImageOpen(false); setFilename('')
              setReading(true)
              try {
                const doc = await extractHostDocument(selectedGroup!, file); setDocument(doc.document); setImages(doc.images ?? []); setFilename(file.name); setPreview(undefined); setConfirmed(false)
              } catch (e) {
                message.error(errText(e, t))
              } finally { setReading(false) }
              return false
            }}><Button icon={<UploadOutlined aria-hidden />} loading={reading} disabled={busy || !secure || !selectedGroup}>{t('hostChooseDocument')}</Button></Upload>
            {filename && <Typography.Text type="secondary" ellipsis={{ tooltip: filename }}>{filename}</Typography.Text>}
            {!!images.length && <Image.PreviewGroup preview={{ open: imageOpen, current: imageIndex, onOpenChange: setImageOpen, onChange: setImageIndex }}><Space wrap>{images.map((img, i) => <Space key={i} orientation="vertical"><Image width={100} height={100} style={{ objectFit: 'contain' }} src={img.dataUrl} alt={img.name} /><Typography.Text>{t('hostSourceImage', { n: i + 1 })}</Typography.Text></Space>)}</Space></Image.PreviewGroup>}
            <div ref={sourceRef}><Input.TextArea aria-label={t('hostImportDocument')} autoComplete="off" spellCheck={false} rows={10} value={document} placeholder={t('hostImportExample')} disabled={busy}
              onChange={e => { setDocument(e.target.value); setFilename(''); setPreview(undefined); setConfirmed(false) }} /></div>
            <Space wrap>
              <Button icon={<EyeOutlined aria-hidden />} loading={parse.isPending} disabled={!secure || !selectedGroup || (!document.trim() && !images.length) || busy || running || !status.data?.aiParsing} onClick={() => parse.mutate()}>{t('hostImportPreview')}</Button>
              <Button type="primary" icon={<CheckOutlined aria-hidden />} loading={save.isPending} disabled={!secure || !preview?.hosts.length || !confirmed || busy} onClick={() => save.mutate()}>{t('hostImportConfirm')}</Button>
            </Space>
            {running && <Alert type="info" showIcon icon={<LoadingOutlined />} title={t('hostImportRunning')} description={t('aiBackgroundHint')} />}
            {job.data?.status === 'failed' && !preview && <Alert type="warning" showIcon title={job.data.error || t('hostImportFailed')} />}
            {preview && !document && !images.length && <Alert type="info" showIcon title={t('hostImportRestored')} action={<Button size="small" onClick={discard}>{t('hostImportDiscard')}</Button>} />}
            {preview && <Typography.Text role="status">{t('hostPreviewCount', { n: preview.hosts.length })}</Typography.Text>}
            {preview && <Checkbox checked={confirmed} disabled={busy || !preview.hosts.length} onChange={e => setConfirmed(e.target.checked)}>{t('hostReviewConfirm')}</Checkbox>}
            {preview && <Table<ReviewedHost> rowKey="reviewId" size="small" scroll={{ x: 1550 }} columns={reviewColumns} dataSource={preview.hosts} pagination={{ pageSize: 10 }} />}
          </Flex> },
          { key: 'credentials', icon: <KeyOutlined aria-hidden />, label: t('hostCredentials'), children: <Flex vertical gap={12}>
            <Typography.Text type="secondary">{t('hostEnrollmentHint')}</Typography.Text>
            {credentials.isError && <Alert type="error" title={t('hostCredentialsError')} action={<Button size="small" icon={<ReloadOutlined aria-hidden />} loading={credentials.isFetching} onClick={() => credentials.refetch()}>{t('retry')}</Button>} />}
            <Table<HostCredential> rowKey="id" loading={credentials.isPending} size="small" scroll={{ x: 850 }} dataSource={credentials.data ?? []} pagination={{ pageSize: 10 }} columns={[
              ...columns,
              { title: t('actions'), render: (_, c) => <Space>
                <Button size="small" icon={<RocketOutlined aria-hidden />} disabled={!status.data?.sshEnrollment || busy} onClick={() => { setTarget(c); setFingerprint(c.hostKey) }}>{t('hostEnrollSSH')}</Button>
                <Popconfirm title={t('hostCredentialDeleteConfirm')} onConfirm={() => remove.mutateAsync(c.id)}><Button danger size="small" icon={<DeleteOutlined aria-hidden />} disabled={busy || remove.isPending}>{t('del')}</Button></Popconfirm>
              </Space> },
            ]} />
          </Flex> },
        ]} />
      </Flex>
    </Modal>
    <Modal title={t('hostEnrollSSH')} open={!!target} onCancel={() => !install.isPending && setTarget(undefined)} onOk={() => install.mutate()}
      confirmLoading={install.isPending} closable={!install.isPending} maskClosable={!install.isPending} keyboard={!install.isPending} okButtonProps={{ disabled: !fingerprint.startsWith('SHA256:') || install.isPending }}>
      <Flex vertical gap={12}>
        <Typography.Text>{target?.hostname} · {target?.username}@{target?.address}:{target?.port}</Typography.Text>
        <Alert type="info" title={t('hostFingerprintHint')} />
        <Input aria-label={t('hostFingerprint')} value={fingerprint} disabled={install.isPending || !!target?.hostKey} onChange={e => setFingerprint(e.target.value)} placeholder="SHA256:…" />
      </Flex>
    </Modal>
  </>
}
