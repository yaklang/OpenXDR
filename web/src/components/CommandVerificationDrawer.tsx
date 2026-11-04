import { useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Card, Descriptions, Drawer, Empty, Form, Input, Pagination, Select, Skeleton, Space, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchCommandVerification, fetchCommandVerifications, recordCommandVerification, type CommandRow, type CommandVerificationInput, type VerificationEvidence } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { CommandStatusTag, commandKind, errText, fmtTime } from './format'
import { LoadError } from './LoadError'

const outcomes: Record<CommandVerificationInput['outcome'], MsgKey> = {
  effective: 'verificationEffective', ineffective: 'verificationIneffective', inconclusive: 'verificationInconclusive',
}
const sources: Record<string, MsgKey> = {
  human: 'verificationSourceHuman', system: 'verificationSourceSystem', ai: 'verificationSourceAI',
}
const methods: Record<string, MsgKey> = {
  manual_review: 'verificationMethodManual', telemetry_post_action: 'verificationMethodTelemetry',
  exec_probe: 'verificationMethodProbe', receipt_correlation: 'verificationMethodReceipt',
  context_only: 'verificationMethodContext', ai_investigation: 'verificationMethodAI',
}

function EvidenceList({ title, items }: { title: string; items: VerificationEvidence[] }) {
  if (!items.length) return null
  return <Space orientation="vertical" style={{ width: '100%' }}>
    <Typography.Text strong>{title}</Typography.Text>
    {items.map(e => <div key={e.id} style={{ width: '100%' }}>
      <Typography.Text copyable>{e.id}</Typography.Text>
      <div>{fmtTime(e.ts)} · {e.source} · {e.classUid}</div>
      <pre className="json-block">{JSON.stringify(e.raw, null, 2)}</pre>
    </div>)}
  </Space>
}

function Evidence({ commandId, id, scope }: { commandId: string; id: string; scope: string }) {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['verificationEvidence', scope, commandId, id], queryFn: () => fetchCommandVerification(commandId, id), gcTime: 0 })
  if (query.isPending) return <Skeleton active />
  if (query.isError) return <LoadError error={query.error} onRetry={() => query.refetch()} />
  return <Space orientation="vertical" style={{ width: '100%' }}>
    {!query.data.evidence.length && <Typography.Text type="secondary">{t('verificationNoEvidence')}</Typography.Text>}
    <EvidenceList title={t('verificationAfterEvidence')} items={query.data.evidence} />
    <EvidenceList title={t('verificationBeforeContext')} items={query.data.context ?? []} />
  </Space>
}

export function CommandVerificationDrawer({ command, canEdit, onClose }: { command: CommandRow; canEdit: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { me, groups } = useSession()
  const scope = `${me.username}:${me.role}:${groups.map(g => `${g.id}:${g.role}`).sort().join(',')}`
  const [form] = Form.useForm<CommandVerificationInput>()
  const [saving, setSaving] = useState(false)
  const [uncertain, setUncertain] = useState(false)
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string | null>(null)
  const query = useQuery({ queryKey: ['commandVerifications', scope, command.id], queryFn: () => fetchCommandVerifications(command.id), gcTime: 0 })
  const currentPage = Math.min(page, Math.max(1, Math.ceil((query.data?.items.length ?? 0) / 10)))
  const save = async (input: CommandVerificationInput) => {
    if (saving) return
    setSaving(true)
    try {
      await recordCommandVerification(command.id, { ...input, eventIds: input.eventIds ?? [] })
      setUncertain(false)
      form.resetFields()
      setPage(1)
      message.success(t('verificationSaved'))
      await query.refetch()
    } catch (e) {
      setUncertain(true)
      message.error(errText(e, t))
    } finally { setSaving(false) }
  }
  const textRule = { validator: (_: unknown, value: string) => value?.trim() && new TextEncoder().encode(value).length <= 4000 ? Promise.resolve() : Promise.reject(new Error(t('verificationTextInvalid'))) }

  return <Drawer open onClose={onClose} title={t('verificationTitle')} size={720}>
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Text>{commandKind(command.kind, t)} · {fmtTime(command.createdAt)}</Typography.Text>
      <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{command.id}</Typography.Text>
      <Alert type="info" showIcon title={t('verificationHint')} />
      {canEdit && <Form form={form} layout="vertical" onFinish={save} disabled={saving} initialValues={{ outcome: 'inconclusive', eventIds: [] }}>
        {uncertain && <Alert type="warning" showIcon title={t('verificationSaveUncertain')} style={{ marginBottom: 16 }} />}
        <Form.Item name="expected" label={t('verificationExpected')} rules={[textRule]}><Input.TextArea rows={2} /></Form.Item>
        <Form.Item name="observed" label={t('verificationObserved')} rules={[textRule]}><Input.TextArea rows={3} /></Form.Item>
        <Form.Item name="outcome" label={t('verificationOutcome')} rules={[{ required: true }]}>
          <Select options={Object.entries(outcomes).map(([value, label]) => ({ value, label: t(label) }))} />
        </Form.Item>
        <Form.Item name="eventIds" label={t('verificationEvents')} extra={t('verificationEventsHint')} dependencies={['outcome']}
          rules={[{ validator: (_, values: string[] = []) => {
            const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            const valid = values.length <= 20 && new Set(values.map(v => v.toLowerCase())).size === values.length
              && values.every(v => uuid.test(v) && v !== '00000000-0000-0000-0000-000000000000')
              && (form.getFieldValue('outcome') === 'inconclusive' || values.length > 0)
            return valid ? Promise.resolve() : Promise.reject(new Error(t('verificationEvidenceInvalid')))
          } }]}><Select mode="tags" tokenSeparators={[',', ' ', '\n']} open={false} /></Form.Item>
        <Button type="primary" htmlType="submit" loading={saving}>{t('verificationSave')}</Button>
      </Form>}
      <Space wrap><Typography.Title level={5} style={{ margin: 0 }}>{t('verificationHistory')}</Typography.Title><Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button></Space>
      {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : query.isPending ? <Skeleton active /> : <>
        {query.data.truncated && <Alert type="info" showIcon title={t('listTruncated', { n: query.data.items.length })} />}
        {!query.data.items.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('verificationEmpty')} />}
        {query.data.items.slice((currentPage - 1) * 10, currentPage * 10).map(row => <Card key={row.id} size="small" title={t(outcomes[row.outcome])}>
          <Descriptions column={1} size="small" items={[
            { key: 'source', label: t('verificationSource'), children: <Tag color={row.source === 'ai' ? 'purple' : row.source === 'system' ? 'blue' : undefined}>{t(sources[row.source ?? 'human'] ?? 'verificationSourceUnknown')}</Tag> },
            { key: 'reviewer', label: t('verificationReviewer'), children: row.reviewer },
            ...(row.method ? [{ key: 'method', label: t('verificationMethod'), children: methods[row.method] ? t(methods[row.method]) : row.method }] : []),
            ...(row.sessionId ? [{ key: 'session', label: t('verificationSession'), children: <Typography.Text copyable>{row.sessionId}</Typography.Text> }] : []),
            { key: 'time', label: t('thTime'), children: fmtTime(row.createdAt) },
            { key: 'status', label: t('verificationReceipt'), children: <CommandStatusTag value={row.commandStatus} /> },
            { key: 'expected', label: t('verificationExpected'), children: <span style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{row.expected}</span> },
            { key: 'observed', label: t('verificationObserved'), children: <span style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{row.observed}</span> },
          ]} />
          <Button size="small" style={{ marginTop: 10 }} aria-expanded={expanded === row.id} onClick={() => setExpanded(expanded === row.id ? null : row.id)}>{t('verificationEvidence')}</Button>
          {expanded === row.id && <div style={{ marginTop: 12 }}><Evidence key={`${scope}:${row.id}`} scope={scope} commandId={command.id} id={row.id} /></div>}
        </Card>)}
        <Pagination current={currentPage} pageSize={10} total={query.data.items.length} hideOnSinglePage showSizeChanger={false} onChange={value => { setPage(value); setExpanded(null) }} />
      </>}
    </Space>
  </Drawer>
}
