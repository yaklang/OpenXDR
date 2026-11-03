import { useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Card, Form, Input, Popconfirm, Space, Switch, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchFeishuApproval, requestFeishuBinding, saveFeishuApproval, sendFeishuTest, unbindFeishu } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'

const STATES: Record<string, MsgKey> = {
  connected: 'feishuStateConnected',
  bound: 'feishuStateBound',
  connecting: 'feishuStateConnecting',
  reconnecting: 'feishuStateReconnecting',
  reconnect_wait: 'feishuStateReconnectWait',
  disconnected: 'feishuStateDisconnected',
  disabled: 'feishuStateDisabled',
  binding_rejected: 'feishuStateBindingRejected',
  connection_error: 'feishuStateConnectionError',
  configuration_unavailable: 'feishuStateConfigUnavailable',
  credential_unavailable: 'feishuStateCredentialUnavailable',
}

export function FeishuApproval() {
  const { t } = useI18n()
  const { isAdmin } = useSession()
  const { message } = App.useApp()
  const state = useQuery({ queryKey: ['feishu-approval'], queryFn: fetchFeishuApproval, refetchInterval: 5000 })
  const [busy, setBusy] = useState(false)
  const [binding, setBinding] = useState<{ code: string; expires: number }>()
  const [form] = Form.useForm()
  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    try { await fn(); await state.refetch() } catch { message.error(t('feishuRequestFailed')) } finally { setBusy(false) }
  }
  if (state.isError) return <Alert type="error" title={t('feishuLoadFailed')} action={<Button onClick={() => state.refetch()}>{t('retry')}</Button>} />
  if (!state.data) return <Card loading />
  const current = state.data
  const label = STATES[current.connection]
  return <Space orientation="vertical" style={{ width: '100%' }} size={16}>
    <Alert type="info" showIcon title={t('feishuTab')} description={t('feishuIntro')} />
    <Space><Tag>{label ? t(label) : current.connection}</Tag><Tag color={current.bound ? 'green' : 'default'}>{t(current.bound ? 'feishuBound' : 'feishuUnbound')}</Tag>{current.callback_verified && <Tag color="green">{t('feishuCallbackVerified')}</Tag>}</Space>
    <Card title={t('feishuBindTitle')}>
      <Typography.Paragraph>{t('feishuSetupHint')}</Typography.Paragraph>
      {!current.bound && <Button disabled={!current.enabled || busy} loading={busy} onClick={() => run(async () => { const r = await requestFeishuBinding(); setBinding({ code: r.code, expires: Date.now() + r.expires_in * 1000 }) })}>{t('feishuGenerateCode')}</Button>}
      {!current.bound && binding && binding.expires > Date.now() && <Alert style={{ marginTop: 12 }} type="warning" title={t('feishuCodeHint')} description={<Typography.Text code copyable>{binding.code}</Typography.Text>} />}
      {current.bound && <Space><Button loading={busy} disabled={busy || !current.enabled} onClick={() => run(async () => { await sendFeishuTest(); message.success(t('feishuTestRequested')) })}>{t('feishuSendTest')}</Button><Popconfirm title={t('feishuUnbindConfirm')} onConfirm={() => run(async () => { await unbindFeishu(); setBinding(undefined) })}><Button danger disabled={busy}>{t('feishuUnbind')}</Button></Popconfirm></Space>}
    </Card>
    {isAdmin && <Card title={t('feishuSettingsTitle')}>
      <Form form={form} layout="vertical" initialValues={{ app_id: current.app_id, enabled: current.enabled }} onFinish={values => run(async () => { await saveFeishuApproval(values); form.setFieldValue('app_secret', ''); message.success(t('feishuSaved')) })}>
        <Form.Item name="enabled" valuePropName="checked" label={t('feishuEnable')}><Switch /></Form.Item>
        <Form.Item name="app_id" label="App ID" rules={[{ required: true, pattern: /^cli_[a-zA-Z0-9]{8,80}$/ }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="app_secret" label="App Secret" extra={t(current.secret_set ? 'feishuSecretKept' : 'feishuSecretNew')}><Input.Password autoComplete="new-password" /></Form.Item>
        <Typography.Paragraph type="secondary">{t('feishuSaveHint')}</Typography.Paragraph>
        <Button htmlType="submit" type="primary" loading={busy}>{t('feishuSave')}</Button>
      </Form>
    </Card>}
  </Space>
}
