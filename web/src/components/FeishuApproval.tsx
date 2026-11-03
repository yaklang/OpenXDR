import { useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Card, Form, Input, Popconfirm, Space, Switch, Tag, Typography } from 'antd'
import { useState } from 'react'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'

type State = { enabled: boolean; app_id: string; secret_set: boolean; bound: boolean; connection: string; callback_verified: boolean }
async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(path, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  if (!response.ok) throw new Error('request_failed')
  return response.status === 204 || response.status === 202 ? undefined as T : response.json()
}

export function FeishuApproval() {
  const { locale } = useI18n()
  const zh = locale === 'zh'
  const { isAdmin } = useSession()
  const { message } = App.useApp()
  const state = useQuery({ queryKey: ['feishu-approval'], queryFn: () => request<State>('/api/approvals/feishu'), refetchInterval: 5000 })
  const [busy, setBusy] = useState(false)
  const [binding, setBinding] = useState<{ code: string; expires: number }>()
  const [form] = Form.useForm()
  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    try { await fn(); await state.refetch() } catch { message.error(zh ? '操作失败，请检查配置或稍后重试' : 'Request failed. Check the configuration or retry later.') } finally { setBusy(false) }
  }
  if (state.isError) return <Alert type="error" title={zh ? '无法读取飞书配置' : 'Cannot load Feishu settings'} action={<Button onClick={() => state.refetch()}>{zh ? '重试' : 'Retry'}</Button>} />
  if (!state.data) return <Card loading />
  const current = state.data
  const labels: Record<string, string> = zh ? { connected: '已连接', bound: '绑定成功', connecting: '连接中', reconnecting: '重连中', disconnected: '已断开', disabled: '未启用', binding_rejected: '绑定码无效或账号已绑定', connection_error: '连接失败', configuration_unavailable: '配置读取失败', credential_unavailable: '密钥不可用' } : {}
  return <Space orientation="vertical" style={{ width: '100%' }} size={16}>
    <Alert type="info" showIcon title={zh ? '飞书私聊审批' : 'Feishu private approvals'} description={zh ? '先绑定本人飞书账号。卡片只发送给有组审批权限的绑定用户，点击仍检查当前权限和有效期。批准不等于命令已执行成功。' : 'Bind your own Feishu account once. Cards are sent only to bound group administrators; permissions and expiry are checked again on every click. Approval does not mean execution succeeded.'} />
    <Space><Tag>{labels[current.connection] ?? current.connection}</Tag><Tag color={current.bound ? 'green' : 'default'}>{zh ? (current.bound ? '本人已绑定' : '本人未绑定') : (current.bound ? 'Account bound' : 'Not bound')}</Tag>{current.callback_verified && <Tag color="green">{zh ? '按钮回调已验证' : 'Callback verified'}</Tag>}</Space>
    <Card title={zh ? '绑定我的飞书账号' : 'Bind my Feishu account'}>
      <Typography.Paragraph>{zh ? '在飞书开放平台启用机器人，并在“事件与回调”选择长连接，添加 im.message.receive_v1 事件和 card.action.trigger 回调；开通 im:message.p2p_msg:readonly、im:message:send_as_bot 并发布。' : 'Enable the bot and long connection in Feishu Events & Callbacks. Subscribe to im.message.receive_v1 and card.action.trigger, grant im:message.p2p_msg:readonly and im:message:send_as_bot, then publish.'}</Typography.Paragraph>
      {!current.bound && <Button disabled={!current.enabled || busy} loading={busy} onClick={() => run(async () => { const r = await request<{ code: string; expires_in: number }>('/api/approvals/feishu/bind', 'POST', {}); setBinding({ code: r.code, expires: Date.now() + r.expires_in * 1000 }) })}>{zh ? '生成一次性绑定码' : 'Generate binding code'}</Button>}
      {!current.bound && binding && binding.expires > Date.now() && <Alert style={{ marginTop: 12 }} type="warning" title={zh ? '十分钟内将以下完整绑定码私发给机器人；不要发到群里或转交他人' : 'Send this code privately to the bot within 10 minutes. Do not share it.'} description={<Typography.Text code copyable>{binding.code}</Typography.Text>} />}
      {current.bound && <Space><Button loading={busy} disabled={busy || !current.enabled} onClick={() => run(async () => { await request('/api/approvals/feishu/test', 'POST', {}); message.success(zh ? '已请求向本人私发一张连接测试卡片' : 'Requested one private connection-test card') })}>{zh ? '私发测试卡片' : 'Send private test card'}</Button><Popconfirm title={zh ? '解绑后旧卡片将不能审批，确定？' : 'Unbind and invalidate existing cards?'} onConfirm={() => run(async () => { await request('/api/approvals/feishu/bind', 'DELETE'); setBinding(undefined) })}><Button danger disabled={busy}>{zh ? '解绑本人账号' : 'Unbind my account'}</Button></Popconfirm></Space>}
    </Card>
    {isAdmin && <Card title={zh ? '应用设置（全局管理员）' : 'Application settings (administrator)'}>
      <Form form={form} layout="vertical" initialValues={{ app_id: current.app_id, enabled: current.enabled }} onFinish={values => run(async () => { await request('/api/settings/feishu-approval', 'PUT', values); form.setFieldValue('app_secret', ''); message.success(zh ? '已保存，连接会自动刷新' : 'Saved. The connection will refresh.') })}>
        <Form.Item name="enabled" valuePropName="checked" label={zh ? '启用私聊审批通知' : 'Enable private approval cards'}><Switch /></Form.Item>
        <Form.Item name="app_id" label="App ID" rules={[{ required: true, pattern: /^cli_[a-zA-Z0-9]{8,80}$/ }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="app_secret" label="App Secret" extra={zh ? (current.secret_set ? '已加密保存；留空保留原密钥。更换应用须重新填写。' : '仅加密保存，不回显密钥。') : 'Stored encrypted and never returned. Leave blank to retain the existing secret for this app.'}><Input.Password autoComplete="new-password" /></Form.Item>
        <Typography.Paragraph type="secondary">{zh ? '保存配置会使之前发出的卡片失效，已有申请仍可在平台处理。' : 'Saving invalidates previously sent cards; existing requests remain available in the platform.'}</Typography.Paragraph>
        <Button htmlType="submit" type="primary" loading={busy}>{zh ? '保存应用设置' : 'Save application settings'}</Button>
      </Form>
    </Card>}
  </Space>
}
