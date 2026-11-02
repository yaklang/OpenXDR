import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Form, Input, InputNumber, Skeleton, Space, Switch, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchAISettings, saveAISettings, testAISettings, type AISettings, type AISettingsPatch } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { errText } from './format'

// 每项旁边标明来自控制台还是环境变量；控制台改过的可以一键回到环境变量
function Source({ field, view, onReset }: { field: string; view: AISettings; onReset: (f: string) => void }) {
  const { t } = useI18n()
  return view.source[field] === 'console'
    ? <Space size={4}><Tag color="blue" variant="filled">{t('srcConsole')}</Tag><Button type="link" size="small" aria-label={t('srcReset')} style={{ padding: 0 }} onClick={() => onReset(field)}>{t('srcReset')}</Button></Space>
    : <Tag variant="filled">{t('srcEnv')}</Tag>
}

// 密钥输入：不回显原值，只给末四位；留空不改，「清空」显式置空
function SecretField({ name, label, set, hint, view, onReset, onClear, extra }: {
  name: string; label: string; set: boolean; hint?: string; view: AISettings; onReset: (f: string) => void; onClear: () => void; extra?: string
}) {
  const { t } = useI18n()
  return (
    <Form.Item htmlFor={name} label={<Space>{label}<Source field={name} view={view} onReset={onReset} /></Space>} extra={extra}>
      <Space.Compact style={{ width: '100%', maxWidth: 520 }}>
        <Form.Item name={name} noStyle>
          <Input.Password id={name} aria-label={label} autoComplete="new-password" disabled={!view.canSaveSecrets}
            placeholder={set ? t('secretKeep', { hint: hint ? `····${hint}` : '' }) : t('secretEmpty')} />
        </Form.Item>
        {set && <Button disabled={!view.canSaveSecrets} onClick={onClear}>{t('secretClear')}</Button>}
      </Space.Compact>
    </Form.Item>
  )
}

function useAISettings() {
  const { t } = useI18n()
  const { message, modal } = App.useApp()
  const client = useQueryClient()
  const query = useQuery({ queryKey: ['ai-settings'], queryFn: fetchAISettings })
  const [busy, setBusy] = useState(false)
  const save = async (p: AISettingsPatch, ok = t('settingsSaved')) => {
    setBusy(true)
    try {
      client.setQueryData(['ai-settings'], await saveAISettings(p))
      message.success(ok)
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally {
      setBusy(false)
    }
  }
  const reset = (field: string) => modal.confirm({ title: t('srcResetConfirm'), onOk: () => save({ reset: [field] }) })
  const test = async (p: AISettingsPatch & { target: 'model' | 'piModel' | 'vt' }) => {
    setBusy(true)
    try {
      const r = await testAISettings(p)
      message.success(p.target === 'vt' ? t('testVtOk', { ms: r.ms }) : t('testModelOk', { ms: r.ms, reply: r.reply || '-' }))
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }
  return { query, busy, save, reset, test }
}

// 只把改过的项发出去，没动的保持来源不变（环境变量的仍跟着环境变量走）
function diff(v: Record<string, unknown>, view: AISettings, keys: (keyof AISettings)[], secrets: string[]): AISettingsPatch {
  const p: Record<string, unknown> = {}
  for (const k of keys) if (v[k] !== undefined && v[k] !== view[k]) p[k] = v[k]
  for (const k of secrets) if (typeof v[k] === 'string' && v[k]) p[k] = v[k]
  return p as AISettingsPatch
}

export function AIModelSettings() {
  const { t } = useI18n()
  const [form] = Form.useForm()
  const { query, busy, save, reset, test } = useAISettings()
  if (query.isError) return <LoadError error={query.error} onRetry={() => query.refetch()} />
  if (!query.data) return <Card><Skeleton active /></Card>
  const view = query.data
  const patch = () => diff(form.getFieldsValue(), view, ['baseUrl', 'model', 'piModel'], ['apiKey'])

  return (
    <Card title={t('settingsAI')}>
      <Typography.Paragraph type="secondary">{t('settingsAIHint')}</Typography.Paragraph>
      {!view.canSaveSecrets && <Alert type="info" showIcon style={{ marginBottom: 16 }} title={t('noVaultHint')} />}
      <Form form={form} layout="vertical" style={{ maxWidth: 640 }} disabled={busy} initialValues={view} key={JSON.stringify(view)}
        onFinish={async () => { if (await save(patch())) form.setFieldsValue({ apiKey: '' }) }}>
        <Form.Item name="baseUrl" label={<Space>{t('aiBaseUrl')}<Source field="baseUrl" view={view} onReset={reset} /></Space>} extra={t('aiBaseUrlHint')}
          rules={[{ required: true, pattern: /^https?:\/\/\S+$/, message: t('aiBaseUrlHint') }]}>
          <Input style={{ maxWidth: 520 }} placeholder="https://…/v1" />
        </Form.Item>
        <SecretField name="apiKey" label={t('aiApiKey')} set={view.apiKeySet} hint={view.apiKeyHint} view={view} onReset={reset}
          onClear={() => save({ apiKey: '' }, t('secretCleared'))} />
        {(['model', 'piModel'] as const).map(name => (
          <Form.Item key={name} label={<Space>{t(name === 'model' ? 'aiModel' : 'aiPiModel')}<Source field={name} view={view} onReset={reset} /></Space>}
            extra={t(name === 'model' ? 'aiModelHint' : 'aiPiModelHint')}>
            <Space.Compact style={{ width: '100%', maxWidth: 520 }}>
              <Form.Item name={name} noStyle><Input placeholder={t('aiModelEmpty')} /></Form.Item>
              <Button loading={busy} onClick={() => test({ ...patch(), target: name })}>{t('testConnection')}</Button>
            </Space.Compact>
          </Form.Item>
        ))}
        <Button type="primary" htmlType="submit" loading={busy}>{t('save')}</Button>
      </Form>
    </Card>
  )
}

export function IntelLookupSettings() {
  const { t } = useI18n()
  const [form] = Form.useForm()
  const { query, busy, save, reset, test } = useAISettings()
  if (query.isError) return <LoadError error={query.error} onRetry={() => query.refetch()} />
  if (!query.data) return <Card><Skeleton active /></Card>
  const view = query.data
  const patch = () => diff(form.getFieldsValue(), view, ['ptr', 'vtAlertMin'], ['vtKey', 'abuseCHKey'])

  return (
    <Card title={t('settingsIntelLookup')}>
      <Typography.Paragraph type="secondary">{t('settingsIntelLookupHint')}</Typography.Paragraph>
      {!view.canSaveSecrets && <Alert type="info" showIcon style={{ marginBottom: 16 }} title={t('noVaultHint')} />}
      <Form form={form} layout="vertical" style={{ maxWidth: 640 }} disabled={busy} initialValues={view} key={JSON.stringify(view)}
        onFinish={async () => { if (await save(patch())) form.setFieldsValue({ vtKey: '', abuseCHKey: '' }) }}>
        <Form.Item name="ptr" valuePropName="checked" label={<Space>{t('ptrLabel')}<Source field="ptr" view={view} onReset={reset} /></Space>} extra={t('ptrHint')}>
          <Switch />
        </Form.Item>
        <SecretField name="vtKey" label={t('vtKeyLabel')} set={view.vtKeySet} hint={view.vtKeyHint} view={view} onReset={reset}
          onClear={() => save({ vtKey: '' }, t('secretCleared'))} extra={t('vtKeyHint')} />
        <SecretField name="abuseCHKey" label={t('abuseCHKeyLabel')} set={view.abuseCHKeySet} hint={view.abuseCHKeyHint} view={view} onReset={reset}
          onClear={() => save({ abuseCHKey: '' }, t('secretCleared'))} extra={t('abuseCHKeyHint')} />
        <Form.Item name="vtAlertMin" label={<Space>{t('vtAlertMinLabel')}<Source field="vtAlertMin" view={view} onReset={reset} /></Space>} extra={t('vtAlertMinHint')}>
          <InputNumber min={0} max={100} style={{ width: 120 }} />
        </Form.Item>
        <Space>
          <Button type="primary" htmlType="submit" loading={busy}>{t('save')}</Button>
          <Button loading={busy} onClick={() => test({ ...patch(), target: 'vt' })}>{t('testVt')}</Button>
        </Space>
      </Form>
    </Card>
  )
}
