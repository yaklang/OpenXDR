import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, DatePicker, Form, Input, Modal, Select, Skeleton } from 'antd'
import type { Dayjs } from 'dayjs'
import { useState } from 'react'
import { HttpError, createIntent, fetchAssets, fetchFacts } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { INTENT_CATEGORIES, bareAddr, factLive } from './control'
import { errText } from './format'

interface Draft {
  assetIds: string[]
  keyFingerprint: string
  channel: string
  sourceAddr?: string
  category: string
  durationMinutes: number
  note?: string
  startedAt?: Dayjs | null
}

const DURATIONS = [30, 60, 120, 180, 240]
const shortFp = (v: string) => (v.length > 24 ? `${v.slice(0, 15)}…${v.slice(-6)}` : v)

// 登记运维意图：钥匙与来源只能从事实库里登记在自己名下的选，不手打指纹；通道是网段时在网段内填具体地址
export function IntentModal({ open, assetIds, onClose }: { open: boolean; assetIds?: string[]; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { me } = useSession()
  const [form] = Form.useForm<Draft>()
  const [busy, setBusy] = useState(false)
  const facts = useQuery({ queryKey: ['facts'], queryFn: () => fetchFacts(), enabled: open })
  const assets = useQuery({ queryKey: ['assets'], queryFn: () => fetchAssets(), enabled: open })
  const channel = Form.useWatch('channel', form)

  const holder = `user:${me.username}`
  const mine = (facts.data ?? []).filter(f => f.holder === holder && factLive(f))
  const keys = mine.filter(f => f.kind === 'key')
  const channels = mine.filter(f => f.kind === 'channel')
  const isNet = (c?: string) => !!c && bareAddr(c).includes('/')

  const submit = async (v: Draft) => {
    setBusy(true)
    try {
      const r = await createIntent({
        keyFingerprint: v.keyFingerprint,
        sourceAddr: isNet(v.channel) ? (v.sourceAddr ?? '').trim() : bareAddr(v.channel),
        assetIds: v.assetIds,
        category: v.category,
        note: (v.note ?? '').trim(),
        durationMinutes: v.durationMinutes,
        ...(v.startedAt ? { startedAt: v.startedAt.toISOString() } : {}),
      })
      message.success(t('intentRegistered', { ref: r.ref }))
      client.invalidateQueries({ queryKey: ['intents'] })
      onClose()
    } catch (e) {
      // 登记被拒的原因（不是你名下的通道、主机无权限、时长超限）原样给人看
      message.error(e instanceof HttpError && (e.status === 400 || e.status === 403) ? e.message : errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  const ready = !facts.isPending && keys.length > 0 && channels.length > 0

  return (
    <Modal open={open} title={t('intentRegister')} onCancel={() => { if (!busy) onClose() }} onOk={() => form.submit()}
      okButtonProps={{ disabled: !ready }} confirmLoading={busy} width={620} destroyOnHidden>
      {facts.isPending ? <Skeleton active /> : <>
        {facts.isError && <Alert type="error" showIcon style={{ marginBottom: 16 }} title={errText(facts.error, t)} />}
        {!facts.isError && !ready && <Alert type="warning" showIcon style={{ marginBottom: 16 }} title={t('intentNoOwned', { holder })} />}
        <Form<Draft> form={form} layout="vertical" disabled={busy} onFinish={submit}
          initialValues={{
            assetIds: assetIds ?? [],
            keyFingerprint: keys.length === 1 ? keys[0].subject : undefined,
            channel: channels.length === 1 ? channels[0].subject : undefined,
            category: 'maintenance',
            durationMinutes: 60,
          }}>
          <Form.Item name="assetIds" label={t('intentHosts')} rules={[{ required: true, type: 'array', min: 1, max: 20, message: t('intentHostsRule') }]}>
            <Select mode="multiple" showSearch optionFilterProp="label" loading={assets.isPending}
              options={(assets.data ?? []).map(a => ({ value: a.id, label: a.hostname }))} />
          </Form.Item>
          <Form.Item name="keyFingerprint" label={t('intentKey')} extra={t('intentKeyHint')} rules={[{ required: true }]}>
            <Select options={keys.map(f => ({ value: f.subject, label: <span><span className="mono">{shortFp(f.subject)}</span> · {f.content}</span> }))} />
          </Form.Item>
          <Form.Item name="channel" label={t('intentChannel')} rules={[{ required: true }]}>
            <Select options={channels.map(f => ({ value: f.subject, label: <span><span className="mono">{bareAddr(f.subject)}</span> · {f.content}</span> }))} />
          </Form.Item>
          {isNet(channel) && (
            <Form.Item name="sourceAddr" label={t('intentSourceAddr')} extra={t('intentSourceAddrHint', { cidr: channel })} rules={[{ required: true, whitespace: true }]}>
              <Input className="mono" placeholder={channel.split('/')[0]} />
            </Form.Item>
          )}
          <Form.Item name="category" label={t('intentCategory')} extra={t('intentCategoryHint')} rules={[{ required: true }]}>
            <Select options={INTENT_CATEGORIES.map(c => ({ value: c, label: t(`intentCat_${c}` as MsgKey) }))} />
          </Form.Item>
          <Form.Item name="durationMinutes" label={t('intentDuration')} rules={[{ required: true }]}>
            <Select options={DURATIONS.map(n => ({ value: n, label: n < 60 ? t('intentMinutes', { n }) : t('intentHours', { n: n / 60 }) }))} />
          </Form.Item>
          <Form.Item name="note" label={t('intentNote')} extra={t('intentNoteHint')} rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item name="startedAt" label={t('intentStartedAt')} extra={t('intentStartedAtHint')}>
            <DatePicker showTime={{ format: 'HH:mm' }} format="MM-DD HH:mm" placeholder={t('intentStartedAtNow')} />
          </Form.Item>
        </Form>
      </>}
    </Modal>
  )
}
