import { DeleteOutlined, EditOutlined, ExperimentOutlined, PlusOutlined, UploadOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Drawer, Input, Popconfirm, Space, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import { useRef, useState } from 'react'
import { checkCustomRule, deleteCustomRule, fetchCustomRules, saveCustomRule, type BacktestResult, type CustomRule } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { EmptyHint } from './Ago'
import { errText, fmtTime, SeverityTag } from './format'
import { LoadError } from './LoadError'
import { TableActions } from './TableActions'

// crypto.randomUUID 只在安全上下文可用，控制台可能走内网 http
function uuid4() {
  const b = crypto.getRandomValues(new Uint8Array(16))
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

const template = (author: string) => `title:
id: ${uuid4()}
status: experimental
description:
author: ${author}
level: medium
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: ''
  condition: selection
tags:
  - attack.execution
`

// 一个文件里可以有多条规则，按 YAML 文档分隔符拆开
const splitDocs = (text: string) => text.split(/^---\s*$/m).map(d => d.trim()).filter(Boolean).map(d => d + '\n')

type Editing = { id: string | null; content: string; enabled: boolean }

// 自定义规则：Sigma 格式，存库后各节点热加载，叠在内置规则之上
export function CustomRules() {
  const { t } = useI18n()
  const { message, modal } = App.useApp()
  const client = useQueryClient()
  const { isAdmin, me } = useSession()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['custom-rules'], queryFn: fetchCustomRules })
  const [editing, setEditing] = useState<Editing | null>(null)
  const [check, setCheck] = useState<{ result?: BacktestResult; error?: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const refresh = () => Promise.all([client.invalidateQueries({ queryKey: ['custom-rules'] }), client.invalidateQueries({ queryKey: ['rules'] })])
  const open = (e: Editing) => { setEditing(e); setCheck(null) }

  const runCheck = async () => {
    if (!editing) return
    setBusy(true)
    try {
      setCheck({ result: await checkCustomRule(editing.content) })
    } catch (e) {
      setCheck({ error: errText(e, t) })
    } finally {
      setBusy(false)
    }
  }

  const save = async () => {
    if (!editing) return
    setBusy(true)
    try {
      await saveCustomRule(editing.id, editing.content, editing.enabled)
      setEditing(null)
      await refresh()
      message.success(t('customRuleSaved'))
    } catch (e) {
      setCheck({ error: errText(e, t) })
    } finally {
      setBusy(false)
    }
  }

  const toggle = async (r: CustomRule, enabled: boolean) => {
    try {
      await saveCustomRule(r.id, r.content, enabled)
      await refresh()
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const remove = async (id: string) => {
    try {
      await deleteCustomRule(id)
      await refresh()
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  // 导入逐条走同一个新建接口，校验口径一致；失败的列出原因，成功的照常生效
  const importFiles = async (files: FileList | null) => {
    if (!files?.length) return
    const failures: string[] = []
    let ok = 0
    for (const file of Array.from(files)) {
      for (const [i, doc] of splitDocs(await file.text()).entries()) {
        try {
          await saveCustomRule(null, doc, true)
          ok++
        } catch (e) {
          failures.push(`${file.name} #${i + 1}: ${errText(e, t)}`)
        }
      }
    }
    if (fileInput.current) fileInput.current.value = ''
    await refresh()
    if (failures.length === 0) message.success(t('customRuleImported', { n: ok }))
    else modal.warning({
      title: t('customRuleImportPartial', { ok, failed: failures.length }),
      width: 640,
      content: <div style={{ maxHeight: 360, overflow: 'auto' }}>{failures.map(f => <Typography.Paragraph key={f} style={{ fontSize: 12.5, marginBottom: 6 }}>{f}</Typography.Paragraph>)}</div>,
    })
  }

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <Alert type="info" showIcon title={t('customRuleIntro')} />
      {isAdmin && (
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => open({ id: null, content: template(me.username), enabled: true })}>{t('customRuleNew')}</Button>
          <Button icon={<UploadOutlined />} onClick={() => fileInput.current?.click()}>{t('customRuleImport')}</Button>
          <input ref={fileInput} type="file" accept=".yml,.yaml" multiple hidden onChange={e => void importFiles(e.target.files)} />
        </Space>
      )}
      {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<CustomRule>
        size="small"
        rowKey="id"
        loading={isPending}
        dataSource={data}
        pagination={{ defaultPageSize: 30, hideOnSinglePage: true }}
        scroll={{ x: 900 }}
        locale={{ emptyText: <EmptyHint title={t('customRuleEmpty')} hint={t('customRuleEmptyHint')} /> }}
        columns={[
          {
            title: t('thRule'), dataIndex: 'title',
            render: (v, r) => <>
              <Typography.Text>{v || r.id}</Typography.Text>
              {r.error && <Tooltip title={r.error}><Tag color="error" style={{ marginLeft: 8 }}>{t('customRuleBroken')}</Tag></Tooltip>}
              <Typography.Text type="secondary" className="mono" style={{ display: 'block', fontSize: 12 }}>{r.id}</Typography.Text>
            </>,
          },
          { title: t('thSeverity'), dataIndex: 'severity', width: 95, render: v => (v ? <SeverityTag value={v} /> : '-') },
          {
            title: t('customRuleEnabled'), dataIndex: 'enabled', width: 90,
            render: (v: boolean, r) => <Switch size="small" checked={v} disabled={!isAdmin} onChange={on => void toggle(r, on)} />,
          },
          { title: t('customRuleUpdated'), dataIndex: 'updatedAt', width: 230, render: (v, r) => `${fmtTime(v)} · ${r.updatedBy}` },
          {
            title: '', width: 170, align: 'right',
            render: (_, r) => (
              <TableActions>
                <Button size="small" type="link" icon={<EditOutlined />} onClick={() => open({ id: r.id, content: r.content, enabled: r.enabled })}>{t(isAdmin ? 'customRuleEditBtn' : 'customRuleView')}</Button>
                {isAdmin && (
                  <Popconfirm title={t('customRuleDeleteConfirm')} onConfirm={() => remove(r.id)}>
                    <Button size="small" type="link" danger icon={<DeleteOutlined />} aria-label={t('del')} />
                  </Popconfirm>
                )}
              </TableActions>
            ),
          },
        ]}
      />}
      <Drawer
        open={Boolean(editing)}
        onClose={() => setEditing(null)}
        size="large"
        title={t(editing?.id ? (isAdmin ? 'customRuleEdit' : 'customRuleView') : 'customRuleNew')}
        extra={isAdmin && editing && (
          <Space>
            <Switch checked={editing.enabled} checkedChildren={t('customRuleEnabled')} unCheckedChildren={t('customRuleDisabled')} onChange={on => setEditing({ ...editing, enabled: on })} />
            <Button icon={<ExperimentOutlined />} loading={busy} onClick={runCheck}>{t('customRuleCheck')}</Button>
            <Button type="primary" loading={busy} onClick={save}>{t('save')}</Button>
          </Space>
        )}
      >
        {editing && (
          <Space orientation="vertical" size={12} style={{ width: '100%' }}>
            <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('customRuleEditorHint')}</Typography.Text>
            <Input.TextArea
              className="mono"
              aria-label={t('customRuleContent')}
              value={editing.content}
              readOnly={!isAdmin}
              spellCheck={false}
              autoSize={{ minRows: 18, maxRows: 40 }}
              style={{ fontSize: 12.5 }}
              onChange={e => { setEditing({ ...editing, content: e.target.value }); setCheck(null) }}
            />
            {check?.error && <Alert type="error" showIcon title={check.error} />}
            {check?.result && (
              <Alert type={check.result.matchedCount > 0 ? 'warning' : 'success'} showIcon
                title={t('customRuleCheckResult', { matched: check.result.matchedCount, scanned: check.result.scannedEvents, hosts: check.result.hosts.length })}
                description={check.result.hosts.length > 0 ? check.result.hosts.map(h => `${h.hostname} ×${h.count}`).join('，') : undefined}
              />
            )}
          </Space>
        )}
      </Drawer>
    </Space>
  )
}
