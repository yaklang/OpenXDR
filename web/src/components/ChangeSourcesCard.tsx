import { GithubOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Empty, Form, Input, Modal, Popconfirm, Space, Switch, Table, Tag, Typography } from 'antd'
import { useRef, useState } from 'react'
import { deleteChangeSource, fetchChangeSources, saveChangeSource, syncChangeSource, type ChangeSourceInput, type ChangeSourceRow } from '../api'
import { useI18n } from '../i18n'
import { Refreshed } from './Ago'
import { LoadError } from './LoadError'
import { TableCard } from './Page'
import { TableActions } from './TableActions'
import { errText, fmtTime } from './format'

export function ChangeSourcesCard() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const [syncingId, setSyncingId] = useState<string | null>(null)
  const [editing, setEditing] = useState<ChangeSourceRow | 'new' | null>(null)
  const [form] = Form.useForm<ChangeSourceInput>()
  const query = useQuery({ queryKey: ['changeSources'], queryFn: fetchChangeSources })

  const run = async (fn: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true
    setBusy(true)
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['changeSources'] })
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      lock.current = false
      setBusy(false)
    }
  }

  const openEdit = (row?: ChangeSourceRow) => {
    form.resetFields()
    form.setFieldsValue(row
      ? { name: row.name, repo: row.repo, branch: row.branch, token: '', clearToken: false, enabled: row.enabled }
      : { name: '', repo: '', branch: '', token: '', clearToken: false, enabled: true })
    setEditing(row ?? 'new')
  }

  const triggerSync = async (row: ChangeSourceRow) => {
    if (lock.current) return
    lock.current = true
    setSyncingId(row.id)
    try {
      const res = await syncChangeSource(row.id)
      message.success(t('changeSourceSyncDone', { n: res.added }))
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      await client.invalidateQueries({ queryKey: ['changeSources'] })
      lock.current = false
      setSyncingId(null)
    }
  }

  const vaultConfigured = query.data?.vaultConfigured ?? true
  const items = query.data?.items ?? []

  return (
    <TableCard>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 8 }}>
        <Space wrap>
          <GithubOutlined style={{ fontSize: 18 }} />
          <Typography.Title level={4} style={{ margin: 0 }}>{t('changeSourcesTitle')}</Typography.Title>
          <Refreshed at={query.dataUpdatedAt} fetching={query.isFetching} onRefresh={() => query.refetch()} />
        </Space>
        <Button icon={<PlusOutlined />} onClick={() => openEdit()}>{t('changeSourceAdd')}</Button>
      </div>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>
        {t('changeSourcesHint')}
      </Typography.Paragraph>
      {!vaultConfigured && (
        <Alert type="warning" showIcon title={t('changeSourcesNoVault')} style={{ marginBottom: 12 }} />
      )}
      {query.isError ? (
        <LoadError error={query.error} onRetry={() => query.refetch()} />
      ) : (
        <Table<ChangeSourceRow>
          size="small"
          rowKey="id"
          loading={query.isPending}
          dataSource={items}
          pagination={false}
          scroll={{ x: 860 }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('changeSourceEmpty')} /> }}
          columns={[
            {
              title: t('changeSourceRepo'),
              render: (_, row) => (
                <Space orientation="vertical" size={0}>
                  <Typography.Text strong className="mono">{row.repo}</Typography.Text>
                  {row.name && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{row.name}</Typography.Text>}
                </Space>
              ),
            },
            {
              title: t('changeSourceBranch'),
              width: 130,
              render: (_, row) => row.branch
                ? <Tag className="mono">{row.branch}</Tag>
                : <Typography.Text type="secondary">{t('changeSourceBranchDefault')}</Typography.Text>,
            },
            {
              title: t('changeSourceToken'),
              width: 150,
              render: (_, row) => row.hasToken
                ? <Tag color="blue">{t('changeSourceTokenConfigured', { hint: row.tokenHint || '' })}</Tag>
                : <Typography.Text type="secondary">{t('changeSourceTokenNone')}</Typography.Text>,
            },
            {
              title: t('integrationEnabled'),
              width: 90,
              render: (_, row) => <Tag color={row.enabled ? 'green' : 'default'}>{t(row.enabled ? 'integrationOn' : 'integrationOff')}</Tag>,
            },
            {
              title: t('changeSourceRecords'),
              dataIndex: 'recordCount',
              width: 110,
            },
            {
              title: t('changeSourceLastSync'),
              width: 220,
              render: (_, row) => (
                <Space orientation="vertical" size={2}>
                  <span>{row.lastSyncedAt ? fmtTime(row.lastSyncedAt) : t('changeSourceNeverSynced')}</span>
                  {row.lastError && <Typography.Text type="danger" style={{ fontSize: 12 }}>{row.lastError}</Typography.Text>}
                </Space>
              ),
            },
            {
              title: t('integrationActions'),
              width: 220,
              render: (_, row) => (
                <TableActions>
                  <Button size="small" icon={<SyncOutlined spin={syncingId === row.id} />} loading={syncingId === row.id} disabled={busy} onClick={() => triggerSync(row)}>
                    {t('changeSourceSyncNow')}
                  </Button>
                  <Button size="small" disabled={busy || syncingId === row.id} onClick={() => openEdit(row)}>
                    {t('integrationEdit')}
                  </Button>
                  <Popconfirm title={t('changeSourceDeleteConfirm')} onConfirm={() => run(async () => { await deleteChangeSource(row.id) })}>
                    <Button size="small" danger disabled={busy || syncingId === row.id}>{t('del')}</Button>
                  </Popconfirm>
                </TableActions>
              ),
            },
          ]}
        />
      )}

      <Modal
        title={editing === 'new' ? t('changeSourceAdd') : t('changeSourceEdit')}
        open={!!editing}
        onCancel={() => setEditing(null)}
        confirmLoading={busy}
        okText={t('save')}
        onOk={() => form.submit()}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={values => run(async () => {
            await saveChangeSource(
              { ...values, provider: 'github' },
              editing && editing !== 'new' ? editing.id : undefined,
            )
            setEditing(null)
          })}
        >
          <Form.Item
            name="repo"
            label={t('changeSourceRepo')}
            extra={t('changeSourceRepoHint')}
            rules={[{ required: true, whitespace: true, max: 200 }]}
          >
            <Input placeholder="example-org/network-config" className="mono" />
          </Form.Item>
          <Form.Item name="name" label={t('integrationName')}>
            <Input maxLength={100} />
          </Form.Item>
          <Form.Item name="branch" label={t('changeSourceBranch')} extra={t('changeSourceBranchHint')}>
            <Input maxLength={128} placeholder="main / master" className="mono" />
          </Form.Item>
          <Form.Item
            name="token"
            label={t('changeSourceToken')}
            extra={editing && editing !== 'new' && editing.hasToken
              ? `${t('changeSourceTokenConfigured', { hint: editing.tokenHint })} · ${t('changeSourceTokenHint')}`
              : t('changeSourceTokenHint')}
          >
            <Input.Password autoComplete="new-password" placeholder="github_pat_..." disabled={!vaultConfigured} />
          </Form.Item>
          {editing && editing !== 'new' && editing.hasToken && (
            <Form.Item name="clearToken" valuePropName="checked">
              <Checkbox>{t('changeSourceClearToken')}</Checkbox>
            </Form.Item>
          )}
          <Form.Item name="enabled" label={t('integrationEnabled')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </TableCard>
  )
}
