import { TableActions } from '../components/TableActions'
import { DeleteOutlined, EditOutlined, PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { createMemory, deleteMemory, fetchAssets, fetchMemories, updateMemory, type MemoryRow } from '../api'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { HostLink } from '../components/HostLink'
import { LoadError } from '../components/LoadError'
import { FilterCard, Page, STICKY_HEADER } from '../components/Page'
import { useCanActIn, useSession } from '../app/session'
import { errText } from '../components/format'
import { useI18n } from '../i18n'

// AI 记忆：AI 在对话与巡检里记下的环境知识，之后的会话与研判都会带上。人在这里补充、改正、删除；人改过的即算人工记忆
export function MemoriesPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { group } = useSession()
  const canAct = useCanActIn(group?.id)
  const [q, setQ] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [editing, setEditing] = useState<MemoryRow | 'new' | null>(null)
  const [form] = Form.useForm<{ content: string; assetId?: string }>()
  const { data, isPending, isError, error, refetch, dataUpdatedAt, isFetching } = useQuery({ queryKey: ['memories'], queryFn: fetchMemories })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })
  const groupRows = (data ?? []).filter(m => m.groupId === group?.id)
  const hosts = (assets.data ?? []).filter(a => a.groupId === group?.id)
  const hostNameOf = (assetId?: string | null) => hosts.find(h => h.id === assetId)?.hostname ?? ''

  const activeQ = q.trim().toLowerCase()
  const hasFilters = Boolean(activeQ || sourceFilter)
  const rows = groupRows.filter(m =>
    (!sourceFilter || m.source === sourceFilter) &&
    (!activeQ || m.content.toLowerCase().includes(activeQ) || hostNameOf(m.assetId).toLowerCase().includes(activeQ) || (m.author ?? '').toLowerCase().includes(activeQ))
  )

  const open = (row: MemoryRow | 'new') => {
    form.setFieldsValue(row === 'new' ? { content: '', assetId: undefined } : { content: row.content, assetId: row.assetId ?? undefined })
    setEditing(row)
  }
  const save = async () => {
    const v = await form.validateFields()
    try {
      if (editing === 'new') await createMemory({ groupId: group!.id, assetId: v.assetId, content: v.content })
      else if (editing) await updateMemory(editing.id, v.content)
    } catch (e) {
      message.error(errText(e, t))
      return
    }
    setEditing(null)
    client.invalidateQueries({ queryKey: ['memories'] })
  }
  const remove = async (row: MemoryRow) => {
    try {
      await deleteMemory(row.id)
    } catch (e) {
      message.error(errText(e, t))
      return
    }
    client.invalidateQueries({ queryKey: ['memories'] })
  }

  return (
    <Page title={t('navMemories')} subtitle={t('memoriesSubtitle')}
      extra={canAct && group && <Button type="primary" icon={<PlusOutlined />} onClick={() => open('new')}>{t('memoryAdd')}</Button>}>
      <FilterCard
        onReset={hasFilters ? () => { setQ(''); setSourceFilter('') } : undefined}
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 250 }} placeholder={t('searchMemories')} value={q} onChange={e => setQ(e.target.value)} />
            <Select aria-label={t('memorySource')} style={{ width: 140 }} value={sourceFilter} onChange={setSourceFilter}
              options={[
                { value: '', label: t('allSources') },
                { value: 'human', label: t('memoryHuman') },
                { value: 'ai', label: 'AI' },
              ]}
            />
            <Typography.Text type="secondary">{t('memoriesHint', { n: groupRows.length })}</Typography.Text>
          </Space>
        }
        extra={<Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />}
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<MemoryRow>
          sticky={STICKY_HEADER}
          size="small" rowKey="id" loading={isPending} dataSource={rows} pagination={{ defaultPageSize: 50, showSizeChanger: true, hideOnSinglePage: true }}
          locale={{ emptyText: <EmptyHint title={t(hasFilters ? 'noMatch' : 'memoriesEmpty')} hint={hasFilters ? undefined : t('memoriesEmptyHint')} /> }}
          columns={[
            { title: t('memoryContent'), dataIndex: 'content', sorter: (a, b) => a.content.localeCompare(b.content), render: v => <Typography.Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>{v}</Typography.Paragraph> },
            { title: t('thHostname'), dataIndex: 'assetId', width: 140, sorter: (a, b) => hostNameOf(a.assetId).localeCompare(hostNameOf(b.assetId)), render: v => (v ? <HostLink id={v} /> : <Typography.Text type="secondary">{t('memoryWholeGroup')}</Typography.Text>) },
            {
              title: t('memorySource'), dataIndex: 'source', width: 150,
              sorter: (a, b) => a.source.localeCompare(b.source),
              render: (v: MemoryRow['source'], r) => v === 'ai'
                ? <Space size={4}><Tag color="purple" variant="filled">AI</Tag>{r.sessionId && <Link to={`/chat/${r.sessionId}`}>{t('openSession')}</Link>}</Space>
                : <Space size={4}><Tag color="cyan" variant="filled">{t('memoryHuman')}</Tag><Typography.Text type="secondary">{r.author}</Typography.Text></Space>,
            },
            { title: t('memoryUpdated'), dataIndex: 'updatedAt', width: 120, sorter: (a, b) => a.updatedAt.localeCompare(b.updatedAt), render: v => <Ago iso={v} /> },
            ...(canAct ? [{
              key: 'actions', width: 90,
              render: (_: unknown, r: MemoryRow) => (
                <TableActions>
                  <Tooltip title={t('memoryEditBtn')}><Button type="text" size="small" icon={<EditOutlined />} aria-label={t('memoryEditBtn')} onClick={() => open(r)} /></Tooltip>
                  <Popconfirm title={t('confirmDelete')} onConfirm={() => remove(r)}>
                    <Button type="text" size="small" danger icon={<DeleteOutlined />} aria-label={t('del')} />
                  </Popconfirm>
                </TableActions>
              ),
            }] : []),
          ]}
        />}
      </FilterCard>
      <Modal open={!!editing} title={editing === 'new' ? t('memoryAdd') : t('memoryEdit')} onOk={save} onCancel={() => setEditing(null)} destroyOnHidden>
        <Form form={form} layout="vertical">
          <Form.Item name="content" label={t('memoryContent')} extra={t('memoryContentHint')}
            rules={[{ required: true, whitespace: true, message: t('memoryContentHint') }, { max: 500 }]}>
            <Input.TextArea rows={4} maxLength={500} showCount />
          </Form.Item>
          {editing === 'new' && (
            <Form.Item name="assetId" label={t('thHostname')}>
              <Select allowClear placeholder={t('memoryWholeGroup')} options={hosts.map(a => ({ value: a.id, label: a.hostname }))} />
            </Form.Item>
          )}
        </Form>
      </Modal>
    </Page>
  )
}
