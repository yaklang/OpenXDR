import { TableActions } from '../components/TableActions'
import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Drawer, Empty, Form, Input, Modal, Popconfirm, Select, Space, Spin, Table, Tabs, Transfer, Typography } from 'antd'
import { useRef, useState } from 'react'
import {
  assignAsset, createGroup, deleteGroup, fetchAssets, fetchGroups, fetchMembers, fetchUsers, removeMember, setMember, unassignAsset,
  type GroupRow, type MemberRow,
} from '../api'
import { LoadError } from '../components/LoadError'
import { DirectoryStatus } from '../components/DirectoryStatus'
import { FilterCard, Page, STICKY_HEADER } from '../components/Page'
import { ROLE_KEY, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

function GroupDrawer({ group, onClose }: { group: GroupRow; onClose: () => void }) {
  const { t } = useI18n()
  const { message, modal } = App.useApp()
  const client = useQueryClient()
  const pending = useRef(false)
  const [busy, setBusy] = useState(false)
  const [newUser, setNewUser] = useState<string>()
  const [newRole, setNewRole] = useState('analyst')
  const [activeTab, setActiveTab] = useState('members')
  const members = useQuery({ queryKey: ['members', group.id], queryFn: () => fetchMembers(group.id) })
  const usersQuery = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const assetsQuery = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })

  const run = async (fn: () => Promise<unknown>) => {
    if (pending.current) return false
    pending.current = true
    setBusy(true)
    try {
      await fn()
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally {
      await Promise.all([
        client.invalidateQueries({ queryKey: ['members', group.id] }),
        client.invalidateQueries({ queryKey: ['assets'] }),
        client.invalidateQueries({ queryKey: ['groups'] }),
      ])
      pending.current = false
      setBusy(false)
    }
  }
  const users = usersQuery.data ?? []
  const assets = assetsQuery.data ?? []
  const roleOptions = Object.entries(ROLE_KEY).map(([value, key]) => ({ value, label: t(key) }))
  const candidates = users.filter(u => !members.data?.some(m => m.userId === u.id))
  const inGroup = assets.filter(a => a.groupId === group.id).map(a => a.id)

  // 穿梭框：右侧即本组资产。移入归组（会离开原组），移出退回未分组。从别的组拉过来先确认
  const moveAssets = (_: React.Key[], direction: 'left' | 'right', keys: React.Key[]) => {
    const go = () => run(async () => {
      for (const id of keys.map(String)) {
        if (direction === 'right') await assignAsset(group.id, id)
        else await unassignAsset(group.id, id)
      }
    })
    const taken = direction === 'right' ? assets.filter(a => keys.includes(a.id) && a.groupId && a.groupId !== group.id) : []
    if (!taken.length) return void go()
    modal.confirm({ title: t('regroupConfirm', { host: taken.map(a => a.hostname).join('、') }), content: t('regroupLeaveMany'), onOk: go })
  }

  return (
    <Drawer open size={720} title={t('manageGroup', { name: group.name })} onClose={() => { if (!busy) onClose() }} closable={!busy} maskClosable={!busy} keyboard={!busy}>
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'directories', label: t('directoryTitle'), children: activeTab === 'directories' && <DirectoryStatus groupId={group.id} /> },
          {
            key: 'members',
            label: t('groupMembers'),
            children: members.isError ? <LoadError error={members.error} onRetry={() => members.refetch()} /> : usersQuery.isError ? <LoadError error={usersQuery.error} onRetry={() => usersQuery.refetch()} /> : (members.isPending || usersQuery.isPending) ? <Spin /> : (
              <Space orientation="vertical" style={{ width: '100%' }}>
                <Space.Compact style={{ width: '100%' }}>
                  <Select disabled={busy} aria-label={t('pickUser')} style={{ flex: 1, minWidth: 0 }} placeholder={t('pickUser')} value={newUser} onChange={setNewUser} options={candidates.map(u => ({ value: u.id, label: u.username }))} showSearch optionFilterProp="label" />
                  <Select disabled={busy} aria-label={t('groupRole')} style={{ width: 120 }} value={newRole} onChange={setNewRole} options={roleOptions} />
                  <Button type="primary" icon={<PlusOutlined />} disabled={busy || !newUser} loading={busy} onClick={() => run(async () => { await setMember(group.id, newUser!, newRole); setNewUser(undefined) })}>{t('add')}</Button>
                </Space.Compact>
                <Table<MemberRow>
                  scroll={{ x: 440 }}
                  size="small"
                  rowKey="userId"
                  loading={members.isPending}
                  dataSource={members.data ?? []}
                  pagination={false}
                  locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noMembers')} /> }}
                  columns={[
                    { title: t('username'), dataIndex: 'username', sorter: (a, b) => a.username.localeCompare(b.username) },
                    { title: t('groupRole'), dataIndex: 'role', width: 160, sorter: (a, b) => a.role.localeCompare(b.role), render: (v, m) => <Select disabled={busy} aria-label={`${m.username} ${t('groupRole')}`} size="small" style={{ width: 130 }} value={v} options={roleOptions} onChange={r => run(() => setMember(group.id, m.userId, r))} /> },
                    {
                      title: t('actions'), width: 90,
                      render: (_, m) => (
                        <Popconfirm title={t('confirmRemoveMember', { name: m.username })} onConfirm={() => run(() => removeMember(group.id, m.userId))}>
                          <Button type="link" danger size="small" disabled={busy}>{t('remove')}</Button>
                        </Popconfirm>
                      ),
                    },
                  ]}
                />
              </Space>
            ),
          },
          {
            key: 'assets',
            label: t('groupAssets'),
            children: assetsQuery.isError ? <LoadError error={assetsQuery.error} onRetry={() => assetsQuery.refetch()} /> : assetsQuery.isPending ? <Spin /> : (
              <Transfer
                disabled={busy}
                dataSource={assets.map(a => ({ key: a.id, title: a.hostname, description: a.ipAddrs?.join(', ') ?? '' }))}
                targetKeys={inGroup}
                onChange={moveAssets}
                render={item => item.title}
                titles={[t('otherAssets'), t('thisGroup')]}
                showSearch
                filterOption={(input, item) => `${item.title} ${item.description}`.toLowerCase().includes(input.toLowerCase())}
                styles={{ section: { flex: 1, minWidth: 0, height: 420 } }}
              />
            ),
          },
        ]}
      />
    </Drawer>
  )
}

// 资产组：纳管与授权的单位。组内角色决定能否在组里对话、处置、审批
export function GroupsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const pending = useRef(false)
  const [busy, setBusy] = useState(false)
  const [q, setQ] = useState('')
  const [creating, setCreating] = useState(false)
  const [managing, setManaging] = useState<GroupRow | null>(null)
  const [form] = Form.useForm()
  const { data, isPending } = useQuery({ queryKey: ['groups'], queryFn: fetchGroups })

  const activeQ = q.trim().toLowerCase()
  const rows = (data ?? []).filter(g => !activeQ || g.name.toLowerCase().includes(activeQ))

  const run = async (fn: () => Promise<unknown>) => {
    if (pending.current) return false
    pending.current = true
    setBusy(true)
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['groups'] })
      // 删组会把资产退回未分组，资产页的组列要跟着变
      client.invalidateQueries({ queryKey: ['assets'] })
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally { pending.current = false; setBusy(false) }
  }

  return (
    <Page
      title={t('navGroups')}
      subtitle={t('groupsSubtitle')}
      extra={<Button type="primary" icon={<PlusOutlined />} disabled={busy} onClick={() => { form.resetFields(); setCreating(true) }}>{t('newGroup')}</Button>}
    >
      <FilterCard
        onReset={activeQ ? () => setQ('') : undefined}
        extra={activeQ && data ? <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total: data.length })}</Typography.Text> : undefined}
        filters={<Input.Search allowClear style={{ width: 240 }} placeholder={t('searchGroups')} value={q} onChange={e => setQ(e.target.value)} />}
      >
        <Table<GroupRow>
          sticky={STICKY_HEADER}
          scroll={{ x: 650 }}
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={false}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t(activeQ ? 'noMatch' : 'noGroups')} /> }}
          columns={[
            { title: t('groupName'), dataIndex: 'name', sorter: (a, b) => a.name.localeCompare(b.name), render: (v, g) => <Button type="link" disabled={busy} onClick={() => setManaging(g)}>{v}</Button> },
            { title: t('thAssetCount'), dataIndex: 'assetCount', width: 120, align: 'right', sorter: (a, b) => a.assetCount - b.assetCount },
            { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 200, sorter: (a, b) => a.createdAt.localeCompare(b.createdAt), render: fmtTime },
            {
              title: t('actions'), width: 160,
              render: (_, g) => (
                <TableActions>
                  <Button type="link" size="small" disabled={busy} onClick={() => setManaging(g)}>{t('manage')}</Button>
                  <Popconfirm title={t('groupDeleteConfirm', { name: g.name })} onConfirm={() => run(() => deleteGroup(g.id))}>
                    <Button type="link" danger size="small" disabled={busy}>{t('del')}</Button>
                  </Popconfirm>
                </TableActions>
              ),
            },
          ]}
        />
      </FilterCard>
      <Modal open={creating} title={t('newGroup')} onCancel={() => { if (!busy) setCreating(false) }} confirmLoading={busy} closable={!busy} maskClosable={!busy} keyboard={!busy} cancelButtonProps={{ disabled: busy }} onOk={() => form.submit()} destroyOnHidden>
        <Form disabled={busy} form={form} layout="vertical" onFinish={async v => { if (await run(() => createGroup(v.name.trim()))) { setCreating(false); form.resetFields() } }}>
          <Form.Item name="name" label={t('groupName')} rules={[{ required: true, whitespace: true }]}><Input /></Form.Item>
        </Form>
      </Modal>
      {managing && <GroupDrawer key={managing.id} group={managing} onClose={() => setManaging(null)} />}
    </Page>
  )
}
