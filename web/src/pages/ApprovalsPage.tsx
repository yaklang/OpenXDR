import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Col, Empty, Input, Popconfirm, Result, Row, Space, Spin, Table, Tabs, Tag, Typography } from 'antd'
import { useRef, useState } from 'react'
import { Link } from 'react-router'
import { createPolicy, deletePolicy, fetchApprovals, fetchPolicies, type Approval, type CommandPolicy } from '../api'
import { useSession } from '../app/session'
import { HostLink } from '../components/HostLink'
import { ApprovalActions } from '../components/ApprovalActions'
import { LoadError } from '../components/LoadError'
import { Page, STICKY_HEADER } from '../components/Page'
import { EmptyHint } from '../components/Ago'
import { fmtTime, errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const STATUS: Record<Approval['status'], { key: MsgKey; color: string }> = {
  pending: { key: 'apPending', color: 'processing' },
  approved: { key: 'apApproved', color: 'success' },
  rejected: { key: 'apRejected', color: 'error' },
  expired: { key: 'apExpired', color: 'default' },
  cancelled: { key: 'apCancelled', color: 'default' },
  consumed: { key: 'apConsumed', color: 'success' },
}

// 名单：AI 与人工都是黑名单，命中的命令暂停等组管理员批准，其余直接执行
function PolicyCard({ groupId, origin, rows }: { groupId: string; origin: 'ai' | 'human'; rows: CommandPolicy[] }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [pattern, setPattern] = useState('')
  const [busy, setBusy] = useState(false)
  const submitting = useRef(false)
  const run = async (fn: () => Promise<unknown>) => {
    if (submitting.current) return
    submitting.current = true
    setBusy(true)
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['policies', groupId] })
    } catch (e) {
      message.error(errText(e, t))
    } finally { submitting.current = false; setBusy(false) }
  }
  const add = () => run(async () => { await createPolicy(groupId, origin, pattern.trim()); setPattern('') })

  return (
    <Card title={t(origin === 'ai' ? 'policyAiTitle' : 'policyHumanTitle')} style={{ height: '100%' }}>
      <Typography.Paragraph type="secondary">{t(origin === 'ai' ? 'policyAiHint' : 'policyHumanHint')}</Typography.Paragraph>
      <Table<CommandPolicy>
        size="small"
        bordered
        showHeader={false}
        rowKey="id"
        pagination={false}
        dataSource={rows.filter(p => p.origin === origin)}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('policyEmpty')} /> }}
        columns={[
          { dataIndex: 'pattern', render: v => <code className="cmd-cell">{v}</code> },
          {
            width: 56,
            render: (_, p) => (
              <Popconfirm title={t('confirmDelete')} onConfirm={() => run(() => deletePolicy(p.id))}>
                <Button type="text" danger size="small" disabled={busy} aria-label={t('del')} icon={<DeleteOutlined />} />
              </Popconfirm>
            ),
          },
        ]}
      />
      <Space.Compact style={{ width: '100%', marginTop: 12 }}>
        <Input disabled={busy} className="mono" placeholder={t('policyPattern')} value={pattern} onChange={e => setPattern(e.target.value)} onPressEnter={() => pattern.trim() && add()} />
        <Button type="primary" icon={<PlusOutlined />} loading={busy} disabled={busy || !pattern.trim()} onClick={add}>{t('add')}</Button>
      </Space.Compact>
    </Card>
  )
}

// 审批中心：命中黑名单的命令在这里批准或拒绝；黑名单也在这里配
export function ApprovalsPage() {
  const { t } = useI18n()
  const { group } = useSession()
  const isGroupAdmin = group?.role === 'admin'
  const approvals = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: !!group && isGroupAdmin,
    refetchInterval: 3_000,
  })
  const policies = useQuery({ queryKey: ['policies', group?.id], queryFn: () => fetchPolicies(group!.id), enabled: !!group && isGroupAdmin })

  if (!group) return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  if (!isGroupAdmin) return <Result status="403" title="403" subTitle={t('groupAdminOnly', { name: group.name })} />

  const all = approvals.data ?? []
  const pending = all.filter(a => a.status === 'pending')
  const columns = (withActions: boolean) => [
    { title: t('thTime'), dataIndex: 'created_at', width: 170, render: fmtTime },
    { title: t('thHostname'), dataIndex: 'asset_id', width: 140, render: (v: string) => <HostLink id={v} /> },
    { title: t('apCmd'), dataIndex: 'cmd', render: (v: string) => <code className="cmd-cell">{v}</code> },
    { title: t('apRequester'), width: 140, render: (_: unknown, a: Approval) => <Space size={4}><Tag>{a.origin === 'ai' ? 'AI' : t('human')}</Tag>{a.requested_by}</Space> },
    { title: t('apSession'), dataIndex: 'session_id', width: 100, render: (v?: string) => (v ? <Link to={`/chat/${v}`}>{t('openSession')}</Link> : '-') },
    ...(withActions
      ? [
          { title: t('apExpiresAt'), dataIndex: 'expires_at', width: 170, render: fmtTime },
          {
            title: t('actions'), width: 150,
            render: (_: unknown, a: Approval) => (
              <ApprovalActions approval={a} onDecided={() => { void approvals.refetch() }} />
            ),
          },
        ]
      : [
          { title: t('thStatus'), dataIndex: 'status', width: 100, render: (v: Approval['status']) => <Tag color={STATUS[v].color}>{t(STATUS[v].key)}</Tag> },
          { title: t('apDecidedBy'), dataIndex: 'decided_by', width: 110, render: (v?: string) => v ?? '-' },
        ]),
  ]

  return (
    <Page title={t('navApprovals')} subtitle={t('approvalsSubtitle', { name: group.name })}>
      <Card styles={{ body: { paddingTop: 8 } }}>
        <Tabs
          items={[
            {
              key: 'pending',
              label: t('apTabQueue', { n: pending.length }),
              children: approvals.isError ? <LoadError error={approvals.error} onRetry={() => approvals.refetch()} /> : <Table<Approval> sticky={STICKY_HEADER} scroll={{ x: 1050 }} rowKey="id" size="small" loading={approvals.isPending} dataSource={pending} pagination={false} columns={columns(true)} locale={{ emptyText: <EmptyHint title={t('apNone')} hint={t('apNoneHint')} /> }} />,
            },
            {
              key: 'history',
              label: t('apTabHistory'),
              children: approvals.isError ? <LoadError error={approvals.error} onRetry={() => approvals.refetch()} /> : <Table<Approval> sticky={STICKY_HEADER} scroll={{ x: 1050 }} rowKey="id" size="small" dataSource={all.filter(a => a.status !== 'pending')} pagination={{ pageSize: 20, hideOnSinglePage: true }} columns={columns(false)} />,
            },
            {
              key: 'policies',
              label: t('apTabPolicies'),
              children: policies.isError ? <LoadError error={policies.error} onRetry={() => policies.refetch()} /> : policies.isPending ? <Spin /> : (
                <Space orientation="vertical" size={20} style={{ width: '100%' }}>
                  <Alert type="info" showIcon title={t('policyRegexHint')} />
                  <Row gutter={[20, 20]}>
                    <Col xs={24} lg={12}><PolicyCard key={`${group.id}:ai`} groupId={group.id} origin="ai" rows={policies.data ?? []} /></Col>
                    <Col xs={24} lg={12}><PolicyCard key={`${group.id}:human`} groupId={group.id} origin="human" rows={policies.data ?? []} /></Col>
                  </Row>
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </Page>
  )
}
