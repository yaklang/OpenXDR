import { ImportOutlined, SyncOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Empty, Flex, Form, Input, InputNumber, List, Modal, Popconfirm, Select, Space, Spin, Switch, Table, Tag, Typography } from 'antd'
import { useMemo, useRef, useState } from 'react'
import { deleteIntel, fetchIntel, fetchIntelFeeds, importIntel, saveIntelFeeds, syncIntelFeeds, type IntelRow } from '../api'
import { useSession } from '../app/session'
import { LoadError } from '../components/LoadError'
import { Page, STICKY_HEADER, TableCard } from '../components/Page'
import { SeverityTag, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

// 情报订阅：开关即时生效（开的马上拉、关的马上清），命中过的订阅情报直接列出来
function FeedsCard() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin } = useSession()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['intel-feeds'], queryFn: fetchIntelFeeds })
  const pending = useRef(false)
  const [busy, setBusy] = useState<string>()
  // 接口保存整份订阅配置，串行提交，避免后一次用旧快照覆盖前一次。
  const update = async (id?: string, on?: boolean) => {
    if (pending.current || !data) return
    pending.current = true
    setBusy(id ?? 'sync')
    try {
      const result = id === undefined
        ? await syncIntelFeeds()
        : await saveIntelFeeds(data.feeds.filter(f => f.id === id ? on : f.enabled).map(f => f.id))
      client.setQueryData(['intel-feeds'], result)
      await client.invalidateQueries({ queryKey: ['intel'] })
    } catch (e) {
      message.error(errText(e, t))
      // 配置可能已保存、同步才失败；重新读取实际开关与情报，避免旧快照覆盖下一次操作。
      await Promise.all([
        client.invalidateQueries({ queryKey: ['intel-feeds'] }),
        client.invalidateQueries({ queryKey: ['intel'] }),
      ])
    } finally {
      pending.current = false
      setBusy(undefined)
    }
  }

  return (
    <Card
      title={t('intelFeeds')}
      extra={isAdmin && <Button icon={<SyncOutlined />} loading={busy === 'sync'} disabled={!!busy || isPending || isError} onClick={() => update()}>{t('intelFeedSync')}</Button>}
    >
      {isError ? <LoadError error={error} onRetry={() => refetch()} /> : isPending ? <Spin /> : <>
      <Typography.Paragraph type="secondary">{t('intelFeedsHint', { n: data?.intervalHours ?? 6 })}</Typography.Paragraph>
      <List
        className="intel-feed-list"
        size="small"
        split={false}
        dataSource={data?.feeds ?? []}
        renderItem={f => (
          <List.Item
            actions={[<Switch key="on" checked={f.enabled} aria-label={f.name} disabled={!isAdmin || !!busy} loading={busy === f.id}
              onChange={on => update(f.id, on)} />]}
          >
            <List.Item.Meta
              title={<Space wrap><span>{f.name}</span><SeverityTag value={f.severity} /></Space>}
              description={
                <Space wrap size={12}>
                  <span>{t('intelFeedCount', { n: f.count })}</span>
                  <span>{t('intelFeedHits', { n: f.hits })}</span>
                  <span>{f.syncedAt ? t('intelFeedSynced', { time: fmtTime(f.syncedAt) }) : t('intelFeedNever')}</span>
                  {f.error && f.attemptedAt && <span>{t('intelFeedAttempted', { time: fmtTime(f.attemptedAt) })}</span>}
                  {f.error && <Typography.Text type="danger">{t('intelFeedError', { err: f.error })}</Typography.Text>}
                </Space>
              }
            />
          </List.Item>
        )}
      />
      <Typography.Title level={5} style={{ marginTop: 20, marginBottom: 10 }}>{t('intelFeedHitList')}</Typography.Title>
      <Table<IntelRow>
        scroll={{ x: 750 }}
        size="small"
        rowKey="id"
        dataSource={data?.hits ?? []}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('intelFeedNoHits')} /> }}
        columns={[
          { title: t('thKind'), dataIndex: 'kind', width: 95, sorter: (a, b) => a.kind.localeCompare(b.kind), render: v => <Tag>{v}</Tag> },
          { title: t('thValue'), dataIndex: 'value', sorter: (a, b) => a.value.localeCompare(b.value), render: (v, r) => <Typography.Text className="mono" copyable title={r.note ?? ''}>{v}</Typography.Text> },
          { title: t('thSource'), dataIndex: 'source', width: 160, sorter: (a, b) => (a.source ?? '').localeCompare(b.source ?? '') },
          { title: t('thHits'), dataIndex: 'matchedCount', width: 95, align: 'right', sorter: (a, b) => a.matchedCount - b.matchedCount },
          { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, sorter: (a, b) => (a.lastMatchedAt ?? '').localeCompare(b.lastMatchedAt ?? ''), render: fmtTime },
        ]}
      />
      </>}
    </Card>
  )
}

// 威胁情报：命中数让每条 IOC 的价值可见，长期零命中的陈年情报该清理
export function IntelPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite } = useSession()
  const [importing, setImporting] = useState(false)
  const [busy, setBusy] = useState(false)
  const [q, setQ] = useState('')
  const [kindFilter, setKindFilter] = useState('')
  const [sevFilter, setSevFilter] = useState(0)
  const submitting = useRef(false)
  const [form] = Form.useForm()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['intel'], queryFn: fetchIntel })

  const kinds = useMemo(() => {
    const set = new Set<string>()
    for (const r of data ?? []) if (r.kind) set.add(r.kind)
    return Array.from(set).sort()
  }, [data])

  const activeQ = q.trim().toLowerCase()
  const hasFilters = Boolean(activeQ || kindFilter || sevFilter)
  const rows = useMemo(() => (data ?? []).filter(r =>
    (!kindFilter || r.kind === kindFilter) &&
    (!sevFilter || r.severity === sevFilter) &&
    (!activeQ || r.value.toLowerCase().includes(activeQ) || (r.source ?? '').toLowerCase().includes(activeQ) || (r.note ?? '').toLowerCase().includes(activeQ))
  ), [data, kindFilter, sevFilter, activeQ])

  const refresh = () => client.invalidateQueries({ queryKey: ['intel'] })
  const doImport = async (v: { text: string; source?: string; expiresInDays?: number }) => {
    if (submitting.current) return
    submitting.current = true
    setBusy(true)
    try {
      const r = await importIntel({ text: v.text, source: v.source || undefined, expiresInDays: v.expiresInDays ?? 0 })
      message.success(t('intelImported', { n: r.imported, skipped: r.skipped }))
      setImporting(false)
      form.resetFields()
      refresh()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      submitting.current = false
      setBusy(false)
    }
  }
  const revoke = (id: string) => deleteIntel(id).then(refresh).catch(e => message.error(errText(e, t)))

  return (
    <Page
      title={t('navIntel')}
      subtitle={t('intelSubtitle', { n: data?.length ?? 0 })}
      extra={canWrite && <Button type="primary" icon={<ImportOutlined />} onClick={() => setImporting(true)}>{t('intelImport')}</Button>}
    >
      <Flex vertical gap={20}>
      <FeedsCard />
      <TableCard
        title={t('intelManual')}
        extra={
          <Space wrap>
            {hasFilters && data && <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total: data.length })}</Typography.Text>}
            <Input.Search allowClear style={{ width: 240 }} placeholder={t('searchIntel')} value={q} onChange={e => setQ(e.target.value)} />
            <Select aria-label={t('thKind')} style={{ width: 130 }} value={kindFilter} onChange={setKindFilter}
              options={[{ value: '', label: t('allKinds') }, ...kinds.map(k => ({ value: k, label: k }))]} />
            <Select aria-label={t('thSeverity')} style={{ width: 130 }} value={sevFilter} onChange={setSevFilter}
              options={[{ value: 0, label: t('allSeverities') }, ...[5, 4, 3, 2, 1].map(n => ({ value: n, label: t(`sev${n}` as 'sev1') }))]} />
            {hasFilters && <Button type="link" onClick={() => { setQ(''); setKindFilter(''); setSevFilter(0) }}>{t('resetFilters')}</Button>}
          </Space>
        }
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<IntelRow>
          sticky={STICKY_HEADER}
          scroll={{ x: 1100 }}
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ defaultPageSize: 20, showSizeChanger: true, hideOnSinglePage: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t(hasFilters ? 'noMatch' : 'noIntel')} /> }}
          columns={[
            { title: t('thKind'), dataIndex: 'kind', width: 95, sorter: (a, b) => a.kind.localeCompare(b.kind), render: v => <Tag>{v}</Tag> },
            { title: t('thValue'), dataIndex: 'value', sorter: (a, b) => a.value.localeCompare(b.value), render: (v, r) => <Typography.Text className="mono" copyable title={r.note ?? ''}>{v}</Typography.Text> },
            { title: t('thSource'), dataIndex: 'source', width: 140, sorter: (a, b) => (a.source ?? '').localeCompare(b.source ?? '') },
            { title: t('thSeverity'), dataIndex: 'severity', width: 95, sorter: (a, b) => a.severity - b.severity, render: v => <SeverityTag value={v} /> },
            { title: t('thHits'), dataIndex: 'matchedCount', width: 95, align: 'right', sorter: (a, b) => a.matchedCount - b.matchedCount },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, sorter: (a, b) => (a.lastMatchedAt ?? '').localeCompare(b.lastMatchedAt ?? ''), render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 170, sorter: (a, b) => (a.expiresAt ?? '9999').localeCompare(b.expiresAt ?? '9999'), render: v => (v ? fmtTime(v) : t('longTerm')) },
            ...(canWrite
              ? [{
                  title: t('actions'), width: 90,
                  render: (_: unknown, r: IntelRow) => (
                    <Popconfirm title={t('confirmRevoke')} onConfirm={() => revoke(r.id)}>
                      <Button type="link" danger size="small">{t('revoke')}</Button>
                    </Popconfirm>
                  ),
                }]
              : []),
          ]}
        />}
      </TableCard>
      </Flex>
      <Modal open={importing} title={t('intelImport')} onCancel={() => { if (!busy) setImporting(false) }} closable={!busy} maskClosable={!busy} keyboard={!busy} cancelButtonProps={{ disabled: busy }} onOk={() => form.submit()} confirmLoading={busy} width={640} destroyOnHidden>
        <Form disabled={busy} form={form} layout="vertical" onFinish={doImport} initialValues={{ expiresInDays: 0 }}>
          <Form.Item name="text" label={t('intelIocs')} extra={t('intelImportHint')} rules={[{ required: true, whitespace: true }]}>
            <Input.TextArea rows={8} className="mono" />
          </Form.Item>
          <Form.Item name="source" label={t('intelSource')}>
            <Input />
          </Form.Item>
          <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('validityZero')}>
            <InputNumber min={0} precision={0} style={{ width: 160 }} />
          </Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
