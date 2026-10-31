import { Alert, Card, Descriptions, Space, Table, Tag, Typography } from 'antd'
import { useEffect, useState } from 'react'
import type { Asset, CollectorCapability } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { fmtTime } from './format'

const states: Record<string, { label: MsgKey; color?: string }> = {
  active: { label: 'collectorActive', color: 'blue' },
  degraded: { label: 'collectorDegraded', color: 'warning' },
  unavailable: { label: 'collectorUnavailable', color: 'error' },
  disabled: { label: 'collectorDisabled' },
  unknown: { label: 'collectorUnknown' },
}
const names: Record<string, MsgKey> = {
  process: 'collectorProcess', files: 'collectorFiles', network: 'collectorNetwork', dns: 'collectorDNS',
  powershell: 'collectorPowerShell', auth: 'collectorAuth', inventory: 'collectorInventory', 'local-accounts': 'collectorLocalAccounts', persist: 'collectorPersist', kmod: 'collectorKmod',
}
const size = (n: number) => `${(n / 1048576).toFixed(2)} MiB`

export function CollectorHealth({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const [now, setNow] = useState(Date.now)
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 15000); return () => clearInterval(timer) }, [])
  const health = asset.collectorHealth
  if (!health) return <Card title={t('collectorTitle')} size="small"><Typography.Text type="secondary">{t('collectorNoReport')}</Typography.Text></Card>
  const received = Date.parse(health.receivedAt)
  const stale = !Number.isFinite(received) || now - received > 90000 || received > now + 300000
  const rows = Object.entries(health.capabilities ?? {}).map(([name, value]) => ({ name, ...value }))
  return <Card title={t('collectorTitle')} size="small">
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {stale && <Alert type="warning" showIcon title={t('collectorStale')} />}
      {health.writeBlocked && <Alert type="error" showIcon title={t('collectorBlocked')} />}
      <div className="cmd-item" style={{ padding: '14px 18px' }}>
        <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }} items={[
          { key: 'received', label: t('collectorReceived'), children: fmtTime(health.receivedAt) },
          { key: 'receipts', label: t('collectorReceipts'), children: health.receipts ? `${health.receipts.pending} / ${health.receipts.incomplete}` : '—' },
          { key: 'queue', label: t('collectorQueue'), children: `${health.queueBatches} · ${size(health.queueBytes)}` },
          { key: 'limit', label: t('collectorLimit'), children: size(health.queueLimitBytes) },
          { key: 'dropped', label: t('collectorDropped'), children: <Typography.Text type={health.droppedEvents ? 'danger' : undefined}>{health.droppedEvents}</Typography.Text> },
        ]} />
      </div>
      {health.receipts && health.receipts.incomplete > 0 && <Alert type="warning" showIcon title={t('collectorReceiptIncomplete')} />}
      <Table<CollectorCapability & { name: string }> size="small" rowKey="name" pagination={false} dataSource={rows} columns={[
        { title: t('collectorComponent'), dataIndex: 'name', render: (name: string) => names[name] ? t(names[name]) : name },
        { title: t('collectorPath'), dataIndex: 'path', render: (path: string) => path || '—' },
        { title: t('collectorState'), dataIndex: 'state', render: (value: string, row) => { const state = states[value] ?? states.unknown; return <Space size={4} wrap><Tag color={stale ? undefined : state.color}>{t(state.label)}</Tag>{row.reason && <Typography.Text type="secondary">{row.reason}</Typography.Text>}{!!row.rebuilds && <Typography.Text type="warning">{t('collectorRebuilds', { n: row.rebuilds })}</Typography.Text>}{!!row.recoveries && <Tag>{t('collectorRecoveries', { n: row.recoveries })}</Tag>}</Space> } },
      ]} />
      <Typography.Text type="secondary">{t('collectorEvidenceHint')}</Typography.Text>
    </Space>
  </Card>
}

// 同机流量探针的抓包状态：与采集状态同一口径（组件状态 + 接收时刻），另列网卡、后端、丢包与速率
export function SensorHealth({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const [now, setNow] = useState(Date.now)
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 15000); return () => clearInterval(timer) }, [])
  const health = asset.sensorHealth
  if (!asset.sensorSeen && !health) return null
  const title = <Space>{t('sensorTitle')}{asset.sensorVersion && <Typography.Text type="secondary">{asset.sensorVersion}</Typography.Text>}</Space>
  if (!health) return <Card title={title} size="small"><Typography.Text type="secondary">{t('collectorNoReport')}</Typography.Text></Card>
  const received = Date.parse(health.receivedAt)
  const stale = !Number.isFinite(received) || now - received > 90000 || received > now + 300000
  const capture = health.capabilities?.capture
  const state = states[capture?.state ?? 'unknown'] ?? states.unknown
  return <Card title={title} size="small">
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {stale && <Alert type="warning" showIcon title={t('collectorStale')} />}
      <div className="cmd-item" style={{ padding: '14px 18px' }}>
        <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }} items={[
          { key: 'state', label: t('collectorState'), children: <Tag color={stale ? undefined : state.color}>{t(state.label)}</Tag> },
          { key: 'path', label: t('sensorCapture'), children: <Typography.Text className="mono">{capture?.path || `${health.backend}:${health.iface}`}</Typography.Text> },
          { key: 'workers', label: t('sensorWorkers'), children: <Typography.Text type={health.workersAlive < health.workers ? 'danger' : undefined}>{health.workersAlive} / {health.workers}</Typography.Text> },
          { key: 'received', label: t('collectorReceived'), children: fmtTime(health.receivedAt) },
          { key: 'packets', label: t('sensorPacketRate'), children: health.packetRate.toLocaleString() },
          { key: 'flows', label: t('sensorFlowRate'), children: health.flowRate.toLocaleString() },
          { key: 'kernel', label: t('sensorKernelDrops'), children: <Typography.Text type={health.kernelDrops ? 'danger' : undefined}>{health.kernelDrops.toLocaleString()}</Typography.Text> },
          { key: 'queue', label: t('sensorQueueDrops'), children: <Typography.Text type={health.queueDrops ? 'danger' : undefined}>{health.queueDrops.toLocaleString()}</Typography.Text> },
        ]} />
      </div>
      <Typography.Text type="secondary">{t('sensorEvidenceHint')}</Typography.Text>
    </Space>
  </Card>
}
