import { ArrowRightOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Descriptions, Drawer, Empty, Flex, Input, Skeleton, Space, Switch, Tag, Typography, theme } from 'antd'
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { fetchAssetMap, type AssetMap, type MapNode } from '../api'
import { useSession } from '../app/session'
import { AssetGraph, type Selection } from '../components/AssetGraph'
import { Ago } from '../components/Ago'
import { AssetProfileView, CritTag, ZoneTag, useZoneColor } from '../components/AssetProfile'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { PublicDestList } from '../components/PublicDests'
import { fmtTime } from '../components/format'
import { useI18n } from '../i18n'

// 图例：区域颜色 + 节点形态
function Legend() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const color = useZoneColor()
  const dot = (fill: string, dashed?: boolean) => (
    <svg width={14} height={14} aria-hidden><circle cx={7} cy={7} r={5.5} fill={dashed ? 'none' : fill} stroke={fill} strokeWidth={1.5} strokeDasharray={dashed ? '2 2' : undefined} /></svg>
  )
  return (
    <Flex gap={16} wrap style={{ fontSize: 12, color: token.colorTextSecondary }}>
      {(['external', 'dmz', 'cloud', 'internal'] as const).map(k => (
        <Space key={k} size={4}>{dot(color(k))}{t(({ external: 'zoneExternal', dmz: 'zoneDmz', cloud: 'zoneCloud', internal: 'zoneInternal' } as const)[k])}</Space>
      ))}
      <Space size={4}>{dot(token.colorTextTertiary, true)}{t('mapLegendDiscovered')}</Space>
      <Space size={4}>{dot(token.colorTextTertiary)}{t('mapLegendManaged')}</Space>
      <span>{t('mapLegendSize')}</span>
    </Flex>
  )
}

export function AssetMapPage() {
  const { t } = useI18n()
  const { group, isAdmin, canWrite } = useSession()
  const [search, setSearch] = useState('')
  // 未纳管地址多时默认收起，首屏先看清已纳管资产之间的关系；null 表示还没手动切过
  const [discoveredChoice, setShowDiscovered] = useState<boolean | null>(null)
  const [showInternet, setShowInternet] = useState(true)
  // 全部组：全局管理员把所有组画进一张图，跨组的连接连成主机到主机（按组看只是别组的一个地址）
  const [allGroups, setAllGroups] = useState(false)
  const [selected, setSelected] = useState<Selection>(null)
  const scope = isAdmin && allGroups ? 'all' : group?.id
  const query = useQuery({ queryKey: ['assetMap', scope], queryFn: () => fetchAssetMap(scope!), enabled: !!scope, refetchInterval: 60_000 })
  const discoveredCount = query.data?.nodes.filter(n => n.kind === 'discovered' || n.kind === 'managed').length ?? 0
  const showDiscovered = discoveredChoice ?? discoveredCount <= 20

  // 开关只影响画面，不改数据：去掉的节点连同它的边一起隐藏
  const graph = useMemo<AssetMap | undefined>(() => {
    if (!query.data) return undefined
    const keep = (n: MapNode) => (showDiscovered || (n.kind !== 'discovered' && n.kind !== 'managed')) && (showInternet || n.kind !== 'internet')
    const nodes = query.data.nodes.filter(keep)
    const ids = new Set(nodes.map(n => n.id))
    return { nodes, edges: query.data.edges.filter(e => ids.has(e.from) && ids.has(e.to)) }
  }, [query.data, showDiscovered, showInternet])

  const isGroupAdmin = isAdmin || group?.role === 'admin'
  const canEdit = isAdmin || (canWrite && (group?.role === 'admin' || group?.role === 'analyst'))

  return (
    <Page title={t('navAssetMap')} subtitle={t('assetMapSubtitle')}>
      <Card styles={{ body: { padding: 0 } }}>
        <Flex justify="space-between" align="center" gap={12} wrap className="filter-bar">
          <Space wrap className="filter-controls">
            <Input.Search allowClear placeholder={t('mapSearch')} aria-label={t('mapSearch')} style={{ width: 240, maxWidth: '100%' }}
              value={search} onChange={e => setSearch(e.target.value)} />
            <Space size={6}><Switch size="small" checked={showDiscovered} onChange={setShowDiscovered} aria-label={t('mapShowDiscovered')} />{t('mapShowDiscovered')}{discoveredCount > 0 && ` (${discoveredCount})`}</Space>
            <Space size={6}><Switch size="small" checked={showInternet} onChange={setShowInternet} aria-label={t('mapShowInternet')} />{t('mapShowInternet')}</Space>
            {isAdmin && <Space size={6}><Switch size="small" checked={allGroups} onChange={setAllGroups} aria-label={t('mapAllGroups')} />{t('mapAllGroups')}</Space>}
          </Space>
          <Legend />
        </Flex>
        {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} />
          : !graph ? <Skeleton active style={{ padding: 24 }} />
            : graph.nodes.length === 0 ? <Empty style={{ padding: 64 }} description={t('mapEmpty')} />
              : <AssetGraph graph={graph} search={search} selected={selected} onSelect={setSelected} height={Math.max(520, window.innerHeight - 260)} />}
      </Card>

      <Drawer open={!!selected} size={480} mask={false} onClose={() => setSelected(null)}
        title={selected && ('node' in selected ? <NodeTitle node={selected.node} /> : `${selected.from.label} → ${selected.to.label}`)}>
        {selected && 'node' in selected && <NodeDetail node={selected.node} graph={query.data!} canEdit={canEdit} isGroupAdmin={isGroupAdmin} />}
        {selected && 'edge' in selected && (
          <Descriptions column={1} size="small">
            {selected.edge.note && <Descriptions.Item label={t('edgeNote')}>{selected.edge.note}</Descriptions.Item>}
            <Descriptions.Item label={t('edgePorts')}>{selected.edge.ports.map(p => <Tag key={p} className="mono">{p}</Tag>)}</Descriptions.Item>
            <Descriptions.Item label={t('edgeProcesses')}>{selected.edge.processes.length ? selected.edge.processes.join(', ') : '-'}</Descriptions.Item>
            <Descriptions.Item label={t('edgeCount')}>{selected.edge.count}</Descriptions.Item>
            <Descriptions.Item label={t('thLastActive')}>{fmtTime(selected.edge.lastSeen)}</Descriptions.Item>
          </Descriptions>
        )}
        {selected && 'edge' in selected && !!selected.edge.targets?.length && (() => {
          const a = [selected.from, selected.to].find(n => n.kind === 'asset')
          return (
            <>
              <Typography.Text strong style={{ display: 'block', margin: '16px 0 8px' }}>{t('topTargets')}</Typography.Text>
              <PublicDestList items={selected.edge.targets!} host={a && { id: a.id, name: a.label, groupId: a.groupId ?? group?.id }} />
            </>
          )
        })()}
      </Drawer>
    </Page>
  )
}

function NodeTitle({ node }: { node: MapNode }) {
  const { t } = useI18n()
  return (
    <Space wrap>
      <span className={node.kind === 'asset' ? undefined : 'mono'}>{node.kind === 'internet' ? t('mapLegendInternet') : node.label}</span>
      {node.kind !== 'internet' && <ZoneTag zone={node.zone} />}
      {node.kind === 'asset' && <CritTag value={node.criticality} />}
    </Space>
  )
}

function NodeDetail({ node, graph, canEdit, isGroupAdmin }: { node: MapNode; graph: AssetMap; canEdit: boolean; isGroupAdmin: boolean }) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const { group } = useSession()
  const label = (id: string) => graph.nodes.find(n => n.id === id)?.label ?? id

  if (node.kind === 'asset') {
    return (
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <Link to={`/assets/${node.id}`}>{t('viewAsset')} <ArrowRightOutlined /></Link>
        <AssetProfileView key={node.id} assetId={node.id} hostname={node.label} groupId={node.groupId ?? group?.id} canEdit={canEdit} isGroupAdmin={isGroupAdmin} compact />
      </Space>
    )
  }
  const inbound = graph.edges.filter(e => e.to === node.id)
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
        {t(node.kind === 'internet' ? 'nodeInternetHint' : node.kind === 'managed' ? 'nodeOtherGroupHint' : 'nodeUnmanagedHint')}
      </Typography.Paragraph>
      {node.ports?.length ? (
        <div>
          <Typography.Text strong>{t('portsSeen')}</Typography.Text>
          <div style={{ marginTop: 8 }}>{node.ports.map(p => <Tag key={p} className="mono">{p}</Tag>)}</div>
        </div>
      ) : null}
      {node.kind !== 'internet' && inbound.length > 0 && (
        <div>
          <Typography.Text strong>{t('connectedBy')}</Typography.Text>
          <div style={{ marginTop: 8 }}>{inbound.map(e => <Tag key={e.from}>{label(e.from)}</Tag>)}</div>
        </div>
      )}
      {/* 每台主机一段：先给总量与最近活动，再按地址列明细；连得多的主机排前面 */}
      {node.kind === 'internet' && graph.edges.filter(e => e.from === node.id || e.to === node.id).sort((a, b) => b.count - a.count).map(e => {
        const assetId = e.from === node.id ? e.to : e.from
        return (
          <div key={`${e.from}>${e.to}`}>
            <Flex justify="space-between" align="baseline" gap={8} wrap>
              <Typography.Text strong>{e.from === node.id ? `${t('mapLegendInternet')} → ${label(e.to)}` : `${label(e.from)} → ${t('mapLegendInternet')}`}</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('connCount', { n: e.count.toLocaleString() })} · <Ago iso={e.lastSeen} /></Typography.Text>
            </Flex>
            <div style={{ marginTop: 8 }}><PublicDestList items={e.targets ?? []} host={{ id: assetId, name: label(assetId), groupId: graph.nodes.find(n => n.id === assetId)?.groupId ?? group?.id }} limit={6} /></div>
          </div>
        )
      })}
      {node.kind === 'discovered' && <Button type="primary" onClick={() => navigate('/assets')}>{t('goEnroll')}</Button>}
    </Space>
  )
}
