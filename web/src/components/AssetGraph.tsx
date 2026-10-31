import { CompressOutlined } from '@ant-design/icons'
import { Button, Tooltip, theme } from 'antd'
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationNodeDatum } from 'd3-force'
import { useEffect, useMemo, useRef, useState, type MouseEvent, type PointerEvent, type WheelEvent } from 'react'
import type { AssetMap, MapEdge, MapNode, ZoneKind } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { useZoneColor, zoneName } from './AssetProfile'

// 泳道：从左到右暴露程度递减，一眼看出哪些在最外面
const LANES: { kind: ZoneKind | 'wan'; key: MsgKey }[] = [
  { kind: 'wan', key: 'mapLegendInternet' },
  { kind: 'external', key: 'zoneExternal' },
  { kind: 'dmz', key: 'zoneDmz' },
  { kind: 'cloud', key: 'zoneCloud' },
  { kind: 'internal', key: 'zoneInternal' },
]
// 泳道：从左到右暴露程度递减，一眼看出哪些在最外面
type SimNode = SimulationNodeDatum & { node: MapNode; r: number; lane: number }
type SimLink = { source: SimNode; target: SimNode; edge: MapEdge }
// 一条泳道：只为有节点的区域开道，宽度随节点数增长
type Lane = { kind: ZoneKind | 'wan'; key: MsgKey; x: number; w: number }

export type Selection = { node: MapNode } | { edge: MapEdge; from: MapNode; to: MapNode } | null

function radius(n: MapNode) {
  if (n.kind === 'internet') return 22
  if (n.kind !== 'asset') return 7
  return 9 + (n.criticality ?? 2) * 3
}

function laneKind(n: MapNode) {
  return n.kind === 'internet' ? 'wan' : n.zone.kind
}

function bounds(nodes: SimNode[]) {
  if (!nodes.length) return { x: 0, y: 0, w: 1, h: 1 }
  const xs = nodes.map(n => n.x!), ys = nodes.map(n => n.y!)
  const x = Math.min(...xs) - 80, y = Math.min(...ys) - 90
  return { x, y, w: Math.max(...xs) + 80 - x, h: Math.max(...ys) + 70 - y }
}

// 有向弧线：略微弯曲，避免长边从无关节点身后直穿过去被误读成相连；终点收在目标圆边外，箭头不被盖住
function curve(a: SimNode, b: SimNode) {
  const dx = b.x! - a.x!, dy = b.y! - a.y!
  const d = Math.hypot(dx, dy) || 1
  const bend = Math.min(80, d * 0.18)
  const cx = (a.x! + b.x!) / 2 - (dy / d) * bend, cy = (a.y! + b.y!) / 2 + (dx / d) * bend
  const ex = b.x! - cx, ey = b.y! - cy, el = Math.hypot(ex, ey) || 1
  const tx = b.x! - (ex / el) * (b.r + 4), ty = b.y! - (ey / el) * (b.r + 4)
  return `M${a.x},${a.y} Q${cx},${cy} ${tx},${ty}`
}

// 由 id 得到稳定的 [-0.5, 0.5) 抖动：同一份数据每次布局一样，刷新时节点不跳
function jitter(id: string, salt: number) {
  let h = salt
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 2654435761)
  return ((h >>> 0) % 1000) / 1000 - 0.5
}

// 静态布局：一次跑完模拟再画，节点不漂，截图和讨论时位置稳定
function layout(graph: AssetMap) {
  const lanes: Lane[] = []
  let x = 0
  for (const l of LANES) {
    const n = graph.nodes.filter(node => laneKind(node) === l.kind).length
    if (!n) continue
    const w = Math.max(220, 130 * Math.ceil(Math.sqrt(n)))
    lanes.push({ ...l, x: x + w / 2, w })
    x += w + 24
  }
  const laneIndex = new Map(lanes.map((l, i) => [l.kind, i]))
  const nodes: SimNode[] = graph.nodes.map(node => {
    const lane = laneIndex.get(laneKind(node))!
    return { node, r: radius(node), lane, x: lanes[lane].x + jitter(node.id, 1) * lanes[lane].w * 0.6, y: jitter(node.id, 7) * 400 }
  })
  const byId = new Map(nodes.map(n => [n.node.id, n]))
  const links: SimLink[] = graph.edges.flatMap(edge => {
    const source = byId.get(edge.from), target = byId.get(edge.to)
    return source && target ? [{ source, target, edge }] : []
  })
  const sim = forceSimulation(nodes)
    .force('link', forceLink<SimNode, SimLink>(links).distance(120).strength(0.15))
    .force('charge', forceManyBody<SimNode>().strength(n => -90 - n.r * 14))
    .force('x', forceX<SimNode>(n => lanes[n.lane].x).strength(0.5))
    .force('y', forceY<SimNode>(0).strength(0.05))
    // 碰撞半径要盖住下方的主机名与角色两行字，否则标签互相压住
    .force('collide', forceCollide<SimNode>(n => Math.max(n.r + 30, n.node.kind === 'asset' ? 64 : 46)).strength(1))
    .stop()
  for (let i = 0; i < 400; i++) sim.tick()
  // 连线会把节点拽出泳道，最后夹回去：位置即区域
  for (const n of nodes) {
    const l = lanes[n.lane], pad = Math.min(n.r + 46, l.w / 2)
    n.x = Math.min(l.x + l.w / 2 - pad, Math.max(l.x - l.w / 2 + pad, n.x!))
  }
  return { nodes, links, lanes, box: bounds(nodes) }
}

export function AssetGraph({ graph, search, selected, onSelect, height = 640 }: {
  graph: AssetMap; search: string; selected: Selection; onSelect: (s: Selection) => void; height?: number
}) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const zoneColor = useZoneColor()
  const box = useRef<HTMLDivElement>(null)
  const { nodes, links, lanes, box: area } = useMemo(() => layout(graph), [graph])
  const [view, setView] = useState({ k: 1, x: 0, y: 0 })
  const [hover, setHover] = useState<string | null>(null)
  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null)

  const fit = () => {
    const el = box.current
    if (!el) return
    const k = Math.min(el.clientWidth / area.w, height / area.h, 1.4)
    setView({ k, x: (el.clientWidth - area.w * k) / 2 - area.x * k, y: (height - area.h * k) / 2 - area.y * k })
  }
  // 数据或高度变了重新铺满画布
  useEffect(fit, [area, height]) // eslint-disable-line react-hooks/exhaustive-deps

  // 聚焦：悬停或选中的节点及其邻居保持高亮，其余淡出；搜索同理
  const focusId = hover ?? (selected && 'node' in selected ? selected.node.id : null)
  const neighbors = useMemo(() => {
    if (!focusId) return null
    const s = new Set([focusId])
    for (const l of links) {
      if (l.source.node.id === focusId) s.add(l.target.node.id)
      if (l.target.node.id === focusId) s.add(l.source.node.id)
    }
    return s
  }, [focusId, links])
  const q = search.trim().toLowerCase()
  const visible = (n: MapNode) => (!neighbors || neighbors.has(n.id)) && (!q || n.label.toLowerCase().includes(q) || (n.role ?? '').toLowerCase().includes(q))

  const onWheel = (e: WheelEvent) => {
    const rect = box.current!.getBoundingClientRect()
    const px = e.clientX - rect.left, py = e.clientY - rect.top
    const k = Math.min(4, Math.max(0.2, view.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)))
    setView({ k, x: px - ((px - view.x) / view.k) * k, y: py - ((py - view.y) / view.k) * k })
  }
  const onPointerDown = (e: PointerEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false }
  }
  const onPointerMove = (e: PointerEvent) => {
    const d = drag.current
    if (!d) return
    if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true
    if (d.moved) setView(v => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }))
  }
  const onPointerUp = () => {
    if (drag.current && !drag.current.moved) onSelect(null)
    drag.current = null
  }
  const click = (s: Selection) => (e: MouseEvent) => {
    e.stopPropagation()
    if (!drag.current?.moved) onSelect(s)
  }

  const laneTop = area.y + 6
  const edgeColor = token.colorTextQuaternary

  return (
    <div ref={box} style={{ position: 'relative', height, overflow: 'hidden', cursor: 'grab', touchAction: 'none', borderRadius: 18 }}
      onWheel={onWheel} onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerLeave={() => { drag.current = null }}>
      <svg width="100%" height={height} role="img" aria-label={t('navAssetMap')}>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {lanes.map(l => (
            <g key={l.kind} pointerEvents="none">
              <rect x={l.x - l.w / 2} y={laneTop} width={l.w} height={area.h - 6} rx={20}
                fill={l.kind === 'wan' ? token.colorFillTertiary : zoneColor(l.kind)} fillOpacity={l.kind === 'wan' ? 0.5 : 0.05}
                stroke={l.kind === 'wan' ? token.colorBorderSecondary : zoneColor(l.kind)} strokeOpacity={0.25} strokeDasharray="4 4" />
              <text x={l.x} y={laneTop + 22} textAnchor="middle" fontSize={12} fill={token.colorTextTertiary} letterSpacing={2}>{t(l.key)}</text>
            </g>
          ))}
          <defs>
            {(['idle', 'sel'] as const).map(k => (
              <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX={9} refY={5} markerWidth={9} markerHeight={9} markerUnits="userSpaceOnUse" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill={k === 'sel' ? token.colorPrimary : token.colorTextQuaternary} />
              </marker>
            ))}
          </defs>
          {links.map(({ source, target, edge }) => {
            const on = visible(source.node) && visible(target.node)
            const isSel = !!selected && 'edge' in selected && selected.edge === edge
            return (
              <path key={`${edge.from}>${edge.to}`} d={curve(source, target)} fill="none"
                stroke={isSel ? token.colorPrimary : edge.note ? token.colorPrimaryBorder : edgeColor}
                strokeWidth={Math.min(6, 1 + Math.log10(edge.count + 1)) * (isSel ? 1.6 : 1)}
                strokeOpacity={on ? 0.9 : 0.12} markerEnd={`url(#arrow-${isSel ? 'sel' : 'idle'})`} style={{ cursor: 'pointer' }}
                onClick={click({ edge, from: source.node, to: target.node })} />
            )
          })}
          {nodes.map(({ node, x, y, r }) => {
            const on = visible(node)
            const color = node.kind === 'internet' ? token.colorTextSecondary : zoneColor(node.zone.kind)
            const isSel = selected && 'node' in selected && selected.node.id === node.id
            return (
              <g key={node.id} transform={`translate(${x},${y})`} opacity={on ? 1 : 0.15} style={{ cursor: 'pointer' }}
                onClick={click({ node })} onPointerEnter={() => setHover(node.id)} onPointerLeave={() => setHover(null)}>
                {node.kind === 'asset' && (node.criticality ?? 0) >= 4 && <circle r={r + 6} fill={color} fillOpacity={0.15} />}
                <circle r={r} fill={node.kind === 'asset' ? color : token.colorBgContainer} fillOpacity={node.kind === 'asset' ? (node.online ? 0.9 : 0.4) : 1}
                  stroke={isSel ? token.colorPrimary : color} strokeWidth={isSel ? 3 : node.kind === 'asset' ? 0 : 1.5}
                  strokeDasharray={node.kind === 'discovered' ? '3 3' : undefined} />
                {node.kind === 'internet' && <text textAnchor="middle" dy={4} fontSize={11} fill={token.colorText}>WAN</text>}
                <text y={r + 15} textAnchor="middle" fontSize={12} fontWeight={node.kind === 'asset' ? 600 : 400}
                  fill={node.kind === 'asset' ? token.colorText : token.colorTextSecondary}
                  className={node.kind === 'asset' ? undefined : 'mono'}>
                  {node.kind === 'internet' ? t('mapLegendInternet') : node.label}
                </text>
                {node.role && <text y={r + 29} textAnchor="middle" fontSize={11} fill={token.colorTextTertiary}>{node.role}</text>}
                <title>{[node.label, node.role, zoneName(node.zone, t), node.ports?.join(' ')].filter(Boolean).join('\n')}</title>
              </g>
            )
          })}
        </g>
      </svg>
      <Tooltip title={t('mapFit')}>
        <Button size="small" icon={<CompressOutlined />} onClick={fit} onPointerDown={e => e.stopPropagation()}
          style={{ position: 'absolute', right: 12, top: 12 }} />
      </Tooltip>
    </div>
  )
}
