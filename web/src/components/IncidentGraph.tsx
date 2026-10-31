import { CompressOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons'
import { Button, Flex, Space, Tooltip, Typography, theme } from 'antd'
import { useEffect, useRef, useState } from 'react'
import type { Graph, GraphNode } from '../api'
import { useI18n } from '../i18n'

// 中间一列放进程、连接与文件：端点证据和流量证据在同一层
const COLUMNS = ['asset', 'process', 'connection', 'file', 'alert'] as const
const COL_X: Record<string, number> = { asset: 12, process: 268, connection: 268, file: 268, alert: 524 }
const NODE_W = 220
const LEGEND = { asset: 'graphAsset', process: 'graphProcess', connection: 'graphConnection', file: 'graphFile', alert: 'graphAlert' } as const
// 适配宽度时最多缩到这里：再小字就看不清了，放不下的部分拖动查看
const MIN_FIT = 0.7
const NODE_H = 36
const GAP_Y = 48

// 按显示宽度截断：中日韩字符算两格，免得中文标签冲出节点框
function clip(s: string, max: number) {
  let w = 0
  for (let i = 0; i < s.length; i++) {
    w += s.charCodeAt(i) > 0x2e80 ? 2 : 1
    if (w > max) return s.slice(0, i) + '…'
  }
  return s
}

export function IncidentGraph({ graph }: { graph: Graph }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const colors: Record<string, string> = {
    asset: token.colorPrimary,
    process: token.purple,
    connection: token.colorSuccess,
    file: token.cyan,
    alert: token.colorError,
  }
  const columns: Record<string, GraphNode[]> = { asset: [], process: [], connection: [], file: [], alert: [] }
  for (const node of graph.nodes) (columns[node.type] ?? columns.process).push(node)

  const pos = new Map<string, { x: number; y: number }>()
  let middleRow = 0
  for (const col of COLUMNS) {
    // 中间列几类共用，纵向接着排，不能各自从 0 开始
    const shared = col === 'process' || col === 'connection' || col === 'file'
    columns[col].forEach((n, i) => {
      const row = shared ? middleRow++ : i
      pos.set(n.id, { x: COL_X[col], y: 20 + row * GAP_Y })
    })
  }
  const rows = Math.max(columns.asset.length, middleRow, columns.alert.length, 1)
  const contentW = COL_X.alert + NODE_W + 20
  const contentH = 20 + rows * GAP_Y
  // 缩放只按宽度适配，节点多时字不会被压小；高度跟着缩放后的内容走，最高 720，再多靠拖拽
  const [fitK, setFitK] = useState(1)
  const height = Math.min(Math.max(contentH * fitK + 8, 160), 720)

  // 视图变换：滚轮缩放（以指针为中心）、拖拽平移；节点多时比滚动条好用
  const box = useRef<HTMLDivElement>(null)
  const [view, setView] = useState({ k: 1, x: 0, y: 0 })
  const drag = useRef<{ x: number; y: number } | null>(null)
  const zoom = (f: number, cx = contentW / 2, cy = height / 2) =>
    setView(v => {
      const k = Math.min(3, Math.max(0.3, v.k * f))
      return { k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k }
    })
  const [boxW, setBoxW] = useState(contentW)
  const fit = () => {
    const w = box.current?.clientWidth ?? contentW
    const k = Math.max(MIN_FIT, Math.min(1, w / contentW))
    setFitK(k)
    setBoxW(w)
    // 放得下就居中；放不下（手机）从左边开始，先看到主机与进程
    setView({ k, x: Math.max(0, (w - contentW * k) / 2), y: 0 })
  }
  const overflows = contentW * fitK > boxW + 1
  useEffect(fit, [contentW, contentH, height])
  // React 的 onWheel 是被动监听，阻止不了页面滚动，只能手挂
  useEffect(() => {
    const el = box.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      zoom(e.deltaY < 0 ? 1.1 : 1 / 1.1, e.clientX - r.left, e.clientY - r.top)
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  })

  return (
    <div>
      <Flex justify="space-between" align="center" style={{ marginBottom: 12 }}>
      <Space size={16} wrap>
        {COLUMNS.filter(k => columns[k].length).map(k => (
          <Space key={k} size={6}><span className="graph-legend" style={{ background: colors[k] }} /><Typography.Text type="secondary" style={{ fontSize: 12 }}>{t(LEGEND[k])}</Typography.Text></Space>
        ))}
      </Space>
      <Space.Compact size="small">
        <Tooltip title={t('zoomIn')}><Button icon={<ZoomInOutlined />} onClick={() => zoom(1.25)} /></Tooltip>
        <Tooltip title={t('zoomOut')}><Button icon={<ZoomOutOutlined />} onClick={() => zoom(0.8)} /></Tooltip>
        <Tooltip title={t('zoomFit')}><Button icon={<CompressOutlined />} onClick={fit} /></Tooltip>
      </Space.Compact>
      </Flex>
      <div
        ref={box}
        style={{ height, overflow: 'hidden', cursor: drag.current ? 'grabbing' : 'grab', touchAction: 'none', borderRadius: 16, background: token.colorFillQuaternary, border: `1px solid ${token.colorBorderSecondary}` }}
        onPointerDown={e => { drag.current = { x: e.clientX - view.x, y: e.clientY - view.y }; e.currentTarget.setPointerCapture(e.pointerId) }}
        onPointerMove={e => { const d = drag.current; if (d) setView(v => ({ ...v, x: e.clientX - d.x, y: e.clientY - d.y })) }}
        onPointerUp={() => { drag.current = null }}
      >
      <svg width="100%" height={height}>
        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
        {graph.edges.map((e, i) => {
          const from = pos.get(e.from)
          const to = pos.get(e.to)
          if (!from || !to) return null
          const x1 = from.x + NODE_W
          const y1 = from.y + NODE_H / 2
          const x2 = to.x
          const y2 = to.y + NODE_H / 2
          const mx = (x1 + x2) / 2
          const spawned = e.rel === 'spawned'
          // 父子进程在同一列，直连会压在节点上，绕到列右侧再回来
          const d = spawned
            ? `M ${x1} ${y1} C ${x1 + 40} ${y1}, ${x1 + 40} ${y2}, ${x2 + NODE_W} ${y2}`
            : `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`
          return <path key={i} d={d} fill="none" stroke={spawned ? colors.process : token.colorBorder} strokeWidth={1.5} strokeDasharray={spawned ? '4 3' : undefined} />
        })}
        {graph.nodes.map(node => {
          const p = pos.get(node.id)
          if (!p) return null
          const label = clip(node.label, 31)
          const c = colors[node.type] ?? token.colorBorder
          return (
            <g key={node.id}>
              <rect x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={10} fill={token.colorBgContainer} stroke={token.colorBorder} strokeWidth={1} />
              <rect x={p.x} y={p.y} width={5} height={NODE_H} rx={2.5} fill={c} />
              <text x={p.x + 14} y={p.y + 22} fill={token.colorText} fontSize={13}>
                <title>{node.label}</title>
                {label}
              </text>
            </g>
          )
        })}
        </g>
      </svg>
      </div>
      {overflows && <Typography.Text type="secondary" style={{ display: 'block', marginTop: 6, fontSize: 12 }}>{t('graphDragHint')}</Typography.Text>}
      {graph.overflow > 0 && <Typography.Text type="warning">{t('graphOverflow', { n: graph.overflow })}</Typography.Text>}
    </div>
  )
}
