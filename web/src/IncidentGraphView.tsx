import type { Graph, GraphNode } from './api'

// 中间一列既放进程也放连接：端点证据和流量证据在同一层
const COLUMNS = ['asset', 'process', 'connection', 'alert'] as const
const COL_X: Record<string, number> = { asset: 20, process: 250, connection: 250, alert: 480 }
const NODE_W = 190
const NODE_H = 34
const GAP_Y = 52
const COLORS: Record<string, string> = {
  asset: '#58a6ff',
  process: '#d2a8ff',
  connection: '#3fb950',
  alert: '#f85149',
}

export function IncidentGraphView({ graph }: { graph: Graph }) {
  const columns: Record<string, GraphNode[]> = { asset: [], process: [], connection: [], alert: [] }
  for (const node of graph.nodes) (columns[node.type] ?? columns.process).push(node)

  const pos = new Map<string, { x: number; y: number }>()
  let middleRow = 0
  for (const col of COLUMNS) {
    // process 和 connection 共用中间列，纵向接着排，不能各自从 0 开始
    const shared = col === 'process' || col === 'connection'
    columns[col].forEach((n, i) => {
      const row = shared ? middleRow++ : i
      pos.set(n.id, { x: COL_X[col], y: 20 + row * GAP_Y })
    })
  }

  const rows = Math.max(columns.asset.length, middleRow, columns.alert.length, 1)
  const height = 20 + rows * GAP_Y

  return (
    <div className="graph-scroll">
      <svg width={COL_X.alert + NODE_W + 20} height={height}>
        {graph.edges.map((e, i) => {
          const from = pos.get(e.from)
          const to = pos.get(e.to)
          if (!from || !to) return null
          const x1 = from.x + NODE_W
          const y1 = from.y + NODE_H / 2
          const x2 = to.x
          const y2 = to.y + NODE_H / 2
          const mx = (x1 + x2) / 2
          return (
            <path
              key={i}
              d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke="#30363d"
              strokeWidth={1.5}
            />
          )
        })}
        {graph.nodes.map(node => {
          const p = pos.get(node.id)
          if (!p) return null
          const color = COLORS[node.type] ?? '#8b949e'
          const label = node.label.length > 24 ? node.label.slice(0, 23) + '…' : node.label
          return (
            <g key={node.id}>
              <rect
                x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={6}
                fill="#161b22" stroke={color} strokeWidth={1.5}
              />
              <text x={p.x + 10} y={p.y + 21} fill="#e6edf3" fontSize={12}>
                <title>{node.label}</title>
                {label}
              </text>
            </g>
          )
        })}
      </svg>
      {graph.overflow > 0 && <div className="graph-overflow">+{graph.overflow} 条告警未入图</div>}
    </div>
  )
}
