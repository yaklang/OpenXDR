import { Space, Tooltip, Typography, theme } from 'antd'
import { useLayoutEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTheme } from '../app/theme'

// 图表配色：单序列采用 Gemini 主色蓝，亮暗各取校验通过的一档；级别用固定状态色
export function useSeriesColor() {
  const { dark } = useTheme()
  return dark ? '#4c8df6' : '#0b57d0'
}

export const SEVERITY_COLOR: Record<number, string> = {
  5: '#d93025', // critical
  4: '#e8710a', // serious
  3: '#f29900', // warning
  2: '#4c8df6', // 低危与标签同为蓝，取单色蓝阶中的一档
  1: '#9aa0a6',
}

// 1,284 / 12.9K / 3.4M
export const compact = (n: number) =>
  n < 1000 ? String(n) : n < 1e6 ? `${+(n / 1e3).toFixed(n < 1e4 ? 1 : 0)}K` : `${+(n / 1e6).toFixed(1)}M`

// 取整刻度：四格，每格步长落在 1/2/5×10^k 上，计数类数据的刻度永远是整数（不会出现 12.5）
function niceMax(v: number) {
  const raw = Math.max(1, Math.ceil(v / 4))
  const p = 10 ** Math.floor(Math.log10(raw))
  return [1, 2, 5, 10].map(m => m * p).find(m => m >= raw)! * 4
}

function useWidth() {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(0)
  useLayoutEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, width] as const
}

// 单序列柱图：柱宽封顶 24px、顶端 4px 圆角、底端贴基线；每根柱子整列都是悬停区
export function ColumnChart({ data, height = 200, xLabel, tip, dim }: {
  data: { key: string; value: number }[]
  height?: number
  xLabel: (i: number) => string | null
  tip: (i: number) => string
  dim?: boolean
}) {
  const { token } = theme.useToken()
  const color = useSeriesColor()
  const [ref, width] = useWidth()
  const [hover, setHover] = useState<number | null>(null)
  const axisW = 36
  const axisH = 22
  const padTop = 8
  const plotW = Math.max(0, width - axisW)
  const plotH = height - axisH - padTop
  const max = niceMax(Math.max(...data.map(d => d.value), 0))
  const slot = data.length ? plotW / data.length : 0
  const barW = Math.min(24, Math.max(2, slot - 2))
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => f * max)
  const y = (v: number) => padTop + plotH - (v / max) * plotH

  return (
    <div ref={ref} style={{ opacity: dim ? 0.5 : 1, transition: 'opacity .2s' }}>
      {width > 0 && (
        <svg width={width} height={height} role="img">
          {ticks.map(v => (
            <g key={v}>
              <line x1={axisW} x2={width} y1={y(v)} y2={y(v)} stroke={v ? token.colorBorderSecondary : token.colorBorder} strokeWidth={1} />
              <text x={axisW - 6} y={y(v) + 4} textAnchor="end" fontSize={11} fill={token.colorTextTertiary} style={{ fontVariantNumeric: 'tabular-nums' }}>{compact(v)}</text>
            </g>
          ))}
          {data.map((d, i) => {
            const x = axisW + i * slot
            const h = (d.value / max) * plotH
            const bx = x + (slot - barW) / 2
            const r = Math.min(6, h, barW / 2)
            const base = padTop + plotH
            const label = xLabel(i)
            return (
              <g key={d.key}>
                {h > 0 && (
                  <path
                    d={`M ${bx} ${base} V ${base - h + r} Q ${bx} ${base - h} ${bx + r} ${base - h} H ${bx + barW - r} Q ${bx + barW} ${base - h} ${bx + barW} ${base - h + r} V ${base} Z`}
                    fill={color}
                    opacity={hover === null || hover === i ? 1 : 0.55}
                  />
                )}
                {label && <text x={x + slot / 2} y={height - 6} textAnchor="middle" fontSize={11} fill={token.colorTextTertiary}>{label}</text>}
                <Tooltip title={tip(i)} mouseEnterDelay={0}>
                  <rect x={x} y={0} width={slot} height={padTop + plotH} fill="transparent" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
                </Tooltip>
              </g>
            )
          })}
        </svg>
      )}
    </div>
  )
}

// 横向条形：标签在左、数值在柱端，颜色由调用方给（级别用状态色，排名用序列色）；给了 to 整行可点
export function BarList({ items, max, dim, labelWidth = '38%' }: {
  items: { key: string; label: React.ReactNode; value: number; color: string; to?: string }[]
  max?: number
  dim?: boolean
  labelWidth?: string
}) {
  const { token } = theme.useToken()
  const top = max ?? Math.max(1, ...items.map(i => i.value))
  return (
    <div className="bar-list" style={{ opacity: dim ? 0.5 : 1, '--label-w': labelWidth } as React.CSSProperties}>
      {items.map(i => {
        const row = (
          <>
            <div className="bar-label">{i.label}</div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `calc((100% - 56px) * ${i.value / top})`, minWidth: i.value ? 4 : 0, background: i.color }} />
              <Typography.Text style={{ fontSize: 12, color: token.colorTextSecondary, fontVariantNumeric: 'tabular-nums' }}>{i.value.toLocaleString()}</Typography.Text>
            </div>
          </>
        )
        return i.to
          ? <Link key={i.key} to={i.to} className="bar-row bar-row-link">{row}</Link>
          : <div key={i.key} className="bar-row">{row}</div>
      })}
    </div>
  )
}

// 分类色：参考配色的前五位，固定顺序、亮暗各一组，已用 dataviz 校验脚本跑过（相邻 CVD ΔE ≥ 8.4）。
// 亮色下第 3、4、5 位对底色不到 3:1，用到它们的图必须带图例和表格视图
export function useCategorical() {
  const { dark } = useTheme()
  return dark ? ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181'] : ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4']
}

// 堆叠柱图：同一根柱子里各段之间留 2px 底色缝，只有最上面一段圆角；每根柱子整列是悬停区，提示里逐项列出
export function StackedColumnChart({ data, series, height = 220, xLabel, tip }: {
  data: { key: string; values: number[] }[]
  series: { name: string; color: string }[]
  height?: number
  xLabel: (i: number) => string | null
  tip: (i: number) => React.ReactNode
}) {
  const { token } = theme.useToken()
  const [ref, width] = useWidth()
  const [hover, setHover] = useState<number | null>(null)
  const axisW = 40
  const axisH = 22
  const padTop = 8
  const gap = 2
  const plotW = Math.max(0, width - axisW)
  const plotH = height - axisH - padTop
  const max = niceMax(Math.max(...data.map(d => d.values.reduce((a, b) => a + b, 0)), 0))
  const slot = data.length ? plotW / data.length : 0
  const barW = Math.min(24, Math.max(2, slot - 2))
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => f * max)
  const base = padTop + plotH
  const y = (v: number) => base - (v / max) * plotH

  return (
    <div>
      <Space size={16} wrap style={{ marginBottom: 8 }}>
        {series.map(s => (
          <Space key={s.name} size={6}><span className="graph-legend" style={{ background: s.color }} /><Typography.Text type="secondary" style={{ fontSize: 12 }}>{s.name}</Typography.Text></Space>
        ))}
      </Space>
      <div ref={ref}>
        {width > 0 && (
          <svg width={width} height={height} role="img">
            {ticks.map(v => (
              <g key={v}>
                <line x1={axisW} x2={width} y1={y(v)} y2={y(v)} stroke={v ? token.colorBorderSecondary : token.colorBorder} strokeWidth={1} />
                <text x={axisW - 6} y={y(v) + 4} textAnchor="end" fontSize={11} fill={token.colorTextTertiary} style={{ fontVariantNumeric: 'tabular-nums' }}>{compact(v)}</text>
              </g>
            ))}
            {data.map((d, i) => {
              const x = axisW + i * slot
              const bx = x + (slot - barW) / 2
              const top = d.values.reduce((last, v, j) => (v > 0 ? j : last), -1)
              let cum = 0
              const label = xLabel(i)
              return (
                <g key={d.key} opacity={hover === null || hover === i ? 1 : 0.55}>
                  {d.values.map((v, j) => {
                    if (v <= 0) return null
                    const y0 = y(cum) - (cum > 0 ? gap : 0)
                    cum += v
                    const y1 = y(cum)
                    const h = y0 - y1
                    if (h <= 0) return null
                    const r = j === top ? Math.min(4, h, barW / 2) : 0
                    return (
                      <path key={j} fill={series[j].color}
                        d={`M ${bx} ${y0} V ${y1 + r} Q ${bx} ${y1} ${bx + r} ${y1} H ${bx + barW - r} Q ${bx + barW} ${y1} ${bx + barW} ${y1 + r} V ${y0} Z`} />
                    )
                  })}
                  {label && <text x={x + slot / 2} y={height - 6} textAnchor="middle" fontSize={11} fill={token.colorTextTertiary}>{label}</text>}
                  <Tooltip title={tip(i)} mouseEnterDelay={0}>
                    <rect x={x} y={0} width={slot} height={base} fill="transparent" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
                  </Tooltip>
                </g>
              )
            })}
          </svg>
        )}
      </div>
    </div>
  )
}
