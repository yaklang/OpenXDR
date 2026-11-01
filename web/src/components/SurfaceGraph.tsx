import { GlobalOutlined, QuestionCircleOutlined } from '@ant-design/icons'
import { Tag, Tooltip, Typography, theme } from 'antd'
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import type { AttackSurface, ExposedService, SurfacePeer, ZoneKind } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { CritTag, useZoneColor } from './AssetProfile'

// 攻击者视角：最左是互联网，往右暴露程度递减
const COLUMNS: { kind: ZoneKind | 'wan'; key: MsgKey }[] = [
  { kind: 'wan', key: 'mapLegendInternet' },
  { kind: 'external', key: 'zoneExternal' },
  { kind: 'dmz', key: 'zoneDmz' },
  { kind: 'cloud', key: 'zoneCloud' },
  { kind: 'internal', key: 'zoneInternal' },
]
const CARD_W = 270
const GAP = 96
const HEAD_H = 52
const ROW_H = 30
const PILL_H = 32
const PAD = 16
const TOP = 40

const RISK_KEY: Record<string, MsgKey> = { high: 'riskHigh', medium: 'riskMedium', low: 'riskLow' }
const SOURCE_KEY: Record<string, MsgKey> = { ai: 'noteSourceAi', investigation: 'noteSourceInvestigation', human: 'noteSourceHuman' }

type Box = { x: number; y: number; w: number; h: number; col: number }
type Card = { id: string; label: string; peer?: SurfacePeer; rows: ExposedService[]; box: Box }

// 低危要有依据才藏：端口表认得出的服务，或调查与人工给了低危。认不出又没查过的（docker-proxy 映射出来的端口多是这样）
// 端口表只能默认算低危，藏起来就看不到暴露面里最该查的那部分
const knownLow = (e: ExposedService) => e.service.risk === 'low' && (e.service.category !== 'other' || e.note?.risk === 'low')

// 卡片按最高风险分排在本栏上方；只作为访问方出现的节点（未纳管地址、别组资产、没有暴露面的本组资产）收成小标签
function layout(surface: AttackSurface, hideLow: boolean) {
  const rowsOf = new Map<string, ExposedService[]>()
  for (const e of surface.exposures) {
    if (hideLow && knownLow(e) && !e.fromPublic) continue
    rowsOf.set(e.assetId, [...(rowsOf.get(e.assetId) ?? []), e])
  }
  const peerOf = new Map(surface.peers.map(p => [p.id, p]))
  const visibleRows = new Set([...rowsOf.values()].flat().map(e => `${e.assetId}>${e.proto}/${e.port}`))
  const paths = surface.paths.filter(p => visibleRows.has(`${p.assetId}>${p.service}`))

  const cards: Card[] = []
  for (const [assetId, rows] of rowsOf) {
    rows.sort((a, b) => b.score - a.score)
    cards.push({ id: assetId, label: rows[0].hostname, rows, box: { x: 0, y: 0, w: CARD_W, h: 0, col: COLUMNS.findIndex(c => c.kind === rows[0].zone.kind) } })
  }
  for (const id of new Set(paths.map(p => p.from))) {
    if (rowsOf.has(id)) continue
    const peer = peerOf.get(id)
    if (!peer) continue
    const col = peer.kind === 'internet' ? 0 : COLUMNS.findIndex(c => c.kind === peer.zone.kind)
    cards.push({ id, label: peer.label, peer, rows: [], box: { x: 0, y: 0, w: 0, h: PILL_H, col } })
  }

  // 只保留有内容的栏，栏内先放资产卡片（按风险）再放小标签
  const used = [...new Set(cards.map(c => c.box.col))].sort((a, b) => a - b)
  const top = (c: Card) => Math.max(0, ...c.rows.map(r => r.score))
  let height = 0
  used.forEach((col, i) => {
    let y = TOP
    for (const c of cards.filter(c => c.box.col === col).sort((a, b) => (b.rows.length ? 1 : 0) - (a.rows.length ? 1 : 0) || top(b) - top(a))) {
      const w = c.rows.length ? CARD_W : 170
      c.box = { x: i * (CARD_W + GAP) + (CARD_W - w) / 2, y, w, h: c.rows.length ? HEAD_H + c.rows.length * ROW_H + 8 : PILL_H, col: i }
      y += c.box.h + PAD
    }
    height = Math.max(height, y)
  })
  return { cards, paths, columns: used.map(i => COLUMNS[i]), width: used.length * (CARD_W + GAP) - GAP, height }
}

export function SurfaceGraph({ surface, hideLow, onPick }: { surface: AttackSurface; hideLow: boolean; onPick: (e: ExposedService) => void }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const zoneColor = useZoneColor()
  const [hover, setHover] = useState<string | null>(null)
  const { cards, paths, columns, width, height } = useMemo(() => layout(surface, hideLow), [surface, hideLow])
  const cardOf = new Map(cards.map(c => [c.id, c]))
  const riskColor = (r: string) => (r === 'high' ? token.colorError : r === 'medium' ? token.colorWarning : token.colorTextQuaternary)

  // 连线：从访问方指向被访问服务所在的那一行；同栏的从左侧绕出去
  const lines = paths.flatMap(p => {
    const src = cardOf.get(p.from), dst = cardOf.get(p.assetId)
    const row = dst?.rows.findIndex(r => `${r.proto}/${r.port}` === p.service) ?? -1
    if (!src || !dst || row < 0) return []
    const ty = dst.box.y + HEAD_H + row * ROW_H + ROW_H / 2
    const sy = src.box.y + (src.rows.length ? HEAD_H / 2 : PILL_H / 2)
    let d: string
    if (src.box.col < dst.box.col) {
      const sx = src.box.x + src.box.w, tx = dst.box.x, mid = (sx + tx) / 2
      d = `M${sx},${sy} C${mid},${sy} ${mid},${ty} ${tx - 2},${ty}`
    } else if (src.box.col > dst.box.col) {
      const sx = src.box.x, tx = dst.box.x + dst.box.w, mid = (sx + tx) / 2
      d = `M${sx},${sy} C${mid},${sy} ${mid},${ty} ${tx + 2},${ty}`
    } else {
      const sx = src.box.x, tx = dst.box.x, bulge = Math.min(sx, tx) - 50
      d = `M${sx},${sy} C${bulge},${sy} ${bulge},${ty} ${tx - 2},${ty}`
    }
    const e = dst.rows[row]
    const key = `${p.from}>${p.assetId}>${p.service}`
    const on = !hover || hover === key || hover === `${p.assetId}>${p.service}` || hover === p.from
    return [{ key, d, color: p.from === 'internet' ? token.colorError : riskColor(e.service.risk), w: Math.min(5, 1 + Math.log10(p.count + 1)), on }]
  })

  if (!cards.length) return <Typography.Text type="secondary" style={{ display: 'block', padding: 48, textAlign: 'center' }}>{t('surfaceEmpty')}</Typography.Text>

  return (
    <div style={{ overflow: 'auto', maxHeight: 'calc(100vh - 300px)', minHeight: 420 }}>
      <div style={{ position: 'relative', width: width + 80, height: height + 20, margin: '0 auto' }}>
        {columns.map((c, i) => (
          <div key={c.kind} style={{ position: 'absolute', left: 40 + i * (CARD_W + GAP), top: 8, width: CARD_W, textAlign: 'center', fontSize: 12, letterSpacing: 2, color: token.colorTextTertiary }}>
            {t(c.key)}
          </div>
        ))}
        <svg width={width + 80} height={height + 20} style={{ position: 'absolute', left: 0, top: 0, pointerEvents: 'none' }}>
          <defs>
            <marker id="surface-arrow" viewBox="0 0 10 10" refX={9} refY={5} markerWidth={8} markerHeight={8} markerUnits="userSpaceOnUse" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill={token.colorTextTertiary} />
            </marker>
          </defs>
          <g transform="translate(40,0)">
            {lines.map(l => (
              <path key={l.key} d={l.d} fill="none" stroke={l.color} strokeWidth={l.w} strokeOpacity={l.on ? 0.75 : 0.08} markerEnd="url(#surface-arrow)" />
            ))}
          </g>
        </svg>
        {cards.map(c => {
          const left = 40 + c.box.x
          if (!c.rows.length) {
            const internet = c.peer?.kind === 'internet'
            return (
              <div key={c.id} onMouseEnter={() => setHover(c.id)} onMouseLeave={() => setHover(null)}
                style={{ position: 'absolute', left, top: c.box.y, width: c.box.w, height: PILL_H, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  borderRadius: PILL_H / 2, fontSize: 12, background: token.colorBgContainer,
                  border: `1px ${c.peer?.kind === 'discovered' ? 'dashed' : 'solid'} ${internet ? token.colorError : c.peer ? zoneColor(c.peer.zone.kind) : token.colorBorder}` }}>
                {internet && <GlobalOutlined style={{ color: token.colorError }} />}
                <span className={c.peer?.kind === 'asset' || internet ? undefined : 'mono'}>{internet ? t('mapLegendInternet') : c.label}</span>
              </div>
            )
          }
          const asset = c.rows[0]
          return (
            <div key={c.id} style={{ position: 'absolute', left, top: c.box.y, width: CARD_W, height: c.box.h, borderRadius: 16, overflow: 'hidden',
              background: token.colorBgContainer, border: `1px solid ${token.colorBorderSecondary}`, boxShadow: token.boxShadowTertiary, borderTop: `3px solid ${zoneColor(asset.zone.kind)}` }}>
              <div style={{ height: HEAD_H - 3, padding: '6px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: `1px solid ${token.colorBorderSecondary}` }}
                onMouseEnter={() => setHover(c.id)} onMouseLeave={() => setHover(null)}>
                <Link to={`/assets/${c.id}`} style={{ fontWeight: 600 }}>{c.label}</Link>
                <CritTag value={asset.criticality} />
              </div>
              {c.rows.map(e => {
                const key = `${e.assetId}>${e.proto}/${e.port}`
                const unknown = !e.service.name
                return (
                  <div key={key} role="button" tabIndex={0} onClick={() => onPick(e)} onKeyDown={ev => ev.key === 'Enter' && onPick(e)}
                    onMouseEnter={() => setHover(key)} onMouseLeave={() => setHover(null)}
                    style={{ height: ROW_H, display: 'flex', alignItems: 'center', gap: 6, padding: '0 12px', cursor: 'pointer', fontSize: 12,
                      background: hover === key ? token.colorFillTertiary : undefined, borderLeft: `3px solid ${riskColor(e.service.risk)}` }}>
                    <span className="mono" style={{ width: 70, flexShrink: 0 }}>{e.proto}/{e.port}</span>
                    <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: unknown ? token.colorWarning : undefined }}>
                      {unknown ? <><QuestionCircleOutlined /> {e.process || t('serviceUnknown')}</> : e.service.name}
                    </span>
                    {e.note && <Tooltip title={e.note.note}><Tag style={{ marginInlineEnd: 0, fontSize: 11 }} variant="filled" color={e.note.source === 'ai' ? 'purple' : 'cyan'}>{t(SOURCE_KEY[e.note.source])}</Tag></Tooltip>}
                    <Tag style={{ marginInlineEnd: 0, fontSize: 11 }} variant="filled" color={e.service.risk === 'high' ? 'red' : e.service.risk === 'medium' ? 'orange' : 'default'}>{t(RISK_KEY[e.service.risk])}</Tag>
                  </div>
                )
              })}
            </div>
          )
        })}
      </div>
    </div>
  )
}
