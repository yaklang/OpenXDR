import { Tag } from 'antd'
import { Link } from 'react-router'
import { controlLink } from './control'

// 事实、意图与常设规矩的编号：点开跳到总控对应条目
export function RefTag({ value }: { value: string }) {
  const color = value.startsWith('I-') ? 'purple' : value.startsWith('R-') ? 'cyan' : 'blue'
  return (
    <Link to={controlLink(value)}>
      <Tag color={color} className="mono" style={{ margin: '0 2px', fontSize: 11.5, cursor: 'pointer' }}>{value}</Tag>
    </Link>
  )
}

const REF = /\[?\b([FIR]-[0-9a-f]{8})\b\]?/g

// 研判文字里的 [F-xxxxxxxx] / [I-xxxxxxxx] 换成可点的编号，其余原样
export function RefText({ text }: { text: string }) {
  const parts = text.split(REF)
  if (parts.length === 1) return <>{text}</>
  // split 带捕获组：奇数位是编号
  return <>{parts.map((p, i) => (i % 2 ? <RefTag key={i} value={p} /> : p))}</>
}
