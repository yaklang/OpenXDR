import { Typography } from 'antd'
import type { ReactNode } from 'react'

// 表格里的长文本（原因、详情、日志摘要）：最多两行，悬停看全文。
// 单行截断看不出说了什么，全部展开又让表格没法扫读
export function Clamp({ text, rows = 2, mono, children }: { text?: string | null; rows?: number; mono?: boolean; children?: ReactNode }) {
  if (!text) return <>{children ?? '-'}</>
  return (
    <Typography.Paragraph className={mono ? 'mono' : undefined} style={{ margin: 0, overflowWrap: 'anywhere', fontSize: mono ? 12.5 : undefined }}
      ellipsis={{ rows, tooltip: { title: <span style={{ whiteSpace: 'pre-wrap' }}>{text}</span>, placement: 'topLeft', styles: { root: { maxWidth: 640 } } } }}>
      {children ?? text}
    </Typography.Paragraph>
  )
}
