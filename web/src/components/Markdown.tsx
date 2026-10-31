import { Typography } from 'antd'
import { isValidElement, type ReactNode } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useI18n } from '../i18n'

function extractText(node: ReactNode): string {
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(extractText).join('')
  if (isValidElement<{ children?: ReactNode }>(node)) return extractText(node.props.children)
  return ''
}

// 模型输出不可信：react-markdown 默认不渲染原始 HTML，并过滤 javascript: 等链接；代码块采用 Gemini 风格顶栏 + 一键复制
export function Markdown({ text }: { text: string }) {
  const { t } = useI18n()
  return (
    <div className="markdown">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          table: props => <div className="markdown-table"><table {...props} /></div>,
          pre: ({ children }) => {
            const codeEl = isValidElement<{ className?: string; children?: ReactNode }>(children) ? children : null
            const langMatch = /language-([\w-]+)/.exec(codeEl?.props.className ?? '')
            const lang = langMatch?.[1] ?? 'code'
            const raw = extractText(codeEl?.props.children ?? children).replace(/\n$/, '')
            return (
              <div className="gemini-code-block">
                <div className="gemini-code-head">
                  <span className="gemini-code-lang">{lang}</span>
                  <Typography.Text type="secondary" copyable={{ text: raw, tooltips: [t('copyMessage'), t('copied')] }} style={{ fontSize: 12 }} />
                </div>
                <pre><code>{raw}</code></pre>
              </div>
            )
          },
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  )
}
