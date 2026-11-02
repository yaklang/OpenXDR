import {
  CheckCircleFilled, CloseCircleFilled, CodeOutlined, DownOutlined, ExportOutlined, FilePdfOutlined, FileTextOutlined, LoadingOutlined,
  RightOutlined, ToolOutlined,
} from '@ant-design/icons'
import { Alert, App, Button, Collapse, Drawer, Flex, Space, Timeline, Typography, theme } from 'antd'
import { useState } from 'react'
import { downloadAgentPdf, reportHtmlUrl, type AgentReport, type ContentPart, type PiMessage } from '../api'
import { useI18n } from '../i18n'
import { GeminiSparkle } from './Logo'
import { Markdown } from './Markdown'
import { fmtTime, errText } from './format'

export interface ChatRow {
  message: PiMessage
  at?: string
}

type ToolResult = Extract<PiMessage, { role: 'toolResult' }>
type ToolCallPart = Extract<ContentPart, { type: 'toolCall' }>

export const textOf = (content: string | ContentPart[]) =>
  typeof content === 'string' ? content : content.map(p => (p.type === 'text' ? p.text : '')).join('')

// report 工具返回 {"reportId", "title"}，拿到 id 才能给 HTML / PDF
function reportIdOf(r?: ToolResult) {
  try {
    return (JSON.parse(textOf(r?.content ?? '')) as { reportId?: string }).reportId
  } catch {
    return undefined
  }
}

function ReportDrawer({ call, result, onClose }: { call: ToolCallPart | null; result?: ToolResult; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const id = reportIdOf(result)
  const title = String(call?.arguments.title ?? '')
  return (
    <Drawer size={760} open={!!call} title={title} onClose={onClose}
      extra={id && (
        <Space>
          <Button icon={<ExportOutlined />} onClick={() => window.open(reportHtmlUrl(id), '_blank', 'noopener')}>HTML</Button>
          <Button icon={<FilePdfOutlined />} onClick={() => downloadAgentPdf({ id, title } as AgentReport).catch(e => message.error(errText(e, t)))}>PDF</Button>
        </Space>
      )}>
      {call && <Markdown text={String(call.arguments.markdown ?? '')} />}
    </Drawer>
  )
}

// 执行链（Gemini 折叠思维链风格）：顶部胶囊条可一键收起/展开，运行中自动展开，步骤结果就地折叠
function ExecChain({ calls, results, hosts, onPreview }: {
  calls: ToolCallPart[]
  results: Map<string, ToolResult>
  hosts: Record<string, string>
  onPreview: (c: ToolCallPart) => void
}) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const [all, setAll] = useState(false)
  const done = calls.filter(c => results.has(c.id)).length
  const running = done < calls.length
  const [expanded, setExpanded] = useState(true)
  const open = running || expanded
  // 一轮几十步时只露最后几步，前面的折起来，点开再看
  const FOLD = 6
  const hidden = all ? 0 : Math.max(0, calls.length - FOLD)
  return (
    <div className={open ? 'chat-chain gemini-chain-open' : 'chat-chain gemini-chain-collapsed'}>
      <button
        type="button"
        className="gemini-chain-toggle"
        aria-expanded={open}
        onClick={() => setExpanded(e => !e)}
      >
        <Space size={8}>
          {running ? <GeminiSparkle size={16} active /> : <ToolOutlined style={{ color: token.colorPrimary }} />}
          <span className="gemini-chain-label">{t('execChain', { done, n: calls.length })}</span>
        </Space>
        <span className="gemini-chain-chevron">{open ? <DownOutlined /> : <RightOutlined />}</span>
      </button>
      {open && (
        <div className="gemini-chain-body">
          {hidden > 0 && <Button type="link" size="small" style={{ padding: 0, marginBottom: 8 }} onClick={() => setAll(true)}>{t('showEarlierSteps', { n: hidden })}</Button>}
          <Timeline
            items={calls.slice(hidden).map(c => {
              const r = results.get(c.id)
              const icon = !r ? <LoadingOutlined style={{ color: token.colorPrimary }} />
                : r.isError ? <CloseCircleFilled style={{ color: token.colorError }} />
                  : <CheckCircleFilled style={{ color: token.colorSuccess }} />
              const host = String(c.arguments.host ?? '')
              const title = c.name === 'exec' ? t('toolExec', { host: hosts[host] ?? host })
                : c.name === 'report' ? t('toolReport', { title: String(c.arguments.title ?? '') })
                  : c.name === 'query' ? t('toolQuery')
                    : c.name === 'track' ? t(c.arguments.status === 'resolved' ? 'toolTrackResolved' : c.arguments.status === 'withdrawn' ? 'toolTrackWithdrawn' : 'toolTrackOpen',
                      { title: String(c.arguments.title ?? ''), host: hosts[host] ?? host })
                      : t('toolCall', { name: c.name })
              return {
                key: c.id,
                icon,
                content: (
                  <div className="chat-step">
                    <Space size={6} wrap>
                      <span className="gemini-step-chip">
                        {c.name === 'report' ? <FileTextOutlined /> : <CodeOutlined />}
                        <span>{c.name}</span>
                      </span>
                      <Typography.Text strong>{title}</Typography.Text>
                      {!r && <Typography.Text type="secondary">{t(c.name === 'exec' ? 'stepWaitingExec' : 'stepRunning')}</Typography.Text>}
                    </Space>
                    {c.name === 'exec' && <pre className="chat-code">{String(c.arguments.cmd ?? '')}</pre>}
                    {c.name === 'query' && <pre className="chat-code">{String(c.arguments.sql ?? '')}</pre>}
                    {c.name === 'track' && !!c.arguments.detail && <Typography.Paragraph type="secondary" style={{ margin: '4px 0 0', fontSize: 13 }}>{String(c.arguments.detail)}</Typography.Paragraph>}
                    {!['exec', 'report', 'query', 'track'].includes(c.name) && <pre className="chat-code">{JSON.stringify(c.arguments, null, 2)}</pre>}
                    {c.name === 'report' && <Button size="small" shape="round" icon={<FileTextOutlined />} onClick={() => onPreview(c)} style={{ marginTop: 6 }}>{t('previewReport')}</Button>}
                    {r && c.name !== 'report' && (
                      <Collapse ghost size="small" className="chat-step-out"
                        items={[{ key: 'o', label: t(r.isError ? 'stepFailedOutput' : 'stepOutput'), children: <pre className="chat-code">{textOf(r.content) || t('emptyOutput')}</pre> }]} />
                    )}
                  </div>
                ),
              }
            })}
          />
        </div>
      )}
    </div>
  )
}

function Meta({ at, text }: { at?: string; text?: string }) {
  const { t } = useI18n()
  return <Space size={10} wrap className="chat-meta">
    {text && <Typography.Text type="secondary" copyable={{ text, tooltips: [t('copyMessage'), t('copied')] }} />}
    {at && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(at)}</Typography.Text>}
  </Space>
}

// 会话渲染（Gemini 风格）：user 右侧柔和胶囊气泡；assistant 左侧四芒星图标 + 无边框画布级 Markdown + 本轮执行链
export function ChatConversation({ rows, hosts }: { rows: ChatRow[]; hosts: Record<string, string> }) {
  const { t } = useI18n()
  const [preview, setPreview] = useState<ToolCallPart | null>(null)
  const results = new Map<string, ToolResult>()
  for (const { message } of rows) if (message.role === 'toolResult') results.set(message.toolCallId, message)

  return (
    <>
      {rows.map(({ message: m, at }, i) => {
        if (m.role === 'toolResult') return null
        if (m.role === 'user') {
          return (
            <Flex key={i} justify="flex-end" className="chat-row chat-row-user">
              <Flex vertical align="flex-end" style={{ maxWidth: '78%' }}>
                <div className="chat-bubble chat-bubble-user">{textOf(m.content)}</div>
                <Meta at={at} text={textOf(m.content)} />
              </Flex>
            </Flex>
          )
        }
        const texts = m.content.filter((p): p is Extract<ContentPart, { type: 'text' }> => p.type === 'text' && !!p.text)
        const calls = m.content.filter((p): p is ToolCallPart => p.type === 'toolCall')
        return (
          <Flex key={i} gap={16} className="chat-row chat-row-assistant">
            <div className="gemini-avatar"><GeminiSparkle size={22} /></div>
            <Flex vertical gap={12} style={{ minWidth: 0, flex: 1 }}>
              {texts.map((p, j) => (
                <div key={j} className="chat-bubble chat-bubble-assistant"><Markdown text={p.text} /></div>
              ))}
              {calls.length > 0 && <ExecChain calls={calls} results={results} hosts={hosts} onPreview={setPreview} />}
              {m.errorMessage && <Alert type="error" showIcon title={m.errorMessage} />}
              {(m.stopReason === 'length' || m.stopReason === 'max_turns') && <Alert type="warning" showIcon title={t('chatTruncated')} />}
              <Meta at={at} text={texts.map(p => p.text).join('\n\n')} />
            </Flex>
          </Flex>
        )
      })}
      <ReportDrawer call={preview} result={preview ? results.get(preview.id) : undefined} onClose={() => setPreview(null)} />
    </>
  )
}
