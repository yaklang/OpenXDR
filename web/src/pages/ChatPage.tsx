import {
  ArrowDownOutlined, ArrowUpOutlined, MenuFoldOutlined, MenuOutlined, MenuUnfoldOutlined, AlertOutlined, CloudServerOutlined, GlobalOutlined, LoginOutlined, PlusOutlined, PushpinOutlined, StopOutlined, TeamOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Col, Drawer, Empty, Flex, Grid, Input, Result, Row, Segmented, Space, Spin, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useCallback, useEffect, useRef, useState, type ReactNode, type Dispatch, type SetStateAction } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router'
import {
  createAgentSession, fetchAgentSession, fetchAgentSessions, fetchApprovals, fetchAssets, fetchSessionMessages,
  startSessionMessage, cancelSession, type AgentSession, type Approval, type PiMessage,
} from '../api'
import { useRemember } from '../app/recent'
import { useSession } from '../app/session'
import { ChatConversation, textOf, type ChatRow } from '../components/ChatConversation'
import { ApprovalActions } from '../components/ApprovalActions'
import { SubjectsBar } from '../components/Handoff'
import { GeminiSparkle } from '../components/Logo'
import { SessionStatusTag, fmtTime, errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

// 常用提问模板：Gemini 风格建议卡片，点了只是填进输入框，发不发由人决定
const TEMPLATES: { key: string; icon: ReactNode; title: MsgKey; prompt: MsgKey }[] = [
  { key: 'inspect', icon: <CloudServerOutlined />, title: 'tplInspectTitle', prompt: 'tplInspectPrompt' },
  { key: 'login', icon: <LoginOutlined />, title: 'tplLoginTitle', prompt: 'tplLoginPrompt' },
  { key: 'network', icon: <GlobalOutlined />, title: 'tplNetworkTitle', prompt: 'tplNetworkPrompt' },
  { key: 'incident', icon: <AlertOutlined />, title: 'tplIncidentTitle', prompt: 'tplIncidentPrompt' },
]

function Templates({ onPick }: { onPick: (prompt: string) => void }) {
  const { t } = useI18n()
  return (
    <Row gutter={[16, 16]} className="gemini-templates">
      {TEMPLATES.map(x => (
        <Col key={x.key} xs={24} sm={12} xl={6}>
          <div
            role="button"
            tabIndex={0}
            aria-label={t(x.title)}
            className="gemini-tpl-card"
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPick(t(x.prompt)) }
            }}
            onClick={() => onPick(t(x.prompt))}
          >
            <div className="gemini-tpl-body">
              <Typography.Text strong className="gemini-tpl-title">{t(x.title)}</Typography.Text>
              <Typography.Paragraph type="secondary" ellipsis={{ rows: 3 }} className="gemini-tpl-desc">{t(x.prompt)}</Typography.Paragraph>
            </div>
            <span className="gemini-tpl-icon">{x.icon}</span>
          </div>
        </Col>
      ))}
    </Row>
  )
}

// 对话里卡着的审批：组 admin 直接在这里批，不用跳审批中心
function InlineApprovals({ rows, hosts, onDecided }: { rows: Approval[]; hosts: Record<string, string>; onDecided: () => void }) {
  const { t } = useI18n()
  return rows.map(a => (
    <Alert
      key={a.id}
      type="warning"
      showIcon
      className="chat-indent"
      title={t('apInline', { host: hosts[a.asset_id] ?? a.asset_id })}
      description={<pre className="chat-code">{a.cmd}</pre>}
      action={
        <ApprovalActions approval={a} onDecided={onDecided} vertical />
      }
    />
  ))
}

// Gemini 双层悬浮圆角输入框：上层无边框输入区，下层工具栏左放当前组/模型胶囊、右放圆形发送按钮
function Composer({ value, onChange, onSubmit, disabled, placeholder, inputRef, meta, action }: {
  value: string
  onChange: (v: string) => void
  onSubmit: () => void
  disabled: boolean
  placeholder: string
  inputRef: { current: HTMLTextAreaElement | null }
  meta?: ReactNode
  action: ReactNode
}) {
  return (
    <div className="chat-composer">
      <Input.TextArea
        variant="borderless"
        aria-label={placeholder}
        ref={r => { inputRef.current = r?.resizableTextArea?.textArea ?? null }}
        value={value}
        disabled={disabled}
        autoSize={{ minRows: 2, maxRows: 8 }}
        placeholder={placeholder}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
            e.preventDefault()
            onSubmit()
          }
        }}
      />
      <div className="chat-composer-toolbar">
        <div className="chat-composer-chips">{meta}</div>
        <div className="chat-composer-actions">{action}</div>
      </div>
    </div>
  )
}

// AI 助手：平台主入口。左侧会话、右侧对话；会话绑定当前组
export function ChatPage() {
  const { sessionId = '' } = useParams()
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  // 会话列表的筛选跨会话保留，不随 key 重置。
  const [filter, setFilter] = useState<SessionFilter>({ search: '', kind: '' })
  const setPrompt = useCallback((value: SetStateAction<string>) => setDrafts(previous => ({
    ...previous,
    [sessionId]: typeof value === 'function' ? value(previous[sessionId] ?? '') : value,
  })), [sessionId])
  // 每段会话独立持有请求、滚动和错误状态，草稿在切换后仍保留。
  return <ChatWorkspace key={sessionId} prompt={drafts[sessionId] ?? ''} setPrompt={setPrompt} filter={filter} setFilter={setFilter} />
}

type SessionFilter = { search: string; kind: '' | 'chat' | 'task' }

function ChatWorkspace({ prompt, setPrompt, filter, setFilter }: {
  prompt: string
  setPrompt: Dispatch<SetStateAction<string>>
  filter: SessionFilter
  setFilter: Dispatch<SetStateAction<SessionFilter>>
}) {
  const { t, locale } = useI18n()
  const { me, group, setGroupId } = useSession()
  const { sessionId } = useParams()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { token } = theme.useToken()
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { search, kind } = filter
  const wide = !!Grid.useBreakpoint().lg
  const [sessionsOpen, setSessionsOpen] = useState(false)
  const [railCollapsed, setRailCollapsed] = useState(() => localStorage.getItem('chatRailCollapsed') === '1')
  const toggleRail = () => {
    const next = !railCollapsed
    localStorage.setItem('chatRailCollapsed', next ? '1' : '0')
    setRailCollapsed(next)
  }
  const log = useRef<HTMLDivElement>(null)
  const follow = useRef(true)
  const [away, setAway] = useState(false)
  const scrollLatest = () => {
    if (log.current) log.current.scrollTop = log.current.scrollHeight
    follow.current = true
    setAway(false)
  }
  const input = useRef<HTMLTextAreaElement>(null)
  const pendingAfter = useRef(0)

  const sessions = useQuery({
    queryKey: ['sessions', group?.id],
    queryFn: () => fetchAgentSessions(group!.id),
    enabled: !!group,
  })
  // 会话按 id 直接取：列表只有最近 100 个，通知与报告里的旧链接靠它才打得开；运行中轮询状态
  const current = useQuery({
    queryKey: ['session', sessionId],
    queryFn: () => fetchAgentSession(sessionId!),
    enabled: !!sessionId,
    // 运行在后台：跑着的时候勤看一眼，任何页面切回来都能看到最新进度
    refetchInterval: q => (q.state.data?.status === 'running' ? 1_500 : false),
  })
  const session = current.data
  useRemember(session?.title ? { to: `/chat/${session.id}`, label: session.title, kind: 'session' } : undefined)
  const isRunning = busy || session?.status === 'running'
  const shown = (sessions.data ?? []).filter(s =>
    (!kind || s.kind === kind) && (!search || (s.title ?? '').toLowerCase().includes(search.toLowerCase())),
  )
  // 置顶存在本地，按用户分开；其余按今天 / 昨天 / 更早分组
  const pinKey = `pinnedSessions:${me.username}`
  const [pinned, setPinned] = useState<string[]>(() => {
    try {
      const value: unknown = JSON.parse(localStorage.getItem(pinKey) ?? '[]')
      return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string') : []
    } catch { return [] }
  })
  const togglePin = (id: string) => {
    const next = pinned.includes(id) ? pinned.filter(x => x !== id) : [id, ...pinned]
    localStorage.setItem(pinKey, JSON.stringify(next))
    setPinned(next)
  }
  const dayStart = new Date().setHours(0, 0, 0, 0)
  const buckets: { key: MsgKey; items: AgentSession[] }[] = [
    { key: 'sessionsPinned', items: shown.filter(s => pinned.includes(s.id)) },
    { key: 'sessionsToday', items: shown.filter(s => !pinned.includes(s.id) && Date.parse(s.created_at) >= dayStart) },
    { key: 'sessionsYesterday', items: shown.filter(s => !pinned.includes(s.id) && Date.parse(s.created_at) < dayStart && Date.parse(s.created_at) >= dayStart - 86_400_000) },
    { key: 'sessionsEarlier', items: shown.filter(s => !pinned.includes(s.id) && Date.parse(s.created_at) < dayStart - 86_400_000) },
  ]

  // 别的标签页或定时任务正在跑时，本页没有流，靠轮询跟上
  const messages = useQuery({
    queryKey: ['messages', sessionId],
    queryFn: () => fetchSessionMessages(sessionId!).then(ms => ms.map((m): ChatRow => ({ message: m.content, at: m.created_at }))),
    enabled: !!session,
    refetchInterval: session?.status === 'running' ? 1_500 : false,
  })
  const { data: hosts = {} } = useQuery({
    queryKey: ['assets'],
    queryFn: fetchAssets,
    select: as => Object.fromEntries(as.map(a => [a.id, a.hostname])),
  })
  const isGroupAdmin = group?.role === 'admin'
  const approvals = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: !!group && isGroupAdmin && isRunning,
    refetchInterval: 2_000,
  })
  const inline = approvals.data?.filter(a => a.status === 'pending' && a.session_id === sessionId) ?? []

  // 打开别组的会话链接时跟到它的组；之后用户在顶栏换组，就回到新组的会话列表
  const synced = useRef<string | null>(null)
  useEffect(() => {
    if (!session) return
    if (synced.current !== session.id) {
      synced.current = session.id
      if (session.group_id !== group?.id) setGroupId(session.group_id)
      return
    }
    if (group && group.id !== session.group_id) navigate('/chat')
  }, [session, group, setGroupId, navigate])

  // 会话跑完（含定时任务）列表里的状态标签跟着刷新
  useEffect(() => {
    if (session && session.status !== 'running') {
      client.invalidateQueries({ queryKey: ['sessions', session.group_id] })
      client.invalidateQueries({ queryKey: ['messages', session.id] })
    }
  }, [session?.status, session?.group_id, client, session])

  // 从资产详情"一键排查"或模板进来时带 ?prompt=，填进输入框后从地址栏拿掉；
  // 「交给 AI」还带 send=1，会话就绪后直接发出去，人到了对话页 AI 已经在干活
  const [autoSend, setAutoSend] = useState<string | null>(null)
  // 欢迎页（没有会话）带 ?prompt= 时只填进输入框，发出时再建会话
  useEffect(() => {
    const p = params.get('prompt')
    if (!p || (sessionId && !session)) return
    if (session && params.get('send') === '1') setAutoSend(p)
    else {
      setPrompt(p)
      input.current?.focus()
    }
    setParams({}, { replace: true })
  }, [params, session, sessionId, setParams, setPrompt])

  // 宽屏进欢迎页（含点「新对话」）光标直接落在输入框；窄屏不弹键盘
  useEffect(() => {
    if (!sessionId && wide) input.current?.focus()
  }, [sessionId, wide])

  useEffect(() => {
    if (follow.current) scrollLatest()
  }, [messages.data, pending, inline.length])

  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const canSend = !!session && canChat && session.initiator === me.username && session.status === 'idle' && !busy
  // 停止：发起人或组管理员；只是写停止请求，后台几秒内收手
  const canStop = !!session && isRunning && (session.initiator === me.username || group?.role === 'admin')

  // 欢迎页直接提问：发出时才建会话（标题由首句生成），进会话后自动发出，不留空会话
  const startWith = async () => {
    const text = prompt.trim()
    if (!group || !canChat || !text || busy) return
    setBusy(true)
    try {
      const s = await createAgentSession({ groupId: group.id })
      setPrompt('')
      client.invalidateQueries({ queryKey: ['sessions', group.id] })
      navigate(`/chat/${s.id}?${new URLSearchParams({ prompt: text, send: '1' })}`)
    } catch (e) {
      message.error(errText(e, t))
      setBusy(false)
    }
  }

  // 发出去就交给后台：会话切到 running 后由轮询跟进度，离开页面不影响
  const submit = async (override?: string) => {
    const text = (override ?? prompt).trim()
    if (!session || !text || !canSend) return
    follow.current = true
    setBusy(true)
    setError(null)
    pendingAfter.current = messages.data?.length ?? 0
    setPending(text)
    try {
      await startSessionMessage(session.id, text)
      if (override === undefined) setPrompt(value => value.trim() === text ? '' : value)
    } catch (e) {
      setError(errText(e, t))
      setPending(null)
    } finally {
      await client.invalidateQueries({ queryKey: ['session', session.id] })
      client.invalidateQueries({ queryKey: ['sessions', group?.id] })
      setBusy(false)
    }
  }

  const stop = async () => {
    if (!session) return
    try {
      await cancelSession(session.id)
      message.info(t('stopRequested'))
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  // 会话可发言了就把「交给 AI」带来的第一句发出去，只发一次
  useEffect(() => {
    if (!autoSend || !canSend) return
    setAutoSend(null)
    void submit(autoSend)
  }, [autoSend, canSend]) // eslint-disable-line react-hooks/exhaustive-deps

  const history = messages.data ?? []
  // 首条 user 消息入库前先占位，避免发出去的话"消失"一下
  const showPending = pending && !history.slice(pendingAfter.current).some(r => r.message.role === 'user' && textOf(r.message.content) === pending)
  const rows: ChatRow[] = [
    ...history,
    ...(showPending ? [{ message: { role: 'user', content: pending } as PiMessage }] : []),
  ]

  if (!group) {
    return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  }

  const composerChips = (
    <>
      <span className="gemini-context-chip"><TeamOutlined /> {group.name}</span>
      <span className="gemini-context-chip"><GeminiSparkle size={13} /> {session?.model || 'Pi Agent'}</span>
    </>
  )

  const sessionList = (
    <aside className="chat-sessions" aria-label={t('sessions')}>
      <div className="chat-sessions-top">
        {canChat ? (
          <Button type="primary" shape="round" icon={<PlusOutlined />} className="gemini-new-chat-btn" onClick={() => { navigate('/chat'); setSessionsOpen(false) }}>
            {t('newChat')}
          </Button>
        ) : <Typography.Text strong>{t('sessions')}</Typography.Text>}
        {wide && (
          <Tooltip title={t('sessions')}>
            <Button type="text" shape="circle" size="small" icon={<MenuFoldOutlined />} aria-label={t('sessions')} onClick={toggleRail} />
          </Tooltip>
        )}
      </div>
      <div className="chat-session-filter">
        <Input.Search size="small" variant="filled" allowClear value={search} placeholder={t('searchSessions')} onChange={e => setFilter(f => ({ ...f, search: e.target.value }))} />
        <Segmented size="small" block value={kind} onChange={v => setFilter(f => ({ ...f, kind: v as SessionFilter['kind'] }))}
          options={[{ value: '', label: t('all') }, { value: 'chat', label: t('chatSession') }, { value: 'task', label: t('taskSession') }]} />
      </div>
      <div className="chat-session-scroll">
        {sessions.isError && <Alert type="error" showIcon title={errText(sessions.error, t)} />}
        {sessions.isPending && <Spin style={{ display: 'block', margin: 24 }} />}
        {sessions.data && shown.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noSessions')} />}
        {buckets.filter(b => b.items.length).map(b => (
          <div key={b.key}>
            <div className="chat-session-bucket">{t(b.key)}</div>
            {b.items.map(s => {
              const status = s.id === sessionId && isRunning ? 'running' : s.status
              return (
                <div key={s.id} className={s.id === sessionId ? 'chat-session-entry active' : 'chat-session-entry'}>
                  <button
                    type="button"
                    aria-current={s.id === sessionId ? 'page' : undefined}
                    className="chat-session-item"
                    onClick={() => { navigate(`/chat/${s.id}`); setSessionsOpen(false) }}
                  >
                    <Flex align="center" gap={8}>
                      <span className={`session-status-dot status-${status}`} aria-hidden />
                      <Typography.Text ellipsis strong={s.id === sessionId} style={{ flex: 1, fontSize: 13.5 }}>
                        {s.title || t(s.kind === 'task' ? 'taskSession' : 'chatSession')}
                      </Typography.Text>
                      <Typography.Text type="secondary" style={{ fontSize: 11, flex: 'none' }}>
                        {fmtTime(s.created_at).slice(b.key === 'sessionsEarlier' || b.key === 'sessionsPinned' ? 5 : 11, 16)}
                      </Typography.Text>
                    </Flex>
                    {s.kind === 'task' && (
                      <div style={{ paddingLeft: 16, marginTop: 2 }}>
                        <Tag style={{ fontSize: 11, lineHeight: '16px', paddingInline: 6 }}>{t('taskSession')}</Tag>
                      </div>
                    )}
                  </button>
                  <Tooltip title={t(pinned.includes(s.id) ? 'unpin' : 'pin')}>
                    <button type="button" aria-label={t(pinned.includes(s.id) ? 'unpin' : 'pin')}
                      className={pinned.includes(s.id) ? 'session-pin pinned' : 'session-pin'}
                      onClick={() => togglePin(s.id)}>
                      <PushpinOutlined />
                    </button>
                  </Tooltip>
                </div>
              )
            })}
          </div>
        ))}
      </div>
    </aside>
  )

  return (
    <div className="chat-page">
      {wide ? (!railCollapsed && sessionList) : <Drawer title={t('sessions')} open={sessionsOpen} onClose={() => setSessionsOpen(false)} placement="left" size={308} styles={{ body: { padding: 0, display: 'flex' } }}>{sessionList}</Drawer>}

      <section className="chat-main">
        {(session || !wide || railCollapsed) && (
          <header className="chat-main-topbar">
            <Space style={{ minWidth: 0 }}>
              {(!wide || railCollapsed) && (
                <Tooltip title={t('sessions')}>
                  <Button type="text" shape="circle" icon={wide ? <MenuUnfoldOutlined /> : <MenuOutlined />} aria-label={t('sessions')} onClick={() => (wide ? toggleRail() : setSessionsOpen(true))} />
                </Tooltip>
              )}
              {(!wide || railCollapsed) && canChat && (
                <Tooltip title={t('newChat')}>
                  <Button type="text" shape="circle" icon={<PlusOutlined />} aria-label={t('newChat')} onClick={() => navigate('/chat')} />
                </Tooltip>
              )}
              {session && (
                <Space size={8} style={{ minWidth: 0 }}>
                  <GeminiSparkle size={18} active={isRunning} />
                  <Typography.Text strong ellipsis style={{ fontSize: 15 }}>{session.title || t('chatSession')}</Typography.Text>
                  <SessionStatusTag value={isRunning ? 'running' : session.status} />
                </Space>
              )}
            </Space>
            {wide && session && (
              <span className="gemini-model-pill">{session.initiator} · {session.model}</span>
            )}
          </header>
        )}

        {sessionId && current.isError ? (
          <Result status="warning" title={t('sessionGone')} subTitle={errText(current.error, t)} extra={<Button shape="round" onClick={() => navigate('/chat')}>{t('backToList')}</Button>} />
        ) : sessionId && !session ? <Spin style={{ margin: 'auto' }} /> : !session ? (
          <Flex vertical justify="center" gap={32} className="chat-welcome">
            <div className="gemini-hero-head">
              <div className="gemini-greeting-row">
                <GeminiSparkle size={38} active={busy} />
                <Typography.Title level={1} className="gemini-greeting-title">
                  {locale === 'zh' ? `你好，${me.username}` : `Hello, ${me.username}`}
                </Typography.Title>
              </div>
              <div className="gemini-greeting-sub">{t('welcomeTitle')}</div>
            </div>
            {canChat ? (
              <>
                <div className="welcome-composer">
                  <Composer value={prompt} onChange={setPrompt} onSubmit={startWith} disabled={busy} placeholder={t('chatPlaceholder')} inputRef={input}
                    meta={composerChips}
                    action={
                      <Button type="primary" shape="circle" size="large" className="gemini-send-btn" icon={<ArrowUpOutlined />} aria-label={t('send')} loading={busy} disabled={!prompt.trim()} onClick={startWith} />
                    } />
                </div>
                <Templates onPick={p => { setPrompt(p); input.current?.focus() }} />
                <Typography.Text type="secondary" className="welcome-hint">{t('sessionExecHint')}</Typography.Text>
              </>
            ) : <Alert type="info" showIcon title={t('chatReadonly')} />}
          </Flex>
        ) : (
          <>
            {!!session.subjects?.length && <SubjectsBar subjects={session.subjects} groupId={session.group_id} />}
            <div className="chat-log" ref={log} onScroll={e => {
              const el = e.currentTarget
              follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80
              setAway(!follow.current)
            }}>
              <div className="chat-stream-inner">
                {messages.isPending && <Spin />}
                {messages.isError && <Alert type="error" showIcon title={errText(messages.error, t)} />}
                {messages.isSuccess && rows.length === 0 && canSend && (
                  <Flex vertical gap={24} className="chat-welcome">
                    <div className="gemini-hero-head">
                      <div className="gemini-greeting-row">
                        <GeminiSparkle size={32} />
                        <Typography.Title level={2} className="gemini-greeting-title">{t('welcomeTitle')}</Typography.Title>
                      </div>
                      <div className="gemini-greeting-sub">{t('templatesHint')}</div>
                    </div>
                    <Templates onPick={p => { setPrompt(p); input.current?.focus() }} />
                  </Flex>
                )}
                <ChatConversation rows={rows} hosts={hosts} />
                <InlineApprovals rows={inline} hosts={hosts} onDecided={() => approvals.refetch()} />
                {isRunning && !isGroupAdmin && <Alert className="chat-indent" type="info" showIcon title={t('chatNeedsApprover')} />}
                {isRunning && (
                  <div className="chat-indent gemini-thinking">
                    <Space size={10} style={{ color: token.colorTextSecondary }}>
                      <GeminiSparkle size={20} active />
                      <span>{t('thinking')}</span>
                    </Space>
                    <div className="gemini-shimmer" aria-hidden>
                      <span className="gemini-shimmer-bar" style={{ width: '72%' }} />
                      <span className="gemini-shimmer-bar" style={{ width: '48%' }} />
                    </div>
                  </div>
                )}
                {session.error && <Alert className="chat-indent" type={session.status === 'succeeded' ? 'warning' : 'error'} showIcon title={session.error} />}
                {error && <Alert className="chat-indent" type="error" showIcon title={error} />}
              </div>
            </div>
            {away && <Button className="chat-latest" shape="round" size="small" icon={<ArrowDownOutlined />} onClick={scrollLatest}>{t('backToLatest')}</Button>}
            <div className="chat-composer-bar">
              <div className="welcome-composer chat-session-composer">
                <Composer value={prompt} onChange={setPrompt} onSubmit={() => submit()} disabled={!canSend} inputRef={input}
                  placeholder={canSend ? t('chatPlaceholder') : isRunning ? t('runningInBackground') : t('chatReadonly')}
                  meta={composerChips}
                  action={canStop
                    ? <Button danger shape="circle" size="large" className="gemini-send-btn" icon={<StopOutlined />} aria-label={t('stop')} onClick={stop} />
                    : <Button type="primary" shape="circle" size="large" className="gemini-send-btn" icon={<ArrowUpOutlined />} aria-label={t('send')} disabled={!canSend || !prompt.trim()} onClick={() => submit()} />} />
              </div>
            </div>
          </>
        )}
      </section>

    </div>
  )
}
