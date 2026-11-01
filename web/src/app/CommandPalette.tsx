import {
  AlertOutlined, CloudServerOutlined, CompassOutlined, MessageOutlined, PlayCircleOutlined, MoonOutlined, SearchOutlined, SunOutlined, SwapOutlined, TranslationOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Input, Modal, Typography, theme } from 'antd'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { fetchAgentSessions, fetchAssets, fetchIncidents } from '../api'
import { SeverityTag } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'
import { NAV, type NavItem } from './nav'
import { loadRecent } from './recent'
import { useSession } from './session'
import { useTheme } from './theme'
import { useTour } from './tour'

interface Hit {
  key: string
  section: MsgKey
  icon: ReactNode
  label: string
  extra?: ReactNode
  // 跳转目标或就地执行的操作，二选一
  to?: string
  run?: () => void
}

// 命令面板：Ctrl/⌘+K 打开，一个输入框跳到页面、主机、未结案事件、本组会话，也能切组、切主题、看导览
export function CommandPalette({ open, onClose, onHelp }: { open: boolean; onClose: () => void; onHelp: () => void }) {
  const { t, locale, setLocale } = useI18n()
  const { dark, toggle } = useTheme()
  const tour = useTour()
  const { token } = theme.useToken()
  const navigate = useNavigate()
  const { isAdmin, groups, group, setGroupId } = useSession()
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const list = useRef<HTMLDivElement>(null)
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, enabled: open })
  const incidents = useQuery({ queryKey: ['incidents', 'palette'], queryFn: () => fetchIncidents({ status: 'unresolved', limit: 200 }), enabled: open, staleTime: 30_000 })
  const sessions = useQuery({ queryKey: ['sessions', group?.id], queryFn: () => fetchAgentSessions(group!.id), enabled: open && !!group })

  const hits = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const match = (...xs: (string | null | undefined)[]) => !needle || xs.some(x => x?.toLowerCase().includes(needle))
    const groupAdmin = isAdmin || groups.some(g => g.role === 'admin')
    const pages = NAV.flatMap(n => ('items' in n ? n.items.map(i => ({ ...i, admin: i.admin || n.admin })) : [n]))
      .filter((n: NavItem) => (!n.admin || isAdmin) && (!n.groupAdmin || groupAdmin))
    const kindIcon = { incident: <AlertOutlined />, asset: <CloudServerOutlined />, session: <MessageOutlined /> }
    const out: Hit[] = [
      ...(needle ? [] : loadRecent().slice(0, 5).map(r => ({ key: r.to, section: 'paletteSectionRecent' as MsgKey, icon: kindIcon[r.kind], label: r.label, to: r.to }))),
      ...pages.filter(p => match(t(p.key), p.path)).map(p => ({
        key: p.path, section: 'paletteSectionPages' as MsgKey, icon: p.icon, label: t(p.key), to: p.path,
        extra: p.hotkey && <><kbd>G</kbd><kbd>{p.hotkey.toUpperCase()}</kbd></>,
      })),
      ...(assets.data ?? []).filter(a => needle && match(a.hostname, ...(a.ipAddrs ?? []))).slice(0, 6)
        .map(a => ({ key: a.id, section: 'paletteSectionHosts' as MsgKey, icon: <CloudServerOutlined />, label: a.hostname, extra: a.ipAddrs?.join(', '), to: `/assets/${a.id}` })),
      ...(incidents.data?.items ?? []).filter(i => needle && match(i.title, i.id)).slice(0, 6)
        .map(i => ({ key: i.id, section: 'paletteSectionIncidents' as MsgKey, icon: <AlertOutlined />, label: i.title ?? i.id, extra: <SeverityTag value={i.severity} />, to: `/incidents/${i.id}` })),
      ...(sessions.data ?? []).filter(s => needle && match(s.title)).slice(0, 5)
        .map(s => ({ key: s.id, section: 'paletteSectionSessions' as MsgKey, icon: <MessageOutlined />, label: s.title || t('chatSession'), to: `/chat/${s.id}` })),
      // 操作的标签随状态变（切暗色 / 切亮色），另配一组中英关键词让人按意图搜得到
      ...[
        ...groups.filter(g => g.id !== group?.id).map(g => ({ key: `group:${g.id}`, icon: <SwapOutlined />, label: t('paletteSwitchGroup', { name: g.name }), run: () => setGroupId(g.id) })),
        { key: 'theme', words: 'theme dark light 主题 暗色 亮色', icon: dark ? <SunOutlined /> : <MoonOutlined />, label: dark ? t('lightMode') : t('darkMode'), run: toggle },
        { key: 'language', words: 'language 语言', icon: <TranslationOutlined />, label: locale === 'zh' ? 'English' : '中文', run: () => setLocale(locale === 'zh' ? 'en' : 'zh') },
        { key: 'tour', words: 'tour guide 导览 教程 引导', icon: <CompassOutlined />, label: t('tourStart'), run: tour.start },
        { key: 'welcome', words: 'welcome intro agreement 欢迎 片头 用户协议', icon: <PlayCircleOutlined />, label: t('welcomeReplay'), run: () => navigate('/welcome') },
        { key: 'shortcuts', words: 'shortcuts keyboard 快捷键 键盘', icon: <span className="menu-kbd">?</span>, label: t('shortcutsTitle'), extra: <kbd>?</kbd>, run: onHelp },
      ].filter(a => match(a.label, 'words' in a ? a.words : '')).map(a => ({ ...a, section: 'paletteSectionActions' as MsgKey })),
    ]
    return out
  }, [q, assets.data, incidents.data, sessions.data, isAdmin, groups, group, setGroupId, dark, toggle, locale, setLocale, tour.start, onHelp, navigate, t])

  useEffect(() => setActive(0), [q])
  useEffect(() => {
    if (!open) setQ('')
  }, [open])
  useEffect(() => {
    list.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const go = (h: Hit | undefined) => {
    if (!h) return
    onClose()
    if (h.run) h.run()
    else navigate(h.to!)
  }

  return (
    <Modal open={open} onCancel={onClose} footer={null} closable={false} width={600} styles={{ container: { padding: 0, overflow: 'hidden' }, body: { padding: 0 } }} destroyOnHidden
      style={{ top: 96 }}>
      <Input
        autoFocus
        size="large"
        variant="borderless"
        className="palette-input"
        prefix={<SearchOutlined style={{ color: token.colorTextTertiary, marginRight: 4 }} />}
        suffix={<kbd>Esc</kbd>}
        placeholder={t('palettePlaceholder')}
        value={q}
        onChange={e => setQ(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'ArrowDown') { e.preventDefault(); setActive(a => Math.min(a + 1, hits.length - 1)) }
          if (e.key === 'ArrowUp') { e.preventDefault(); setActive(a => Math.max(a - 1, 0)) }
          if (e.key === 'Enter') go(hits[active])
        }}
        style={{ padding: '16px 20px', borderBottom: `1px solid ${token.colorBorderSecondary}` }}
      />
      <div ref={list} className="palette-list">
        {hits.length === 0 && <Typography.Text type="secondary" style={{ display: 'block', padding: 20, textAlign: 'center' }}>{t('noMatch')}</Typography.Text>}
        {hits.map((h, i) => (
          <div key={h.section + h.key}>
            {(i === 0 || hits[i - 1].section !== h.section) && <div className="palette-section">{t(h.section)}</div>}
            <div
              role="option"
              aria-selected={i === active}
              data-active={i === active}
              className="palette-item"
              style={i === active ? { background: token.controlItemBgActive } : undefined}
              onMouseEnter={() => setActive(i)}
              onClick={() => go(h)}
            >
              <span style={{ color: token.colorTextSecondary }}>{h.icon}</span>
              <Typography.Text ellipsis style={{ flex: 1 }}>{h.label}</Typography.Text>
              {h.extra && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{h.extra}</Typography.Text>}
            </div>
          </div>
        ))}
      </div>
      <div className="palette-foot" style={{ borderTop: `1px solid ${token.colorBorderSecondary}`, color: token.colorTextTertiary }}>
        <span><kbd>↑</kbd><kbd>↓</kbd> {t('paletteMove')}</span>
        <span><kbd>Enter</kbd> {t('paletteOpen')}</span>
        <span><kbd>Esc</kbd> {t('paletteClose')}</span>
      </div>
    </Modal>
  )
}
