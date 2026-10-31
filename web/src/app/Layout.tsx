import {
  BellOutlined, CheckCircleOutlined, CheckOutlined, CompassOutlined, LogoutOutlined, PlayCircleOutlined, MenuFoldOutlined, MenuUnfoldOutlined, MoonOutlined, SearchOutlined, SunOutlined, TeamOutlined,
  TranslationOutlined, UserOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { App, Avatar, Badge, Button, Drawer, Dropdown, Grid, Layout as AntLayout, Menu, Select, Tag, Tooltip, theme } from 'antd'
import type { MenuProps } from 'antd'
import { useEffect, useRef, useState } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router'
import { fetchAgentReports, fetchApprovals, fetchFindingsPage, fetchStats, fetchSuppressions } from '../api'
import { errText, ROLE_KEY } from '../components/format'
import { useI18n } from '../i18n'
import { Logo } from '../components/Logo'
import { CommandPalette } from './CommandPalette'
import { NAV, crumbsOf, type NavItem } from './nav'
import { useSession } from './session'
import { ShortcutHelp, useGlobalKeys } from './shortcuts'
import { useTheme, type ThemeMode } from './theme'
import { TourProvider, useTour } from './tour'

// 菜单上的待办计数：与态势总览共用同一份查询缓存，不额外打接口
function useNavCounts(): Record<string, number | undefined> {
  const { group } = useSession()
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 30_000 })
  const findings = useQuery({ queryKey: ['findings', 'count', 'open'], queryFn: () => fetchFindingsPage({ status: 'open', limit: 1 }), refetchInterval: 60_000 })
  const approvals = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: group?.role === 'admin',
    refetchInterval: 10_000,
  })
  const suppressions = useQuery({ queryKey: ['suppressions'], queryFn: fetchSuppressions, refetchInterval: 60_000 })
  // 未读报告：只算需要处理的，「无异常」只存档的不催
  const reports = useQuery({ queryKey: ['reports', group?.id], queryFn: () => fetchAgentReports(group!.id), enabled: !!group, refetchInterval: 30_000 })
  return {
    '/reports': reports.data?.filter(r => !r.read && r.level !== 'ok').length || undefined,
    '/suppressions': suppressions.data?.filter(s => s.status === 'proposed').length || undefined,
    '/incidents': stats.data?.reviewIncidents,
    '/findings': findings.data?.total,
    '/approvals': approvals.data?.filter(a => a.status === 'pending').length,
  }
}

// 桌面通知：用户在账号菜单里自己开。标签页不在前台时，待复核事件或待审批变多就弹系统通知，点一下回到对应页面
const notifySupported = 'Notification' in window
const notifyOn = () => notifySupported && localStorage.getItem('desktopNotify') === '1' && Notification.permission === 'granted'

function useDesktopAlerts(counts: Record<string, number | undefined>) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const last = useRef(counts)
  useEffect(() => {
    const prev = last.current
    last.current = counts
    if (!notifyOn() || !document.hidden) return
    const rose = (path: string) => prev[path] !== undefined && (counts[path] ?? 0) > prev[path]!
    const fire = (title: string, to: string) => {
      const n = new Notification(title, { icon: '/favicon.svg', tag: to })
      n.onclick = () => { window.focus(); navigate(to); n.close() }
    }
    if (rose('/incidents')) fire(t('notifyReview', { n: counts['/incidents']! }), '/incidents')
    if (rose('/approvals')) fire(t('notifyApprovals', { n: counts['/approvals']! }), '/approvals')
  })
}

// 待审批数：只有组 admin 能看审批，Pi 正阻塞等着人，所以挂在顶栏
function ApprovalBell() {
  const { t } = useI18n()
  const { group } = useSession()
  const navigate = useNavigate()
  const isGroupAdmin = group?.role === 'admin'
  const { data } = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: !!group && isGroupAdmin,
    refetchInterval: 10_000,
  })
  if (!isGroupAdmin) return null
  const pending = data?.filter(a => a.status === 'pending').length ?? 0
  return (
    <Tooltip title={t('pendingApprovals', { n: pending })}>
      <Badge count={pending} size="small">
        <Button type="text" aria-label={t('pendingApprovals', { n: pending })} icon={<CheckCircleOutlined />} onClick={() => navigate('/approvals')} />
      </Badge>
    </Tooltip>
  )
}

// 侧栏底部的账号入口：主题、语言、退出收在一个菜单里，顶栏只留搜索与待办
function UserMenu({ compact, onHelp }: { compact: boolean; onHelp: () => void }) {
  const { t, locale, setLocale } = useI18n()
  const { dark, mode, setMode } = useTheme()
  const { me, signOut } = useSession()
  const { token } = theme.useToken()
  const { message } = App.useApp()
  const navigate = useNavigate()
  const tour = useTour()
  const [notify, setNotify] = useState(notifyOn)
  const toggleNotify = async () => {
    if (notify) {
      localStorage.setItem('desktopNotify', '0')
      setNotify(false)
    } else if (await Notification.requestPermission() === 'granted') {
      localStorage.setItem('desktopNotify', '1')
      setNotify(true)
    } else message.warning(t('notifyDenied'))
  }
  return (
    <Dropdown
      trigger={['click']}
      placement="topLeft"
      menu={{
        items: [
          {
            key: 'theme', icon: dark ? <MoonOutlined /> : <SunOutlined />, label: t('appearance'),
            children: (['system', 'light', 'dark'] as const).map(m => ({
              key: `mode:${m}`, label: t(m === 'system' ? 'modeSystem' : m === 'light' ? 'modeLight' : 'modeDark'),
              icon: mode === m ? <CheckOutlined /> : <span style={{ display: 'inline-block', width: 14 }} />,
            })),
          },
          { key: 'language', icon: <TranslationOutlined />, label: locale === 'zh' ? 'English' : '中文' },
          ...(notifySupported ? [{ key: 'notify', icon: <BellOutlined />, label: t(notify ? 'desktopNotifyOff' : 'desktopNotifyOn') }] : []),
          { type: 'divider' },
          { key: 'tour', icon: <CompassOutlined />, label: t('tourStart') },
          { key: 'welcome', icon: <PlayCircleOutlined />, label: t('welcomeReplay') },
          { key: 'shortcuts', icon: <span className="menu-kbd">?</span>, label: t('shortcutsTitle') },
          { type: 'divider' },
          { key: 'logout', icon: <LogoutOutlined />, label: t('logout') },
        ],
        onClick: ({ key }) => {
          if (key.startsWith('mode:')) setMode(key.slice(5) as ThemeMode)
          else if (key === 'language') setLocale(locale === 'zh' ? 'en' : 'zh')
          else if (key === 'notify') void toggleNotify()
          else if (key === 'tour') tour.start()
          else if (key === 'welcome') navigate('/welcome')
          else if (key === 'shortcuts') onHelp()
          else if (key === 'logout') void signOut().catch(error => message.error(errText(error, t)))
        },
      }}
    >
      <button type="button" className="sider-user" aria-label={me.username}>
        <Avatar size={28} icon={<UserOutlined />} style={{ background: token.colorPrimary, flex: 'none' }} />
        {!compact && <span className="sider-user-name">{me.username}</span>}
        {!compact && <Tag variant="filled" style={{ marginInlineEnd: 0 }}>{t(ROLE_KEY[me.role])}</Tag>}
      </button>
    </Dropdown>
  )
}

export function Layout() {
  return <TourProvider><Shell /></TourProvider>
}

function Shell() {
  const { t } = useI18n()
  const { isAdmin, groups, group, setGroupId } = useSession()
  const { dark, toggle: toggleTheme } = useTheme()
  const { token } = theme.useToken()
  const wide = !!Grid.useBreakpoint().lg
  const [menuOpen, setMenuOpen] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('siderCollapsed') === '1')
  const [palette, setPalette] = useState(false)
  const [help, setHelp] = useState(false)
  const counts = useNavCounts()
  useDesktopAlerts(counts)
  const mac = /Mac|iPhone|iPad/.test(navigator.platform)
  const compact = collapsed && wide

  // Ctrl/⌘+K 在任何页面打开命令面板
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPalette(p => !p)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // 标签页标题带上待复核数，切到别的标签也能看到有没有新事
  const pageKey = crumbsOf(location.pathname).page?.key
  const review = counts['/incidents']
  useEffect(() => {
    document.title = `${review ? `(${review}) ` : ''}${pageKey ? `${t(pageKey)} · ` : ''}OpenXDR`
  }, [review, pageKey, t])

  const isGroupAdmin = isAdmin || groups.some(g => g.role === 'admin')
  const visible = (x: { admin?: boolean; groupAdmin?: boolean }) => (!x.admin || isAdmin) && (!x.groupAdmin || isGroupAdmin)
  const toItem = (n: NavItem) => ({
    key: n.path,
    icon: n.icon,
    label: <span className="nav-label" data-tour={n.path}>{t(n.key)}{!!counts[n.path] && <span className="nav-count">{counts[n.path]}</span>}</span>,
  })
  // 收起时分组标题挤不下，换成分隔线
  type Item = NonNullable<MenuProps['items']>[number]
  const items: Item[] = NAV.filter(visible).flatMap((n): Item[] =>
    !('items' in n)
      ? [toItem(n)]
      : compact
        ? [{ type: 'divider' as const, key: n.key }, ...n.items.filter(visible).map(toItem)]
        : [{ type: 'group' as const, key: n.key, label: t(n.key), children: n.items.filter(visible).map(toItem) }],
  )
  const selected = '/' + location.pathname.split('/')[1]

  const collapse = () => {
    localStorage.setItem('siderCollapsed', collapsed ? '0' : '1')
    setCollapsed(!collapsed)
  }
  useGlobalKeys({ palette: () => setPalette(true), help: () => setHelp(true), sider: wide ? collapse : () => setMenuOpen(o => !o) })

  // 收起的侧栏放不下组切换，挪到顶栏
  const groupSelect = (
    <Select
      aria-label={t('currentGroup')}
      showSearch
      optionFilterProp="label"
      style={{ width: compact ? 200 : '100%' }}
      prefix={<TeamOutlined style={{ color: token.colorTextTertiary }} />}
      value={group?.id}
      placeholder={t('noGroups')}
      onChange={setGroupId}
      options={groups.map(g => ({ value: g.id, label: g.name }))}
      notFoundContent={t('noGroups')}
    />
  )

  // 宽屏侧栏与窄屏抽屉共用同一份内容：品牌、组切换、菜单、账号（参照 Vercel / Linear 的工作区侧栏）
  const sider = (
    <nav className="sider" aria-label={t('navigation')}>
      <Link className="brand" to="/chat" aria-label="OpenXDR">
        <Logo />{!compact && <span className="brand-name">OpenXDR</span>}
      </Link>
      {!compact && <div className="sider-group app-group">{groupSelect}</div>}
      <Menu className="sider-menu" mode="inline" inlineIndent={12} selectedKeys={[selected]} items={items}
        onClick={e => { navigate(e.key); setMenuOpen(false) }} />
      <div className="sider-foot"><UserMenu compact={compact} onHelp={() => setHelp(true)} /></div>
    </nav>
  )

  const isChat = selected === '/chat'

  return (
    <AntLayout className="app-shell" style={{ minHeight: '100vh' }}>
      {wide ? (
        <AntLayout.Sider theme="light" width={240} collapsedWidth={68} collapsed={collapsed} className="app-sider">
          {sider}
        </AntLayout.Sider>
      ) : (
        <Drawer placement="left" size={272} closable={false} open={menuOpen} onClose={() => setMenuOpen(false)} styles={{ body: { padding: 0 } }}>
          {sider}
        </Drawer>
      )}
      <AntLayout className="app-main-wrap" style={{ minWidth: 0 }}>
        <AntLayout.Header className="app-header">
          <Button type="text" shape="circle" aria-label={t('navigation')} aria-expanded={wide ? !collapsed : menuOpen} icon={collapsed || !wide ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={wide ? collapse : () => setMenuOpen(true)} />
          {!wide && <Link to="/chat" aria-label="OpenXDR" style={{ display: 'flex' }}><Logo size={24} /></Link>}
          {compact && <div className="app-group">{groupSelect}</div>}
          <div style={{ flex: 1 }} />
          {wide ? (
            <Button className="search-trigger app-search" icon={<SearchOutlined />} onClick={() => setPalette(true)}>
              <span>{t('paletteTrigger')}</span><kbd>{mac ? '⌘' : 'Ctrl'} K</kbd>
            </Button>
          ) : <Button type="text" shape="circle" className="app-search" aria-label={t('paletteTrigger')} icon={<SearchOutlined />} onClick={() => setPalette(true)} />}
          <Tooltip title={dark ? t('lightMode') : t('darkMode')}>
            <Button type="text" shape="circle" aria-label={dark ? t('lightMode') : t('darkMode')} icon={dark ? <SunOutlined /> : <MoonOutlined />} onClick={toggleTheme} />
          </Tooltip>
          <ApprovalBell />
        </AntLayout.Header>
        <AntLayout.Content className={isChat ? 'app-content app-content-chat' : 'app-content'}>
          <Outlet />
        </AntLayout.Content>
        <CommandPalette open={palette} onClose={() => setPalette(false)} onHelp={() => setHelp(true)} />
        <ShortcutHelp open={help} onClose={() => setHelp(false)} />
      </AntLayout>
    </AntLayout>
  )
}
