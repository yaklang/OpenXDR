import { Button, Result, Spin } from 'antd'
import type { ComponentType, ReactNode } from 'react'
import { Navigate, RouterProvider, createBrowserRouter, useNavigate, useSearchParams } from 'react-router'
import { Layout } from './app/Layout'
import { SessionProvider, useMe, useSession } from './app/session'
import { useI18n } from './i18n'
import { LoadError } from './components/LoadError'
import { LoginPage } from './pages/LoginPage'
import { SetupGate } from './welcome/SetupGate'

// Webhook 里的老链接是 /?incident= 与 /?session=，进来后转到对应页面
function Home() {
  const [params] = useSearchParams()
  const incident = params.get('incident')
  const session = params.get('session')
  if (incident) return <Navigate to={`/incidents/${incident}`} replace />
  if (session) return <Navigate to={`/chat/${session}`} replace />
  return <Navigate to="/chat" replace />
}

function NotFound() {
  const { t } = useI18n()
  const navigate = useNavigate()
  return (
    <Result
      status="404"
      title="404"
      subTitle={t('notFound')}
      extra={<Button type="primary" onClick={() => navigate('/chat')}>{t('backHome')}</Button>}
    />
  )
}

function RouteError() {
  const { t } = useI18n()
  return (
    <Result status="error" title={t('pageErrorTitle')} subTitle={t('pageErrorHint')}
      extra={[
        <Button key="reload" type="primary" onClick={() => window.location.reload()}>{t('reloadPage')}</Button>,
        <Button key="home" href="/chat">{t('backHome')}</Button>,
      ]} />
  )
}

// 管理页：后端同样拦着，这里只是别让人点进一个满屏 403 的页面
function AdminOnly({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const { isAdmin } = useSession()
  return isAdmin ? children : <Result status="403" title="403" subTitle={t('adminOnly')} />
}

// 页面按路由懒加载：首屏只带外壳与登录页，其余页面进入时再取
type Pages = Record<string, ComponentType>
const page = (load: () => Promise<Pages>, name: string, admin = false) => ({
  errorElement: <RouteError />,
  lazy: async () => {
    try {
      const C = (await load())[name]
      return { Component: admin ? () => <AdminOnly><C /></AdminOnly> : C }
    } catch (error) {
      console.error('页面资源加载失败', error)
      return { Component: RouteError }
    }
  },
})

const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    errorElement: <RouteError />,
    // 首屏懒加载页面时的占位
    hydrateFallbackElement: <Spin fullscreen />,
    children: [
      { index: true, element: <Home /> },
      // 已登录再访问登录页（书签、后退）直接回首页
      { path: 'login', element: <Navigate to="/" replace /> },
      { path: 'chat', ...page(() => import('./pages/ChatPage'), 'ChatPage') },
      { path: 'chat/:sessionId', ...page(() => import('./pages/ChatPage'), 'ChatPage') },
      { path: 'overview', ...page(() => import('./pages/OverviewPage'), 'OverviewPage') },
      { path: 'incidents', ...page(() => import('./pages/IncidentsPage'), 'IncidentsPage') },
      { path: 'incidents/:id', ...page(() => import('./pages/IncidentDetailPage'), 'IncidentDetailPage') },
      { path: 'events', ...page(() => import('./pages/EventsPage'), 'EventsPage') },
      { path: 'decoys', ...page(() => import('./pages/DecoysPage'), 'DecoysPage') },
      { path: 'assets', ...page(() => import('./pages/AssetsPage'), 'AssetsPage') },
      { path: 'assets/:id', ...page(() => import('./pages/AssetDetailPage'), 'AssetDetailPage') },
      { path: 'identities', ...page(() => import('./pages/IdentitiesPage'), 'IdentitiesPage') },
      { path: 'identities/:id', ...page(() => import('./pages/IdentityDetailPage'), 'IdentityDetailPage') },
      { path: 'asset-map', ...page(() => import('./pages/AssetMapPage'), 'AssetMapPage') },
      { path: 'attack-surface', ...page(() => import('./pages/AttackSurfacePage'), 'AttackSurfacePage') },
      { path: 'reports', ...page(() => import('./pages/ReportsPage'), 'ReportsPage') },
      { path: 'tasks', ...page(() => import('./pages/TasksPage'), 'TasksPage') },
      { path: 'findings', ...page(() => import('./pages/FindingsPage'), 'FindingsPage') },
      { path: 'memories', ...page(() => import('./pages/MemoriesPage'), 'MemoriesPage') },
      { path: 'approvals', ...page(() => import('./pages/ApprovalsPage'), 'ApprovalsPage') },
      { path: 'rules', ...page(() => import('./pages/RulesPage'), 'RulesPage') },
      // ATT&CK 矩阵并入检测规则页，老链接跳到对应标签
      { path: 'attack', element: <Navigate to="/rules?tab=attack" replace /> },
      { path: 'suppressions', ...page(() => import('./pages/SuppressionsPage'), 'SuppressionsPage') },
      { path: 'trusted-sources', ...page(() => import('./pages/TrustedSourcesPage'), 'TrustedSourcesPage') },
      { path: 'intel', ...page(() => import('./pages/IntelPage'), 'IntelPage') },
      { path: 'integrations', ...page(() => import('./pages/IntegrationsPage'), 'IntegrationsPage', true) },
      { path: 'users', ...page(() => import('./pages/UsersPage'), 'UsersPage', true) },
      { path: 'groups', ...page(() => import('./pages/GroupsPage'), 'GroupsPage', true) },
      { path: 'audit', ...page(() => import('./pages/AuditPage'), 'AuditPage', true) },
      { path: 'settings', ...page(() => import('./pages/SettingsPage'), 'SettingsPage', true) },
      { path: 'welcome', ...page(() => import('./welcome/WelcomeReplay'), 'WelcomeReplay') },
      { path: '*', element: <NotFound /> },
    ],
  },
])

export default function App() {
  const { data: me, isPending, isError, error, refetch } = useMe()
  if (isPending) return <Spin fullscreen />
  if (isError) return <LoadError error={error} onRetry={() => refetch()} />
  if (!me) return <LoginPage />
  return (
    <SessionProvider me={me}>
      <SetupGate>
        <RouterProvider router={router} />
      </SetupGate>
    </SessionProvider>
  )
}
