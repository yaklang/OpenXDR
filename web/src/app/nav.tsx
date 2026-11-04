import {
  AimOutlined, AlertOutlined, AuditOutlined, BulbOutlined, CheckCircleOutlined, ClockCircleOutlined, CloudServerOutlined, DashboardOutlined, DeploymentUnitOutlined, FileSearchOutlined, FileTextOutlined, IdcardOutlined, RobotOutlined, SafetyCertificateOutlined, SafetyOutlined, SearchOutlined, SettingOutlined, StopOutlined, TeamOutlined, ThunderboltOutlined, ToolOutlined, UserOutlined,
} from '@ant-design/icons'
import type { ReactNode } from 'react'
import type { MsgKey } from '../i18n'

export interface NavItem {
  path: string
  key: MsgKey
  icon: ReactNode
  admin?: boolean
  // 只有某个组的 admin 才用得上（审批只给组 admin）
  groupAdmin?: boolean
  // G 之后按这个键跳过来（GitHub / Linear 的两段式快捷键）
  hotkey?: string
}

export interface NavGroup {
  key: MsgKey
  items: NavItem[]
  admin?: boolean
}

// 菜单即信息架构：对话是主入口，原有能力按运营动线归组；面包屑也从这里推
export const NAV: (NavItem | NavGroup)[] = [
  { path: '/chat', key: 'navChat', icon: <RobotOutlined />, hotkey: 'c' },
  { path: '/overview', key: 'navOverview', icon: <DashboardOutlined />, hotkey: 'o' },
  {
    key: 'navGroupOps',
    items: [
      { path: '/incidents', key: 'navIncidents', icon: <AlertOutlined />, hotkey: 'i' },
      { path: '/containment', key: 'navContainment', icon: <ThunderboltOutlined /> },
      { path: '/findings', key: 'navFindings', icon: <ToolOutlined />, hotkey: 'f' },
      { path: '/events', key: 'navEvents', icon: <SearchOutlined />, hotkey: 'e' },
    ],
  },
  {
    key: 'navGroupAssets',
    items: [
      { path: '/assets', key: 'navAssets', icon: <CloudServerOutlined />, hotkey: 'a' },
      { path: '/identities', key: 'navIdentities', icon: <IdcardOutlined /> },
      { path: '/asset-map', key: 'navAssetMap', icon: <DeploymentUnitOutlined /> },
      { path: '/decoys', key: 'navDecoys', icon: <SafetyOutlined /> },
      { path: '/attack-surface', key: 'navAttackSurface', icon: <AimOutlined /> },
    ],
  },
  {
    key: 'navGroupAuto',
    items: [
      { path: '/reports', key: 'navReports', icon: <FileTextOutlined />, hotkey: 'r' },
      { path: '/tasks', key: 'navTasks', icon: <ClockCircleOutlined />, hotkey: 't' },
      { path: '/memories', key: 'navMemories', icon: <BulbOutlined /> },
      { path: '/approvals', key: 'navApprovals', icon: <CheckCircleOutlined />, groupAdmin: true, hotkey: 'p' },
    ],
  },
  {
    key: 'navGroupDetect',
    items: [
      { path: '/rules', key: 'navRules', icon: <FileSearchOutlined />, hotkey: 'd' },
      { path: '/suppressions', key: 'navSuppressions', icon: <StopOutlined /> },
      { path: '/trusted-sources', key: 'navTrustedSources', icon: <SafetyCertificateOutlined /> },
      { path: '/intel', key: 'navIntel', icon: <SafetyOutlined /> },
    ],
  },
  {
    key: 'navGroupSystem',
    admin: true,
    items: [
      { path: '/settings', key: 'navSettings', icon: <SettingOutlined /> },
      { path: '/integrations', key: 'navIntegrations', icon: <DeploymentUnitOutlined /> },
      { path: '/users', key: 'navUsers', icon: <UserOutlined /> },
      { path: '/groups', key: 'navGroups', icon: <TeamOutlined /> },
      { path: '/audit', key: 'navAudit', icon: <AuditOutlined /> },
    ],
  },
]

// 路径第一段 → [分组, 页面]，供面包屑用
export function crumbsOf(pathname: string): { group?: MsgKey; page?: NavItem } {
  const top = '/' + pathname.split('/')[1]
  for (const n of NAV) {
    if ('items' in n) {
      const page = n.items.find(i => i.path === top)
      if (page) return { group: n.key, page }
    } else if (n.path === top) return { page: n }
  }
  return {}
}
