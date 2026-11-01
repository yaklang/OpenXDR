import { ClearOutlined, HomeOutlined } from '@ant-design/icons'
import { Breadcrumb, Button, Card, Flex, Grid, Typography } from 'antd'
import type { Breakpoint, CardProps } from 'antd'
import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import { crumbsOf } from '../app/nav'
import { useI18n } from '../i18n'

// 页面骨架：面包屑 + 标题 + 说明 + 右侧操作（标题不再带图标，侧栏已经标明位置），下面是内容。面包屑从菜单配置推，详情页给最后一级
export function Page({ title, subtitle, extra, crumb, children }: {
  title: ReactNode
  subtitle?: ReactNode
  extra?: ReactNode
  crumb?: ReactNode
  children: ReactNode
}) {
  const { t } = useI18n()
  const { pathname } = useLocation()
  const { group, page } = crumbsOf(pathname)
  const items = [
    { title: <Link to="/chat" aria-label={t('backHome')}><HomeOutlined /></Link> },
    ...(group ? [{ title: t(group) }] : []),
    ...(page ? [{ title: crumb ? <Link to={page.path}>{t(page.key)}</Link> : t(page.key) }] : []),
    ...(crumb ? [{ title: crumb }] : []),
  ]
  return (
    <div className={crumb ? 'page page-detail' : 'page'}>
      <Breadcrumb items={items} className="page-crumb" />
      <Flex justify="space-between" align="flex-start" gap={16} wrap className="page-head">
        <div>
          <Typography.Title level={4} className="page-title">{title}</Typography.Title>
          {subtitle && <Typography.Text type="secondary" className="page-subtitle">{subtitle}</Typography.Text>}
        </div>
        {extra && <Flex gap={8} wrap>{extra}</Flex>}
      </Flex>
      {children}
    </div>
  )
}

// 窄屏表格：次要列加 responsive: WIDE_ONLY 在手机上收起，表格也不再强撑固定宽度，留下的关键列（级别、标题、状态）能完整显示
export const WIDE_ONLY: Breakpoint[] = ['md']
export const useWideTable = () => !!Grid.useBreakpoint().md

// 长列表的表头吸在顶栏下面（顶栏高 60），往下翻也知道每列是什么
export const STICKY_HEADER = { offsetHeader: 60 }

// 表格卡片统一保留边缘与底部留白；不裁剪容器，避免破坏吸顶表头和焦点轮廓。
export function TableCard({ children, toolbar, className, ...props }: Omit<CardProps, 'styles'> & { toolbar?: ReactNode }) {
  return (
    <Card {...props} className={['table-card', className].filter(Boolean).join(' ')} styles={{ body: { padding: 0 } }}>
      {toolbar}
      <div className="table-card-content">{children}</div>
    </Card>
  )
}

// 列表卡片：筛选条单独一行在表格上方，右侧放计数或次要操作
export function FilterCard({ filters, extra, onReset, children }: { filters: ReactNode; extra?: ReactNode; onReset?: () => void; children: ReactNode }) {
  const { t } = useI18n()
  return (
    <TableCard toolbar={
      <Flex justify="space-between" align="center" gap={12} wrap className="filter-bar">
        <Flex className="filter-controls" gap={8} wrap align="center">{filters}
          {onReset && <Button type="text" icon={<ClearOutlined aria-hidden />} onClick={onReset}>{t('resetFilters')}</Button>}
        </Flex>
        {extra}
      </Flex>
    }>
      {children}
    </TableCard>
  )
}
