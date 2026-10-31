import { CheckCircleFilled } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Progress, Typography, theme } from 'antd'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { fetchAgentSessions, fetchAssets, fetchNotifySettings } from '../api'
import { useSession } from '../app/session'
import { useTour } from '../app/tour'
import { useI18n, type MsgKey } from '../i18n'

// 上手清单（管理员）：把从零到能用的几步摆出来，每步的完成状态都从真实数据推，全部完成或手动关掉后不再出现
export function GettingStarted() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const navigate = useNavigate()
  const { isAdmin, groups, group } = useSession()
  const tour = useTour()
  const [dismissed, setDismissed] = useState(() => localStorage.getItem('gettingStarted') === 'off')
  const show = isAdmin && !dismissed
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, enabled: show })
  const notify = useQuery({ queryKey: ['notify-settings'], queryFn: fetchNotifySettings, enabled: show })
  const sessions = useQuery({ queryKey: ['sessions', group?.id], queryFn: () => fetchAgentSessions(group!.id), enabled: show && !!group })
  if (!show || assets.isPending || notify.isPending) return null

  const steps: { title: MsgKey; desc: MsgKey; done: boolean; go: () => void }[] = [
    { title: 'gsGroup', desc: 'gsGroupDesc', done: groups.length > 0, go: () => navigate('/groups') },
    { title: 'gsHost', desc: 'gsHostDesc', done: (assets.data ?? []).length > 0, go: () => navigate('/assets') },
    { title: 'gsAssign', desc: 'gsAssignDesc', done: (assets.data ?? []).some(a => a.groupId), go: () => navigate('/assets') },
    { title: 'gsNotify', desc: 'gsNotifyDesc', done: !!notify.data?.url, go: () => navigate('/settings') },
    { title: 'gsChat', desc: 'gsChatDesc', done: (sessions.data ?? []).length > 0, go: () => navigate('/chat') },
    { title: 'gsTour', desc: 'gsTourDesc', done: tour.done, go: tour.start },
  ]
  const done = steps.filter(s => s.done).length
  if (done === steps.length) return null
  const dismiss = () => {
    localStorage.setItem('gettingStarted', 'off')
    setDismissed(true)
  }

  return (
    <Card
      title={<>{t('gsTitle')} <Typography.Text type="secondary" style={{ fontWeight: 400, fontSize: 13, marginLeft: 8 }}>{t('gsProgress', { done, total: steps.length })}</Typography.Text></>}
      extra={<Button type="text" size="small" onClick={dismiss}>{t('gsDismiss')}</Button>}
      style={{ marginBottom: 20 }}
    >
      <Progress percent={(done / steps.length) * 100} showInfo={false} size="small" style={{ margin: '-4px 0 16px' }} />
      <div className="gs-grid">
        {steps.map((s, i) => (
          <div key={s.title} className={`gs-step${s.done ? ' gs-done' : ''}`}>
            <span className="gs-mark" style={s.done ? { color: token.colorSuccess } : { borderColor: token.colorBorder, color: token.colorTextTertiary }}>
              {s.done ? <CheckCircleFilled /> : i + 1}
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <Typography.Text strong={!s.done} delete={s.done} type={s.done ? 'secondary' : undefined}>{t(s.title)}</Typography.Text>
              <Typography.Paragraph type="secondary" style={{ margin: '2px 0 0', fontSize: 13 }}>{t(s.desc)}</Typography.Paragraph>
            </div>
            {!s.done && <Button size="small" onClick={s.go}>{t('gsGo')}</Button>}
          </div>
        ))}
      </div>
    </Card>
  )
}
