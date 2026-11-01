import { AlertOutlined, ToolOutlined } from '@ant-design/icons'
import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Collapse, Space, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { createAgentSession, fetchFindingsByID, fetchIncident, setFindingStatus, setIncidentStatus } from '../api'
import { useCanAct, useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { ResolveModal } from './ResolveModal'
import { LoadError } from './LoadError'
import { IncidentStatusTag, SeverityTag, errText } from './format'
import { agreesWithAI, proposalNote, verdictStatus } from './verdict'

// 对话只看组内角色（后端同口径）
export function useCanChat() {
  const { groups } = useSession()
  return (groupId: string | null | undefined) => {
    const role = groups.find(g => g.id === groupId)?.role
    return role === 'admin' || role === 'analyst'
  }
}

// 交给 AI：在对象所在组新建绑定会话，跳到对话页并自动发出第一句，AI 立刻开始处理
export function useHandoff() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { setGroupId } = useSession()
  const [busy, setBusy] = useState(false)
  const start = async (groupId: string, subjects: string[], title: string, prompt: string) => {
    setBusy(true)
    try {
      const s = await createAgentSession({ groupId, subjects, title })
      setGroupId(groupId)
      client.invalidateQueries({ queryKey: ['sessions', groupId] })
      navigate(`/chat/${s.id}?${new URLSearchParams({ prompt, send: '1' })}`)
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }
  return { start, busy }
}

// 对话页顶部：本会话在处理的事件与待办，当前状态一眼可见，处理完就地结案或标记
export function SubjectsBar({ subjects, groupId }: { subjects: string[]; groupId: string }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const canAct = useCanAct()(groupId)
  const [resolving, setResolving] = useState<{ kind: 'incident' | 'finding'; id: string; next: string; title: string } | null>(null)
  const parsed = subjects.map(s => s.split(':') as ['incident' | 'finding', string])
  const incidents = useQueries({
    queries: parsed.filter(([k]) => k === 'incident').map(([, id]) => ({ queryKey: ['incident', id], queryFn: () => fetchIncident(id), refetchInterval: 15_000 })),
  })
  const findingIds = parsed.filter(([k]) => k === 'finding').map(([, id]) => id)
  const findings = useQuery({ queryKey: ['findings', 'subjects', findingIds], queryFn: () => fetchFindingsByID(findingIds), enabled: findingIds.length > 0, refetchInterval: 15_000 })
  const failed = [...incidents, findings].filter(q => q.isError)
  // 结案弹窗与事件页同口径：预填结论相同的 AI 结案建议，与研判一致时理由选填、相反时提示
  const incident = resolving?.kind === 'incident' ? incidents.find(q => q.data?.id === resolving.id)?.data : undefined
  const next = incident ? (resolving?.next as 'closed' | 'false_positive') : null

  const submit = async (note: string) => {
    if (!resolving) return
    try {
      if (resolving.kind === 'incident') await setIncidentStatus(resolving.id, resolving.next, note)
      else await setFindingStatus(resolving.id, resolving.next, note)
    } catch (e) {
      message.error(errText(e, t))
      throw e
    }
    client.invalidateQueries({ queryKey: [resolving.kind, resolving.id] })
    client.invalidateQueries({ queryKey: ['incidents'] })
    client.invalidateQueries({ queryKey: ['findings'] })
    setResolving(null)
  }

  const rows = [
    ...incidents.map(q => q.data).filter(i => !!i).map(i => {
      const done = i.status === 'closed' || i.status === 'false_positive'
      const title = i.title ?? i.id
      return (
        <div key={i.id} className="subject-row">
          <AlertOutlined />
          <SeverityTag value={i.severity} />
          <Link to={`/incidents/${i.id}`} className="subject-title"><Typography.Text ellipsis>{title}</Typography.Text></Link>
          <IncidentStatusTag value={i.status} retriage={i.retriage} triageStartedAt={i.triageStartedAt} />
          {canAct && !done && (
            <Space size={0}>
              <Button type="link" size="small" onClick={() => setResolving({ kind: 'incident', id: i.id, next: 'closed', title })}>{t('markTrue')}</Button>
              <Button type="link" size="small" danger onClick={() => setResolving({ kind: 'incident', id: i.id, next: 'false_positive', title })}>{t('markFpShort')}</Button>
            </Space>
          )}
        </div>
      )
    }),
    ...(findings.data ?? []).filter(f => findingIds.includes(f.id)).map(f => (
      <div key={f.id} className="subject-row">
        <ToolOutlined />
        <Typography.Text type="secondary">{f.hostname}</Typography.Text>
        <Link to={`/findings?${new URLSearchParams({ ids: f.id, status: 'all' })}`} className="subject-title"><Typography.Text ellipsis>{f.title}</Typography.Text></Link>
        <Tag>{t(FINDING_STATUS[f.status])}</Tag>
        {canAct && f.status === 'open' && (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => setResolving({ kind: 'finding', id: f.id, next: 'resolved', title: f.title })}>{t('markResolved')}</Button>
            <Button type="link" size="small" onClick={() => setResolving({ kind: 'finding', id: f.id, next: 'ignored', title: f.title })}>{t('markIgnored')}</Button>
          </Space>
        )}
      </div>
    )),
  ]

  return (
    <>
      <Collapse size="small" defaultActiveKey={['s']} className="subjects-bar" bordered={false}
        items={[{ key: 's', label: t('subjectsTitle', { n: subjects.length }), children: <>{failed.length > 0 && <LoadError error={failed[0].error} onRetry={() => failed.forEach(q => q.refetch())} />}{rows}</> }]} />
      <ResolveModal
        open={!!resolving}
        title={`${t(resolving ? RESOLVE_TITLE[resolving.next] : 'resolveClosedTitle')} · ${resolving?.title ?? ''}`}
        hint={t(resolving?.kind === 'finding' ? (resolving.next === 'ignored' ? 'findingIgnoreHint' : 'findingResolveHint') : 'resolveHint')}
        initialNote={incident ? proposalNote([incident], next) : undefined}
        optional={!!incident && agreesWithAI(incident.aiVerdict, next)}
        contradicts={!!incident && !!verdictStatus(incident.aiVerdict) && !agreesWithAI(incident.aiVerdict, next)}
        onCancel={() => setResolving(null)}
        onSubmit={submit}
      />
    </>
  )
}

const FINDING_STATUS: Record<string, MsgKey> = { open: 'findingOpen', resolved: 'findingResolved', ignored: 'findingIgnored' }
const RESOLVE_TITLE: Record<string, MsgKey> = {
  closed: 'resolveClosedTitle', false_positive: 'resolveFpTitle', resolved: 'findingResolveTitle', ignored: 'findingIgnoreTitle',
}
