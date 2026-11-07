import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Space, Typography } from 'antd'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { delegateFinding, fetchFindingDecision, revokeFindingDecision, type FindingRow } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { ResolveModal } from './ResolveModal'
import { errText, fmtTime } from './format'

export function FindingDecisionPanel({ finding }: { finding: FindingRow }) {
  const { t } = useI18n()
  const { groups } = useSession()
  const { message } = App.useApp()
  const client = useQueryClient()
  const navigate = useNavigate()
  const [request, setRequest] = useState<{ requestId: string; expiresAt: string } | null>(null)
  const { data, error } = useQuery({ queryKey: ['finding-decision', finding.id], queryFn: () => fetchFindingDecision(finding.id) })
  const admin = groups.some(g => g.id === finding.groupId && g.role === 'admin')
  const active = data && !data.revoked && Date.parse(data.expiresAt) > Date.now()
  return <Space orientation="vertical" style={{ marginTop: 12 }}>
    {error && <Typography.Text type="danger">{errText(error, t)}</Typography.Text>}
    {data && <>
      <Typography.Text strong>{t('findingDecisionTitle')}</Typography.Text>
      <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{data.instruction}</Typography.Paragraph>
      <Typography.Text type="secondary">{data.author} · {fmtTime(data.expiresAt)} · {t(active ? 'findingDecisionActive' : 'findingDecisionInactive')}</Typography.Text>
      <Space>
        <Link to={`/chat/${data.sessionId}`}>{t('openSession')}</Link>
        {admin && active && <Button size="small" danger onClick={async () => {
          try { await revokeFindingDecision(finding.id); client.invalidateQueries({ queryKey: ['finding-decision', finding.id] }) }
          catch (e) { message.error(errText(e, t)) }
        }}>{t('findingDecisionRevoke')}</Button>}
      </Space>
    </>}
    {admin && finding.status === 'open' && <Button size="small" onClick={() => setRequest({ requestId: crypto.randomUUID(), expiresAt: new Date(Date.now() + 24 * 3600000).toISOString() })}>{t('findingDecisionExecute')}</Button>}
    <ResolveModal open={!!request} title={t('findingDecisionExecute')} hint={t('findingDecisionHint')} onCancel={() => setRequest(null)} onSubmit={async instruction => {
      if (!request) return
      try {
        const result = await delegateFinding(finding.id, { ...request, instruction })
        client.invalidateQueries({ queryKey: ['finding-decision', finding.id] })
        if (result.runError) message.warning(result.runError)
        setRequest(null)
        navigate(`/chat/${result.decision.sessionId}`)
      } catch (e) { message.error(errText(e, t)); throw e }
    }} />
  </Space>
}
