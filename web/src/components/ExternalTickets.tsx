import { useQuery } from '@tanstack/react-query'
import { Card, Space, Tag, Typography } from 'antd'
import { fetchIncidentTickets } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

export function ExternalTickets({ incidentId }: { incidentId: string }) {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['incidentTickets', incidentId], queryFn: () => fetchIncidentTickets(incidentId), refetchInterval: 30_000 })
  return <Card title={t('integrationExternalTickets')} loading={query.isPending}>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : query.data?.length ? <div className="cmd-list">{query.data.map(ticket => <div key={ticket.id} className="cmd-item">
      <Typography.Link href={/^https?:\/\//i.test(ticket.url) ? ticket.url : undefined} target="_blank" rel="noopener noreferrer">{ticket.externalId} · {ticket.title}</Typography.Link>
      <Space size={6} style={{ marginTop: 4 }}><Tag>{ticket.status}</Tag><Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(ticket.updatedAt)}</Typography.Text></Space>
    </div>)}</div> : <Typography.Text type="secondary">{t('integrationNoTicket')}</Typography.Text>}
  </Card>
}
