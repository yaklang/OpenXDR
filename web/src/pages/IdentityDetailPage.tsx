import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Descriptions, Empty, Popconfirm, Result, Select, Skeleton, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import {
  confirmIdentityLink, fetchIdentity, fetchIdentityMergeCandidates, rejectIdentityCandidate, revokeIdentityLink, revokeIdentityRejection,
  HttpError, type IdentityAccount, type IdentityLinkHistory, type IdentityMergeCandidate,
} from '../api'
import { useCanActIn, useSession } from '../app/session'
import { HostLink } from '../components/HostLink'
import { AccountKindTag, AccountName, BasisTag, Evidence, IdentityKindTag, LoginSummary } from '../components/IdentityParts'
import { accountLabel, linkSource } from '../components/identityText'
import { LoadError } from '../components/LoadError'
import { Page, TableCard } from '../components/Page'
import { errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const REASON: Record<IdentityMergeCandidate['reason'], MsgKey> = {
  same_name: 'identityReasonSameName', similar_name: 'identityReasonSimilarName', sid_ambiguous: 'identityReasonSIDAmbiguous',
}

const REVOKE_REASON: Record<string, MsgKey> = {
  manual_merge: 'revokeReasonManualMerge', manual_revoked: 'revokeReasonManualRevoked', evidence_changed: 'revokeReasonEvidenceChanged',
  account_out_of_group: 'revokeReasonAccountOutOfGroup', anchor_out_of_group: 'revokeReasonAnchorOutOfGroup',
}

function host(a: { assetId: string | null; hostname?: string | null; authority?: string | null }) {
  return a.assetId ? <HostLink id={a.assetId} fallback={a.hostname ?? undefined} /> : <Typography.Text type="secondary" style={{ overflowWrap: 'anywhere' }}>{a.authority ?? '—'}</Typography.Text>
}

export function IdentityDetailPage() {
  const { id = '' } = useParams()
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { me, groups } = useSession()
  const [hours, setHours] = useState(168)
  const membership = groups.map(g => `${g.id}:${g.role}`).sort().join(',')
  const scope = [me.username, me.role, membership, id]
  const detail = useQuery({ queryKey: ['identity', ...scope, hours], queryFn: () => fetchIdentity(id, hours), gcTime: 0 })
  const candidates = useQuery({ queryKey: ['identityCandidates', ...scope], queryFn: () => fetchIdentityMergeCandidates(id), gcTime: 0, enabled: detail.isSuccess })
  const canAct = useCanActIn(detail.data?.identity.groupId)

  const run = async (action: () => Promise<void>) => {
    try {
      await action()
    } catch (e) {
      message.error(errText(e, t))
    }
    client.invalidateQueries({ queryKey: ['identity'] })
    client.invalidateQueries({ queryKey: ['identityCandidates'] })
    client.invalidateQueries({ queryKey: ['identities'] })
  }

  if (detail.isPending) return <Skeleton active />
  if (detail.isError) {
    if (detail.error instanceof HttpError && detail.error.status === 404) return <Result status="404" title="404" subTitle={t('identityNotFound')} extra={<Link to="/identities">{t('navIdentities')}</Link>} />
    return <LoadError error={detail.error} onRetry={() => detail.refetch()} />
  }
  const { identity, accounts, truncated, history } = detail.data
  const title = accountLabel(identity)

  return (
    <Page title={title} crumb={title} subtitle={t('identityDetailHint')}>
      <Space orientation="vertical" size={20} style={{ width: '100%' }}>
        <Card>
          <Descriptions column={{ xs: 1, md: 3 }} size="small" items={[
            { key: 'kind', label: t('identityKind'), children: <IdentityKindTag kind={identity.kind} /> },
            { key: 'anchor', label: t('identityAnchor'), children: <Space size={4} wrap><AccountKindTag kind={identity.anchorKind} />{host(identity)}</Space> },
            { key: 'created', label: t('thCreatedAt'), children: fmtTime(identity.createdAt) },
            { key: 'id', label: 'ID', children: <Typography.Text className="mono" copyable>{identity.id}</Typography.Text> },
          ]} />
        </Card>

        <TableCard title={t('identityLinkedAccounts')} extra={<Select aria-label={t('thTime')} value={hours} style={{ width: 150 }} onChange={setHours}
          options={[24, 72, 168, 720].map(n => ({ value: n, label: t('lastHours', { n }) }))} />}>
          {truncated && <Alert type="info" showIcon title={t('identityAccountsTruncated')} style={{ marginBottom: 12 }} />}
          <Table<IdentityAccount> size="small" rowKey="id" dataSource={accounts} scroll={{ x: 820 }}
            pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
            columns={[
              { title: t('thUser'), key: 'account', render: (_, a) => <AccountName account={a} /> },
              { title: t('thHostname'), key: 'host', width: 180, render: (_, a) => host(a) },
              { title: t('identityBasis'), dataIndex: 'basis', width: 170, render: v => <BasisTag basis={v} /> },
              { title: t('identityLogins'), dataIndex: 'logins', width: 220, render: v => <LoginSummary stat={v} /> },
              { title: t('identityLinkSource'), dataIndex: 'source', width: 120, render: v => linkSource(v, t) },
              ...(canAct ? [{
                key: 'actions', width: 110,
                render: (_: unknown, a: IdentityAccount) => a.basis === 'manual' && a.linkId
                  ? <Popconfirm title={t('identityRevokeConfirm')} onConfirm={() => run(() => revokeIdentityLink(a.linkId!))}>
                    <Button size="small" danger>{t('identityRevoke')}</Button>
                  </Popconfirm>
                  : null,
              }] : []),
            ]}
            expandable={{ expandedRowRender: a => <Descriptions column={1} size="small" items={[
              { key: 'sid', label: 'SID', children: a.sid ? <Typography.Text copyable>{a.sid}</Typography.Text> : '—' },
              { key: 'seen', label: t('identityLastSeen'), children: `${fmtTime(a.firstSeen)} – ${fmtTime(a.lastSeen)}` },
              { key: 'linked', label: t('identityLinkedAt'), children: fmtTime(a.linkedAt) },
              { key: 'evidence', label: t('identityEvidence'), children: <Evidence value={a.evidence} /> },
            ]} /> }} />
        </TableCard>

        <TableCard title={t('identityCandidates')}>
          <Typography.Paragraph type="secondary">{t('identityCandidatesGuide')}</Typography.Paragraph>
          {candidates.isError ? <LoadError error={candidates.error} onRetry={() => candidates.refetch()} /> : <>
            {candidates.data?.truncated && <Alert type="info" showIcon title={t('identityCandidatesTruncatedN')} style={{ marginBottom: 12 }} />}
            <Table<IdentityMergeCandidate> size="small" rowKey={c => `${c.account.id}:${c.toIdentityId}`} loading={candidates.isPending}
              dataSource={candidates.data?.items ?? []} scroll={{ x: 820 }} pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('identityCandidatesNone')} /> }}
              columns={[
                { title: t('thUser'), key: 'account', render: (_, c) => <Space orientation="vertical" size={0}><AccountName account={c.account} />{host(c.account)}</Space> },
                { title: t('identityDirection'), dataIndex: 'direction', width: 150, render: v => t(v === 'incoming' ? 'identityCandidateIncoming' : 'identityCandidateOutgoing') },
                {
                  title: t('identityTarget'), key: 'target', width: 220,
                  render: (_, c) => c.direction === 'incoming' ? t('identityThis')
                    : <Space size={4} wrap><IdentityKindTag kind={c.toKind} /><Link to={`/identities/${c.toIdentityId}`}>{c.toName ?? c.toIdentityId.slice(-8)}</Link>{c.toHostname && <Typography.Text type="secondary">@{c.toHostname}</Typography.Text>}</Space>,
                },
                {
                  title: t('identityReason'), key: 'reason', width: 220,
                  render: (_, c) => <Space orientation="vertical" size={0}>
                    <Tag>{t(REASON[c.reason])}</Tag>
                    <Typography.Text type="secondary" style={{ overflowWrap: 'anywhere' }}>{t('identityMatched')}: {c.matchedName ?? '—'}</Typography.Text>
                  </Space>,
                },
                ...(canAct ? [{
                  key: 'actions', width: 200,
                  render: (_: unknown, c: IdentityMergeCandidate) => c.rejectionId
                    ? <Space size={4}><Tag>{t('identityRejected')}</Tag><Button size="small" onClick={() => run(() => revokeIdentityRejection(c.rejectionId!))}>{t('identityUndoReject')}</Button></Space>
                    : <Space size={4}>
                      <Popconfirm title={t('identityConfirmHint')} onConfirm={() => run(() => confirmIdentityLink(c.toIdentityId, c.account.id))}>
                        <Button size="small" type="primary">{t('identityConfirm')}</Button>
                      </Popconfirm>
                      <Button size="small" onClick={() => run(() => rejectIdentityCandidate(c.toIdentityId, c.account.id))}>{t('identityReject')}</Button>
                    </Space>,
                }] : [{
                  key: 'state', width: 100, render: (_: unknown, c: IdentityMergeCandidate) => c.rejectionId ? <Tag>{t('identityRejected')}</Tag> : null,
                }]),
              ]} />
          </>}
        </TableCard>

        <TableCard title={t('identityHistory')}>
          <Table<IdentityLinkHistory> size="small" rowKey="id" dataSource={history} scroll={{ x: 820 }}
            pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
            locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('identityHistoryEmpty')} /> }}
            columns={[
              { title: t('thUser'), key: 'account', render: (_, h) => <Space size={4} wrap><AccountKindTag kind={h.accountKind} /><span style={{ overflowWrap: 'anywhere' }}>{h.accountName ?? h.accountId.slice(-8)}</span></Space> },
              { title: t('thHostname'), dataIndex: 'assetId', width: 150, render: v => (v ? <HostLink id={v} /> : '—') },
              { title: t('identityBasis'), dataIndex: 'basis', width: 170, render: v => <BasisTag basis={v} /> },
              { title: t('identityLinkedAt'), key: 'created', width: 200, render: (_, h) => <>{fmtTime(h.createdAt)} · {linkSource(h.source, t)}</> },
              { title: t('identityRevokedAt'), key: 'revoked', width: 260, render: (_, h) => <>{fmtTime(h.revokedAt)} · {linkSource(h.revokedBy, t)} · {h.revokeReason ? t(REVOKE_REASON[h.revokeReason] ?? 'identityUnknown') : '—'}</> },
            ]}
            expandable={{ expandedRowRender: h => <Evidence value={h.evidence} /> }} />
        </TableCard>
      </Space>
    </Page>
  )
}
