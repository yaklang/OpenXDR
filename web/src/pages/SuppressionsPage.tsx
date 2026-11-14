import { Clamp } from '../components/Clamp'
import { TableActions } from '../components/TableActions'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Input, Popconfirm, Popover, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { deleteSuppression, fetchAssets, fetchSuppressions, reviewSuppression, setSuppressionEnabled, type SuppressCondition, type SuppressEvidence, type Suppression } from '../api'
import { useSession } from '../app/session'
import { EmptyHint } from '../components/Ago'
import { HostLink } from '../components/HostLink'
import { FilterCard, Page, STICKY_HEADER, useWideTable } from '../components/Page'
import { fmtTime, errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'
import { LoadError } from '../components/LoadError'

const OP: Record<string, MsgKey> = {
  equals: 'supOpEquals',
  contains: 'supOpContains',
  startswith: 'supOpStartswith',
  endswith: 'supOpEndswith',
  in: 'supOpIn',
  not_contains: 'supOpNotContains',
  regex: 'supOpRegex',
}

function condValueText(c: SuppressCondition): string {
  return c.values?.length ? `[${c.values.join(', ')}]` : (c.value ?? '')
}

// 抑制规则：最怕被遗忘——列出压掉的次数，让长期无人过问的抑制显形；内置良性链由管理员随时启停
export function SuppressionsPage() {
  const { t } = useI18n()
  const wideTable = useWideTable()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite, isAdmin, groups } = useSession()
  const [q, setQ] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['suppressions'], queryFn: fetchSuppressions })
  const assets = useQuery({ queryKey: ['assets'], queryFn: () => fetchAssets() })
  // AI 提议由 AI 审计员评审；仍待评审的可由主机所在组的管理员批准，与命令审批同一档权限
  const canReview = (s: Suppression) => {
    const groupId = assets.data?.find(a => a.id === s.assetId)?.groupId
    return isAdmin || groups.find(g => g.id === groupId)?.role === 'admin'
  }
  const activeQ = q.trim().toLowerCase()
  const hasFilters = Boolean(activeQ || statusFilter)
  // 待批准的排在最前，其次内置良性链
  const rows = [...(data ?? [])]
    .filter(s =>
      (!statusFilter || s.status === statusFilter) &&
      (!activeQ ||
        (s.builtinTitle ?? '').toLowerCase().includes(activeQ) ||
        (s.builtinKey ?? '').toLowerCase().includes(activeQ) ||
        (s.ruleTitle ?? '').toLowerCase().includes(activeQ) ||
        s.ruleId.toLowerCase().includes(activeQ) ||
        (s.reason ?? '').toLowerCase().includes(activeQ) ||
        s.createdBy.toLowerCase().includes(activeQ) ||
        (s.conditions ?? []).some(c => (c.field + ' ' + condValueText(c)).toLowerCase().includes(activeQ)))
    )
    .sort((a, b) =>
      Number(b.status === 'proposed') - Number(a.status === 'proposed') ||
      Number(b.createdBy === 'builtin') - Number(a.createdBy === 'builtin'))

  const review = async (id: string, decision: 'approve' | 'reject') => {
    try {
      await reviewSuppression(id, decision)
      await client.invalidateQueries({ queryKey: ['suppressions'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const toggleBuiltin = async (id: string, enabled: boolean) => {
    try {
      await setSuppressionEnabled(id, enabled)
      await client.invalidateQueries({ queryKey: ['suppressions'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const revoke = async (id: string) => {
    try {
      await deleteSuppression(id)
      await client.invalidateQueries({ queryKey: ['suppressions'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  return (
    <Page title={t('navSuppressions')} subtitle={t('suppressionsSubtitle')}>
      <FilterCard
        onReset={hasFilters ? () => { setQ(''); setStatusFilter('') } : undefined}
        extra={hasFilters && data ? <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total: data.length })}</Typography.Text> : undefined}
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 280 }} placeholder={t('searchSuppressions')} value={q} onChange={e => setQ(e.target.value)} />
            <Select aria-label={t('thStatus')} style={{ width: 150 }} value={statusFilter} onChange={setStatusFilter}
              options={[
                { value: '', label: t('allStatuses') },
                { value: 'proposed', label: t('supProposed') },
                { value: 'active', label: t('supActive') },
                { value: 'disabled', label: t('supDisabled') },
                { value: 'rejected', label: t('supRejected') },
              ]}
            />
          </Space>
        }
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<Suppression>
          sticky={STICKY_HEADER}
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ defaultPageSize: 20, showSizeChanger: true, hideOnSinglePage: true }}
          scroll={{ x: 1700 }}
          locale={{ emptyText: <EmptyHint title={t(hasFilters ? 'noMatch' : 'noSuppressions')} hint={hasFilters ? undefined : t('noSuppressionsHint')} /> }}
          columns={[
            {
              title: t('thRule'), dataIndex: 'ruleTitle', width: 240,
              sorter: (a, b) => (a.builtinTitle ?? a.ruleTitle ?? a.ruleId).localeCompare(b.builtinTitle ?? b.ruleTitle ?? b.ruleId),
              render: (v, s) => s.builtinTitle ? (
                <div>
                  <Tooltip title={s.builtinKey ?? s.ruleId}><Typography.Text strong>{s.builtinTitle}</Typography.Text></Tooltip>
                  <div><Typography.Text type="secondary" style={{ fontSize: 12 }}>{s.ruleId === '*' ? t('supWildcardRules') : (v ?? s.ruleId)}</Typography.Text></div>
                </div>
              ) : <Tooltip title={s.ruleId}>{v ?? s.ruleId}</Tooltip>,
            },
            {
              title: t('thStatus'), dataIndex: 'status', width: 105,
              sorter: (a, b) => a.status.localeCompare(b.status),
              render: (v: Suppression['status'], s) => (
                <Tag color={v === 'proposed' ? 'gold' : v === 'rejected' || v === 'disabled' ? 'default' : 'green'}>
                  {t(v === 'proposed'
                    ? (s.evidence ? (s.evidence.basis === 'ai_benign' ? 'supAIStatsDraft' : 'supStatsDraft') : 'supProposed')
                    : v === 'disabled' ? 'supDisabled' : v === 'rejected' ? 'supRejected' : 'supActive')}
                </Tag>
              ),
            },
            { title: t('thScope'), dataIndex: 'assetId', width: 130, render: v => (v ? <HostLink id={v} /> : <Tag color="warning">{t('allHosts')}</Tag>) },
            {
              title: t('supConditions'), dataIndex: 'conditions', width: 360,
              render: (v: Suppression['conditions']) => (v?.length
                ? v.map((c, idx) => {
                    const val = condValueText(c)
                    const prefix = c.group ? `[#${c.group}] ` : ''
                    const opLabel = OP[c.op] ? t(OP[c.op]) : c.op
                    return (
                      <Typography.Paragraph key={`${idx}:${c.field}:${c.op}:${val}`} className="mono" style={{ fontSize: 12, margin: 0 }} ellipsis={{ rows: 2, tooltip: val }}>
                        {prefix}{c.field} {opLabel} {val}
                      </Typography.Paragraph>
                    )
                  })
                : <Tag color="warning">{t('supWholeRule')}</Tag>),
            },
            { title: t('reason'), dataIndex: 'reason', render: v => <Clamp text={v} /> },
            { title: t('thMatched'), dataIndex: 'matchedCount', width: 110, align: 'right', sorter: (a, b) => a.matchedCount - b.matchedCount },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 165, sorter: (a, b) => (a.lastMatchedAt ?? '').localeCompare(b.lastMatchedAt ?? ''), render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 165, sorter: (a, b) => (a.expiresAt ?? '9999').localeCompare(b.expiresAt ?? '9999'), render: v => (v ? fmtTime(v) : t('longTerm')) },
            {
              title: t('thCreatedBy'), dataIndex: 'createdBy', width: 125,
              sorter: (a, b) => a.createdBy.localeCompare(b.createdBy),
              render: (v: string, s) => (s.createdBy === 'builtin'
                ? <Tag color="blue">{t('supBuiltin')}</Tag>
                : s.evidence
                  ? <Popover title={t(s.evidence.basis === 'ai_benign' ? 'supFromAIStats' : 'supFromStats')} content={<StatsEvidence e={s.evidence} />}><Tag color={s.evidence.basis === 'ai_benign' ? 'orange' : 'cyan'} style={{ cursor: 'help' }}>{t(s.evidence.basis === 'ai_benign' ? 'supFromAIStats' : 'supFromStats')}</Tag></Popover>
                  : s.sessionId ? <Space size={4}><Tag color="purple" variant="filled">AI</Tag><Link to={`/chat/${s.sessionId}`}>{t('openSession')}</Link></Space> : v),
            },
            ...(canWrite
              ? [{
                  title: t('actions'), width: 130,
                  // 表格要横向滚动才看得全：宽屏把操作列钉在右侧，批准 / 拒绝不用先拖滚动条；窄屏钉住会盖掉一半表格
                  fixed: wideTable ? 'right' as const : undefined,
                  render: (_: unknown, s: Suppression) => (
                    <TableActions>
                      {s.createdBy === 'builtin' ? (
                        isAdmin && (
                          <Button type="link" size="small" danger={s.status === 'active'} onClick={() => toggleBuiltin(s.id, s.status !== 'active')}>
                            {t(s.status === 'active' ? 'supDisable' : 'supEnable')}
                          </Button>
                        )
                      ) : (
                        <>
                          {s.status === 'proposed' && canReview(s) && <>
                            <Button type="link" size="small" onClick={() => review(s.id, 'approve')}>{t('supApprove')}</Button>
                            <Button type="link" size="small" onClick={() => review(s.id, 'reject')}>{t('supReject')}</Button>
                          </>}
                          {s.status !== 'proposed' && (
                            <Popconfirm title={t('confirmRevoke')} onConfirm={() => revoke(s.id)}>
                              <Button type="link" danger size="small">{t('revoke')}</Button>
                            </Popconfirm>
                          )}
                        </>
                      )}
                    </TableActions>
                  ),
                }]
              : []),
          ]}
        />}
      </FilterCard>
    </Page>
  )
}

// 误报统计草案的依据：计数、比例与被人判误报的事件
function StatsEvidence({ e }: { e: SuppressEvidence }) {
  const { t } = useI18n()
  return (
    <div style={{ maxWidth: 420, fontSize: 12 }}>
      {e.scope === 'rule' && <div style={{ marginBottom: 6 }}><Tag color="warning">{t('supWholeRule')}</Tag>{t('supStatsScopeRule')}</div>}
      <div>{e.basis === 'ai_benign'
        ? t('supAIStatsSummary', { days: e.windowDays, benign: e.aiBenign ?? 0, fp: e.falsePositives, ratio: e.ratioPercent, pending: e.pending })
        : t('supStatsSummary', { days: e.windowDays, fp: e.falsePositives, ratio: e.ratioPercent, pending: e.pending })}</div>
      {e.aiProposals + e.autoClosed > 0 && <div style={{ opacity: 0.7 }}>{t('supStatsExcluded', { ai: e.aiProposals, auto: e.autoClosed })}</div>}
      <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
        {e.incidents.map(i => (
          <li key={i.id}>
            <Link to={`/incidents/${i.id}`}>{i.title || i.id}</Link> · {i.source === 'ai_benign' ? t('supStatsAIBenign') : i.resolvedBy}{i.source === 'ai_verdict' ? ` (${t('supStatsAdoptedAI')})` : ''} · {fmtTime(i.resolvedAt)}
          </li>
        ))}
      </ul>
    </div>
  )
}
