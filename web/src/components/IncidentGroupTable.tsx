import { TableActions } from './TableActions'
import { Badge, Button, Space, Table, Tag, Tooltip, Typography } from 'antd'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { BATCH_RESOLVE_MAX, type IncidentGroup, type IncidentSummary } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { Ago } from './Ago'
import { HostLink } from './HostLink'
import { IncidentStatusTag, SeverityTag } from './format'
import { STICKY_HEADER, WIDE_ONLY, useWideTable } from './Page'

const VERDICT: Record<string, { key: MsgKey; status: 'error' | 'warning' | 'success'; color: string }> = {
  malicious: { key: 'verdictMalicious', status: 'error', color: 'red' },
  suspicious: { key: 'verdictSuspicious', status: 'warning', color: 'orange' },
  benign: { key: 'verdictBenign', status: 'success', color: 'green' },
}

// 列表里的研判一列：结论 · 置信度，悬停看摘要
export function VerdictBadge({ row }: { row: IncidentSummary }) {
  const { t } = useI18n()
  const v = VERDICT[row.aiVerdict?.verdict ?? '']
  if (!v) return <Badge status="default" text={t('waitingVerdict')} />
  return (
    <Tooltip title={row.aiVerdict?.summary}>
      <Badge status={v.status} text={`${t(v.key)} · ${row.aiVerdict?.confidence ?? '-'}`} />
    </Tooltip>
  )
}

// 按规则归并：同一规则（或同一情报目标）在同一主机上反复出现的未结案事件一组，整组结案，展开看组内事件。
// 归并只是视图，结案仍逐个事件落库
export function IncidentGroupTable({ groups, loading, emptyText, actable, onResolve }: {
  groups: IncidentGroup[]
  loading: boolean
  emptyText: ReactNode
  actable: (r: IncidentSummary) => boolean
  onResolve: (status: 'closed' | 'false_positive', rows: IncidentSummary[]) => void
}) {
  const { t } = useI18n()
  const wideTable = useWideTable()
  const anyActable = groups.some(g => g.incidents.some(actable))
  return (
    <Table<IncidentGroup>
      sticky={STICKY_HEADER}
      scroll={wideTable ? { x: 1100 } : undefined}
      rowKey="key"
      loading={loading}
      dataSource={groups}
      locale={{ emptyText }}
      pagination={{ pageSize: 50, hideOnSinglePage: true, showSizeChanger: false, showTotal: n => t('totalCount', { n }) }}
      expandable={{
        expandedRowRender: g => (
          <Table<IncidentSummary>
            size="small"
            rowKey="id"
            pagination={false}
            dataSource={g.incidents}
            columns={[
              { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
              { title: t('thTitle'), dataIndex: 'title', render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
              {
                title: t('thStatus'), dataIndex: 'status', width: 130,
                render: (v, r) => <Space size={4} wrap><IncidentStatusTag value={v} retriage={r.retriage} triageStartedAt={r.triageStartedAt} />{r.closureProposal && <Tag color="purple" variant="filled">{t('proposalTag')}</Tag>}</Space>,
              },
              { responsive: WIDE_ONLY, title: t('thVerdict'), width: 150, render: (_, r) => <VerdictBadge row={r} /> },
              { responsive: WIDE_ONLY, title: t('thAlerts'), dataIndex: 'alertCount', width: 80, align: 'right' },
              { responsive: WIDE_ONLY, title: t('thCreatedAt'), dataIndex: 'createdAt', width: 110, render: v => <Ago iso={v} /> },
            ]}
          />
        ),
      }}
      columns={[
        { responsive: WIDE_ONLY, title: t('thSeverity'), dataIndex: 'severity', width: 95, sorter: (a, b) => a.severity - b.severity, render: v => <SeverityTag value={v} /> },
        {
          title: t('thRule'), dataIndex: 'ruleId', ellipsis: wideTable,
          sorter: (a, b) => (a.ruleTitle ?? a.ruleId).localeCompare(b.ruleTitle ?? b.ruleId),
          render: (v, g) => <>
            <Tooltip title={g.ruleTitle ? `${g.ruleTitle} · ${v}` : v}><Typography.Text>{g.ruleTitle ?? (v || '-')}</Typography.Text></Tooltip>
            {/* 窄屏收起级别、主机与事件数三列，挪到规则名下面 */}
            {!wideTable && <div><SeverityTag value={g.severity} /> <HostLink id={g.assetId} fallback={g.hostname ?? '-'} /> · {g.count}</div>}
          </>,
        },
        { responsive: WIDE_ONLY, title: t('thHostname'), dataIndex: 'assetId', width: 150, ellipsis: true, sorter: (a, b) => (a.hostname ?? '').localeCompare(b.hostname ?? ''), render: (v, g) => <HostLink id={v} fallback={g.hostname ?? '-'} /> },
        { responsive: WIDE_ONLY, title: t('thIncidentCount'), dataIndex: 'count', width: 105, align: 'right', sorter: (a, b) => a.count - b.count },
        {
          responsive: WIDE_ONLY, title: t('thVerdictMix'), width: 230,
          render: (_, g) => {
            const proposals = g.incidents.filter(r => r.closureProposal).length
            return (
              <Space size={4} wrap>
                {Object.entries(VERDICT).map(([k, v]) => !!g.verdicts[k as keyof IncidentGroup['verdicts']] &&
                  <Tag key={k} color={v.color} variant="filled">{t(v.key)} {g.verdicts[k as keyof IncidentGroup['verdicts']]}</Tag>)}
                {!!g.verdicts.none && <Tag variant="filled">{t('verdictNone')} {g.verdicts.none}</Tag>}
                {proposals > 0 && <Tag color="purple" variant="filled">{t('proposalTag')} {proposals}</Tag>}
              </Space>
            )
          },
        },
        { responsive: WIDE_ONLY, title: t('groupFirstAt'), dataIndex: 'firstAt', width: 115, sorter: (a, b) => a.firstAt.localeCompare(b.firstAt), render: v => <Ago iso={v} /> },
        { responsive: WIDE_ONLY, title: t('groupLastAt'), dataIndex: 'lastAt', width: 115, sorter: (a, b) => a.lastAt.localeCompare(b.lastAt), render: v => <Ago iso={v} /> },
        ...(anyActable ? [{
          title: '', width: wideTable ? 170 : 96,
          render: (_: unknown, g: IncidentGroup) => {
            const rows = g.incidents.filter(actable)
            if (!rows.length) return null
            const tooMany = rows.length > BATCH_RESOLVE_MAX
            return (
              <Tooltip title={tooMany ? t('batchTooMany', { n: BATCH_RESOLVE_MAX }) : undefined}>
                <TableActions className="row-actions">
                  <Button type="link" size="small" disabled={tooMany} onClick={() => onResolve('closed', rows)}>{t('markTrue')}</Button>
                  <Button type="link" size="small" danger disabled={tooMany} onClick={() => onResolve('false_positive', rows)}>{t('markFpShort')}</Button>
                </TableActions>
              </Tooltip>
            )
          },
        }] : []),
      ]}
    />
  )
}
