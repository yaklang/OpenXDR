import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Descriptions, Input, Popconfirm, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { fetchContainments, fetchContainmentStatus, liftContainment, type Containment, type ContainmentState } from '../api'
import { useSession } from '../app/session'
import { EmptyHint } from '../components/Ago'
import { HostLink } from '../components/HostLink'
import { LoadError } from '../components/LoadError'
import { FilterCard, Page, STICKY_HEADER, useWideTable } from '../components/Page'
import { TableActions } from '../components/TableActions'
import { CommandStatusTag, commandKind, errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const STATE: Record<ContainmentState, { key: MsgKey; color: string }> = {
  active: { key: 'cmtActive', color: 'red' },
  executed: { key: 'cmtExecuted', color: 'volcano' },
  expired: { key: 'cmtExpired', color: 'default' },
  lifted: { key: 'cmtLifted', color: 'default' },
  held: { key: 'cmtHeld', color: 'gold' },
  skipped: { key: 'cmtSkipped', color: 'default' },
  failed: { key: 'cmtFailed', color: 'warning' },
}

const ROLE: Record<Containment['role'], MsgKey> = { source: 'cmtRoleSource', victim: 'cmtRoleVictim', host: 'cmtRoleHost' }

// 策略矩阵：代码里写死的信号 → 动作，这里只展示
const POLICY: { signal: MsgKey; action: MsgKey }[] = [
  { signal: 'cmtSigSpray', action: 'cmtActSpray' },
  { signal: 'cmtSigBrute', action: 'cmtActBrute' },
  { signal: 'cmtSigDBShell', action: 'cmtActDBShell' },
  { signal: 'cmtSigIntelIP', action: 'cmtActIntelIP' },
  { signal: 'cmtSigIntelDomain', action: 'cmtActIntelDomain' },
  { signal: 'cmtSigIntelHash', action: 'cmtActIntelHash' },
]

// 自主响应：平台自己做了什么、什么还在生效、为什么动或没动；人在这里事后审计、一键撤回
export function ContainmentPage() {
  const { t } = useI18n()
  const wideTable = useWideTable()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite } = useSession()
  const [state, setState] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [why, setWhy] = useState('')
  const status = useQuery({ queryKey: ['containment-status'], queryFn: fetchContainmentStatus, refetchInterval: 15_000 })
  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['containments', page, pageSize, state],
    queryFn: () => fetchContainments(page, pageSize, state),
    refetchInterval: 15_000,
  })

  const lift = async (id: string) => {
    try {
      await liftContainment(id, why.trim())
      setWhy('')
      await Promise.all([client.invalidateQueries({ queryKey: ['containments'] }), client.invalidateQueries({ queryKey: ['containment-status'] })])
      message.success(t('cmtLiftDone'))
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const st = status.data
  return (
    <Page title={t('navContainment')} subtitle={t('containmentSubtitle')}>
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {st && !st.enabled && <Alert type="info" showIcon title={t('cmtDisabled')} />}
        {st?.tripped && <Alert type="warning" showIcon title={t('cmtTripped', { n: st.executedLastHour, max: st.maxPerHour ?? 0 })} />}
        {st && (
          <Card size="small">
            <Descriptions size="small" column={{ xs: 2, md: 3, xl: 6 }}>
              <Descriptions.Item label={t('cmtStatus')}>{st.enabled ? <Tag color="green">{t('cmtOn')}</Tag> : <Tag>{t('cmtOff')}</Tag>}</Descriptions.Item>
              <Descriptions.Item label={t('cmtScope')}>{st.scope ? t(st.scope === 'lab' ? 'cmtScopeLab' : 'cmtScopeAll') : '-'}</Descriptions.Item>
              <Descriptions.Item label={t('cmtTTL')}>{st.ttlHours ? t('cmtHours', { n: st.ttlHours }) : '-'}</Descriptions.Item>
              <Descriptions.Item label={t('cmtActiveCount')}>{st.active}</Descriptions.Item>
              <Descriptions.Item label={t('cmtLastHour')}>{st.maxPerHour ? `${st.executedLastHour} / ${st.maxPerHour}` : st.executedLastHour}</Descriptions.Item>
              <Descriptions.Item label={t('cmtHeldLastHour')}>{st.heldLastHour}</Descriptions.Item>
            </Descriptions>
          </Card>
        )}
        <FilterCard
          onReset={state ? () => { setState(''); setPage(1) } : undefined}
          filters={
            <Select aria-label={t('thStatus')} style={{ width: 170 }} value={state} onChange={v => { setState(v); setPage(1) }}
              options={[
                { value: '', label: t('allStatuses') },
                { value: 'active,executed', label: t('cmtInEffect') },
                ...(Object.keys(STATE) as ContainmentState[]).map(s => ({ value: s, label: t(STATE[s].key) })),
              ]}
            />
          }
        >
          {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<Containment>
            sticky={STICKY_HEADER}
            rowKey="id"
            loading={isPending}
            dataSource={data?.items}
            pagination={{ current: page, pageSize, total: data?.total, showSizeChanger: true, hideOnSinglePage: true,
              onChange: (p, s) => { setPage(p); setPageSize(s) } }}
            scroll={{ x: 1500 }}
            locale={{ emptyText: <EmptyHint title={t('cmtEmpty')} hint={t('cmtEmptyHint')} /> }}
            columns={[
              { title: t('thTime'), dataIndex: 'createdAt', width: 165, render: fmtTime },
              { title: t('thHostname'), dataIndex: 'assetId', width: 150, render: (v, c) => <HostLink id={v} fallback={c.assetHostname} /> },
              {
                title: t('cmtAction'), dataIndex: 'kind', width: 240,
                render: (v: string, c) => <span>{commandKind(v, t)} <Typography.Text code style={{ fontSize: 12 }}>{v === 'kill_process' ? `pid ${c.pid}` : c.target}</Typography.Text></span>,
              },
              { title: t('cmtRole'), dataIndex: 'role', width: 100, render: (v: Containment['role'], c) => <Tooltip title={c.sourceHostname ? t('cmtSourceIs', { host: c.sourceHostname }) : undefined}>{t(ROLE[v])}</Tooltip> },
              { title: t('thStatus'), dataIndex: 'state', width: 110, render: (v: ContainmentState) => <Tag color={STATE[v].color}>{t(STATE[v].key)}</Tag> },
              { title: t('reason'), dataIndex: 'reason', ellipsis: { showTitle: false }, render: v => <Tooltip title={v} placement="topLeft">{v}</Tooltip> },
              {
                title: t('cmtCommand'), dataIndex: 'commandStatus', width: 120,
                render: (v: string | undefined, c) => (v ? <Tooltip title={c.commandDetail}><span><CommandStatusTag value={v} /></span></Tooltip> : '-'),
              },
              {
                title: t('cmtUntil'), dataIndex: 'expiresAt', width: 165,
                render: (v: string | null, c) => (c.endedAt ? <Tooltip title={c.liftedBy ? t('cmtLiftedBy', { who: c.liftedBy }) : undefined}>{fmtTime(c.endedAt)}</Tooltip> : v ? fmtTime(v) : '-'),
              },
              {
                title: t('cmtSignal'), dataIndex: 'signal', width: 200, ellipsis: true,
                render: (v: string, c) => (c.incidentId ? <Link to={`/incidents/${c.incidentId}`}>{v}</Link> : v),
              },
              ...(canWrite
                ? [{
                    title: t('actions'), width: 100,
                    fixed: wideTable ? 'right' as const : undefined,
                    render: (_: unknown, c: Containment) => c.liftable && (
                      <TableActions>
                        <Popconfirm
                          title={t(c.state === 'active' ? 'cmtLiftConfirm' : 'cmtRestoreConfirm')}
                          description={<Input size="small" placeholder={t('cmtLiftReason')} value={why} onChange={e => setWhy(e.target.value)} />}
                          onConfirm={() => lift(c.id)}
                        >
                          <Button type="link" danger size="small">{t(c.state === 'active' ? 'cmtLift' : 'cmtRestore')}</Button>
                        </Popconfirm>
                      </TableActions>
                    ),
                  }]
                : []),
            ]}
          />}
        </FilterCard>
        <Card size="small" title={t('cmtPolicy')}>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12.5 }}>{t('cmtPolicyHint')}</Typography.Paragraph>
          <Table size="small" pagination={false} rowKey="signal" dataSource={POLICY}
            columns={[
              { title: t('cmtSignal'), dataIndex: 'signal', width: 240, render: (v: MsgKey) => t(v) },
              { title: t('cmtAction'), dataIndex: 'action', render: (v: MsgKey) => t(v) },
            ]}
          />
        </Card>
      </Space>
    </Page>
  )
}
