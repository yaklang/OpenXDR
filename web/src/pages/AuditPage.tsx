import { useQuery } from '@tanstack/react-query'
import { Alert, Input, Select, Space, Table, Tag, Typography } from 'antd'
import { useMemo, useState } from 'react'
import { fetchAudit, type AuditRow } from '../api'
import { LoadError } from '../components/LoadError'
import { FilterCard, Page, STICKY_HEADER } from '../components/Page'
import { fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const ACTION: Record<string, { key: MsgKey; color?: string }> = {
  login: { key: 'actLogin' },
  login_failed: { key: 'actLoginFailed', color: 'red' },
  logout: { key: 'actLogout' },
  incident_status: { key: 'actIncidentStatus', color: 'blue' },
  command_issued: { key: 'actCommandIssued', color: 'orange' },
  exec_requested: { key: 'actExecRequested', color: 'orange' },
  exec_issued: { key: 'actExecIssued', color: 'orange' },
  exec_denied: { key: 'actExecDenied', color: 'red' },
  exec_unknown: { key: 'actExecUnknown', color: 'red' },
  approval_decided: { key: 'actApprovalDecided', color: 'purple' },
  command_policy_created: { key: 'actPolicyCreated', color: 'purple' },
  command_policy_deleted: { key: 'actPolicyDeleted', color: 'purple' },
  suppression_created: { key: 'actSuppressionCreated' },
  suppression_deleted: { key: 'actSuppressionDeleted' },
  user_created: { key: 'actUserCreated', color: 'cyan' },
  user_deleted: { key: 'actUserDeleted', color: 'cyan' },
  user_password_reset: { key: 'actUserPasswordReset', color: 'cyan' },
  group_created: { key: 'actGroupCreated', color: 'cyan' },
  group_deleted: { key: 'actGroupDeleted', color: 'cyan' },
  group_member_set: { key: 'actGroupMemberSet', color: 'cyan' },
  group_member_removed: { key: 'actGroupMemberRemoved', color: 'cyan' },
  asset_grouped: { key: 'actAssetGrouped' },
  asset_ungrouped: { key: 'actAssetUngrouped' },
  task_updated: { key: 'actTaskUpdated' },
  task_run_requested: { key: 'actTaskRunRequested' },
  finding_status: { key: 'actFindingStatus' },
  hunt: { key: 'actHunt' },
  notify_settings_updated: { key: 'actNotifySettings', color: 'cyan' },
  enroll_token_created: { key: 'actEnrollTokenCreated', color: 'geekblue' },
  enroll_token_revoked: { key: 'actEnrollTokenRevoked', color: 'geekblue' },
  host_enrolled: { key: 'actHostEnrolled', color: 'geekblue' },
  intel_feeds_updated: { key: 'actIntelFeedsUpdated' },
  intel_feeds_synced: { key: 'actIntelFeedsSynced' },
  agent_config_set: { key: 'actAgentConfigSet', color: 'geekblue' },
  hosts_imported: { key: 'actHostsImported', color: 'geekblue' },
  host_credential_deleted: { key: 'actHostCredentialDeleted', color: 'geekblue' },
  host_enrollment_installed: { key: 'actHostEnrollmentInstalled', color: 'geekblue' },
  host_enrollment_started: { key: 'actHostEnrollmentStarted', color: 'geekblue' },
  host_enrollment_unconfirmed: { key: 'actHostEnrollmentUnconfirmed', color: 'orange' },
  intel_created: { key: 'actIntelCreated' },
  intel_deleted: { key: 'actIntelDeleted' },
  intel_imported: { key: 'actIntelImported' },
  login_throttled: { key: 'actLoginThrottled', color: 'red' },
  incident_auto_closed: { key: 'actIncidentAutoClosed', color: 'blue' },
}

export function AuditPage() {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  const [draft, setDraft] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  // 关键词在后端全量匹配，不只筛已加载的这一页
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['audit', q], queryFn: () => fetchAudit(q) })

  const actionOptions = useMemo(() => [
    { value: '', label: t('allActions') },
    ...Object.entries(ACTION).map(([k, v]) => ({ value: k, label: t(v.key) })),
  ], [t])

  const rows = useMemo(() => (data?.items ?? []).filter(r => !actionFilter || r.action === actionFilter), [data?.items, actionFilter])
  const hasFilters = Boolean(draft || q || actionFilter)

  return (
    <Page title={t('navAudit')} subtitle={t('auditSubtitle')}>
      <FilterCard
        onReset={hasFilters ? () => { setDraft(''); setQ(''); setActionFilter('') } : undefined}
        extra={actionFilter && data ? <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{t('filteredCount', { n: rows.length, total: data.items.length })}</Typography.Text> : undefined}
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 280, maxWidth: '100%' }} aria-label={t('auditSearchHint')} value={draft} placeholder={t('auditSearchHint')} onSearch={v => setQ(v.trim())} onChange={e => { setDraft(e.target.value); if (!e.target.value) setQ('') }} />
            <Select showSearch optionFilterProp="label" aria-label={t('thAction')} style={{ width: 170 }} value={actionFilter} onChange={setActionFilter} options={actionOptions} />
          </Space>
        }
      >
        {data?.truncated && <Alert type="info" showIcon style={{ marginBottom: 14 }} title={t('listTruncated', { n: data.items.length })} />}
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<AuditRow>
          sticky={STICKY_HEADER}
          scroll={{ x: 1100 }}
          size="small"
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ defaultPageSize: 50, showSizeChanger: true, hideOnSinglePage: true }}
          columns={[
            { title: t('thTime'), dataIndex: 'ts', width: 180, sorter: (a, b) => a.ts.localeCompare(b.ts), render: fmtTime },
            { title: t('thUser'), dataIndex: 'username', width: 120, sorter: (a, b) => a.username.localeCompare(b.username) },
            { title: t('thAction'), dataIndex: 'action', width: 155, sorter: (a, b) => a.action.localeCompare(b.action), render: v => <Tag color={ACTION[v]?.color}>{ACTION[v] ? t(ACTION[v].key) : v}</Tag> },
            { title: t('thTarget'), dataIndex: 'target', width: 220, ellipsis: true, sorter: (a, b) => (a.target ?? '').localeCompare(b.target ?? ''), render: v => v ?? '-' },
            { title: t('thDetail'), dataIndex: 'detail', ellipsis: true, render: v => v ?? '-' },
            { title: t('thIP2'), dataIndex: 'remoteAddr', width: 150, sorter: (a, b) => (a.remoteAddr ?? '').localeCompare(b.remoteAddr ?? '') },
          ]}
        />}
      </FilterCard>
    </Page>
  )
}
