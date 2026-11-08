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
  agreement_accepted: { key: 'actAgreementAccepted', color: 'cyan' },
  onboarding_finished: { key: 'actOnboardingFinished', color: 'cyan' },
  ai_settings_updated: { key: 'actAiSettingsUpdated', color: 'cyan' },
  session_model_updated: { key: 'actSessionModelUpdated' },
  approval_ai_reviewed: { key: 'actApprovalAiReviewed', color: 'purple' },
  approval_auto: { key: 'actApprovalAuto', color: 'purple' },
  asset_profile_updated: { key: 'actAssetProfileUpdated' },
  asset_response_tier: { key: 'actAssetResponseTier', color: 'orange' },
  asset_service_noted: { key: 'actAssetServiceNoted' },
  asset_zone_assigned: { key: 'actAssetZoneAssigned' },
  assets_exported: { key: 'actAssetsExported' },
  zone_created: { key: 'actZoneCreated' },
  zone_updated: { key: 'actZoneUpdated' },
  zone_deleted: { key: 'actZoneDeleted' },
  auto_response: { key: 'actAutoResponse', color: 'orange' },
  auto_response_failed: { key: 'actAutoResponseFailed', color: 'red' },
  auto_response_skipped: { key: 'actAutoResponseSkipped' },
  command_verification_recorded: { key: 'actCommandVerificationRecorded' },
  containment: { key: 'actContainment', color: 'orange' },
  containment_config_updated: { key: 'actContainmentConfigUpdated', color: 'cyan' },
  containment_expired: { key: 'actContainmentExpired' },
  containment_extended: { key: 'actContainmentExtended', color: 'orange' },
  containment_failed: { key: 'actContainmentFailed', color: 'red' },
  containment_held: { key: 'actContainmentHeld', color: 'gold' },
  containment_history_reconciled: { key: 'actContainmentHistoryReconciled' },
  containment_lifted: { key: 'actContainmentLifted', color: 'blue' },
  custom_rule_created: { key: 'actCustomRuleCreated', color: 'cyan' },
  custom_rule_updated: { key: 'actCustomRuleUpdated', color: 'cyan' },
  custom_rule_deleted: { key: 'actCustomRuleDeleted', color: 'cyan' },
  deception_host_exit_confirmed: { key: 'actDeceptionHostExitConfirmed', color: 'gold' },
  deception_host_instance_assigned: { key: 'actDeceptionHostInstanceAssigned', color: 'gold' },
  deception_host_release_registered: { key: 'actDeceptionHostReleaseRegistered', color: 'gold' },
  deception_release_admitted: { key: 'actDeceptionReleaseAdmitted', color: 'gold' },
  deception_release_disabled: { key: 'actDeceptionReleaseDisabled', color: 'gold' },
  deception_revision_selected: { key: 'actDeceptionRevisionSelected', color: 'gold' },
  deception_stop_requested: { key: 'actDeceptionStopRequested', color: 'gold' },
  deception_trigger_review_opened: { key: 'actDeceptionTriggerReviewOpened', color: 'gold' },
  decoy_install_started: { key: 'actDecoyInstallStarted', color: 'gold' },
  decoy_marker_review_opened: { key: 'actDecoyMarkerReviewOpened', color: 'gold' },
  decoy_observation_review_requested: { key: 'actDecoyObservationReviewRequested', color: 'gold' },
  decoy_registered: { key: 'actDecoyRegistered', color: 'gold' },
  decoy_registration_revoked: { key: 'actDecoyRegistrationRevoked', color: 'gold' },
  decoy_runtime_token_rotated: { key: 'actDecoyRuntimeTokenRotated', color: 'gold' },
  external_ticket_saved: { key: 'actExternalTicketSaved' },
  finding_ai_review: { key: 'actFindingAiReview', color: 'purple' },
  finding_evidence_update: { key: 'actFindingEvidenceUpdate' },
  finding_execution_decided: { key: 'actFindingExecutionDecided', color: 'orange' },
  finding_execution_revoked: { key: 'actFindingExecutionRevoked' },
  finding_risk_escalated: { key: 'actFindingRiskEscalated', color: 'red' },
  finding_risk_recovered: { key: 'actFindingRiskRecovered', color: 'green' },
  finding_work_orphan_recovered: { key: 'actFindingWorkOrphanRecovered' },
  finding_work_woken: { key: 'actFindingWorkWoken' },
  incident_closure_ai_reviewed: { key: 'actIncidentClosureAiReviewed', color: 'purple' },
  incident_contained_reopened: { key: 'actIncidentContainedReopened', color: 'red' },
  incident_proposal_dismissed: { key: 'actIncidentProposalDismissed' },
  integration_delivery_retired: { key: 'actIntegrationDeliveryRetired', color: 'geekblue' },
  integration_incident_resolved: { key: 'actIntegrationIncidentResolved', color: 'geekblue' },
  integration_outbound_allow: { key: 'actIntegrationOutboundAllow', color: 'geekblue' },
  integration_saved: { key: 'actIntegrationSaved', color: 'geekblue' },
  integration_token_created: { key: 'actIntegrationTokenCreated', color: 'geekblue' },
  integration_token_revoked: { key: 'actIntegrationTokenRevoked', color: 'geekblue' },
  'intel.threatbook.lookup': { key: 'actIntelThreatbookLookup' },
  'intel.threatbook.lookup_failed': { key: 'actIntelThreatbookLookupFailed', color: 'red' },
  memory_create: { key: 'actMemoryCreate' },
  memory_update: { key: 'actMemoryUpdate' },
  memory_delete: { key: 'actMemoryDelete' },
  repair_action_denied: { key: 'actRepairActionDenied', color: 'red' },
  repair_action_issued: { key: 'actRepairActionIssued', color: 'orange' },
  repair_action_reserved: { key: 'actRepairActionReserved' },
  repair_action_revalidated: { key: 'actRepairActionRevalidated' },
  repair_action_verified: { key: 'actRepairActionVerified', color: 'green' },
  repair_policy_update: { key: 'actRepairPolicyUpdate', color: 'cyan' },
  sandbox_token_issued: { key: 'actSandboxTokenIssued' },
  sensor_enrolled: { key: 'actSensorEnrolled', color: 'geekblue' },
  suppression_ai_reviewed: { key: 'actSuppressionAiReviewed', color: 'purple' },
  suppression_approved: { key: 'actSuppressionApproved' },
  suppression_proposed: { key: 'actSuppressionProposed' },
  suppression_rejected: { key: 'actSuppressionRejected' },
  task_group_updated: { key: 'actTaskGroupUpdated' },
  trusted_source_auto_created: { key: 'actTrustedSourceAutoCreated', color: 'cyan' },
  trusted_source_auto_renewed: { key: 'actTrustedSourceAutoRenewed', color: 'cyan' },
  trusted_source_auto_revoked: { key: 'actTrustedSourceAutoRevoked', color: 'orange' },
  trusted_source_created: { key: 'actTrustedSourceCreated', color: 'cyan' },
  trusted_source_revoked: { key: 'actTrustedSourceRevoked', color: 'orange' },
  trusted_source_deleted: { key: 'actTrustedSourceDeleted' },
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
