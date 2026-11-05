import { Card, Descriptions, Typography } from 'antd'
import type { IncidentWork } from '../api'
import { useI18n } from '../i18n'
import { fmtTime } from './format'

export function IncidentWorkCard({ work, nextCheckAt }: { work: IncidentWork; nextCheckAt?: string }) {
  const { t } = useI18n()
  const stages: Record<string, string> = {
    investigating: t('incidentWorkInvestigating'),
    followup: t('incidentWorkFollowup'),
    monitoring: t('incidentWorkMonitoring'),
    escalated: t('incidentWorkEscalated'),
    completed: t('incidentWorkCompleted'),
  }
  const wake: Record<string, string> = {
    new_evidence: t('incidentWorkNewEvidence'),
    capability_upgrade: t('incidentWorkCapability'),
  }
  return <Card title={t('incidentWorkTitle')}>
    <Descriptions column={1} size="small">
      <Descriptions.Item label={t('incidentWorkOwner')}>{work.owner === 'ai' ? t('incidentWorkAI') : work.owner === 'human' ? t('incidentWorkHuman') : '—'}</Descriptions.Item>
      <Descriptions.Item label={t('incidentWorkStage')}>{stages[work.stage] ?? work.stage}</Descriptions.Item>
      <Descriptions.Item label={t('incidentWorkNextCheck')}>{nextCheckAt ? fmtTime(nextCheckAt) : work.owner === 'ai' && work.stage === 'monitoring' ? t('incidentWorkWaiting') : '—'}</Descriptions.Item>
      <Descriptions.Item label={t('incidentWorkAttempts')}>{work.attempts}</Descriptions.Item>
      {work.wake_on?.length > 0 && <Descriptions.Item label={t('incidentWorkWake')}>{work.wake_on.map(condition => wake[condition] ?? condition).join(' · ')}</Descriptions.Item>}
      {work.gap_kind && <Descriptions.Item label={t('incidentWorkGap')}>{work.gap_kind === 'evidence_unavailable' ? t('incidentWorkEvidenceUnavailable') : work.gap_kind}</Descriptions.Item>}
      <Descriptions.Item label={t('incidentWorkReason')}>{work.reason}</Descriptions.Item>
    </Descriptions>
    {work.gap_kind && <Typography.Paragraph type="secondary" style={{ marginBottom: 0, marginTop: 12 }}>{t('incidentWorkGapHint')}</Typography.Paragraph>}
  </Card>
}
