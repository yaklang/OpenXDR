import { useQuery } from '@tanstack/react-query'
import { Button, Descriptions, Modal, Space, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchAlertTemporalRevisions, fetchArchivedTemporalRule } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { SeverityTag, fmtTime } from './format'

// 时序告警按命中时的规则快照版本查当时的规则原文；单事件告警、旧版本告警或 viewer 不显示入口
export function TemporalRuleAtAlert({ alertId, ruleId }: { alertId: string; ruleId: string }) {
  const { t } = useI18n()
  const { me } = useSession()
  const [open, setOpen] = useState(false)
  const versions = useQuery({
    queryKey: ['alertTemporalRevisions', alertId, me.username, me.role],
    queryFn: () => fetchAlertTemporalRevisions(alertId),
    enabled: me.role !== 'viewer',
  })
  const revision = versions.data?.items[0]?.revision
  const detail = useQuery({
    queryKey: ['archivedTemporalRule', revision, ruleId, me.username, me.role],
    queryFn: () => fetchArchivedTemporalRule(revision!, ruleId),
    enabled: open && !!revision,
  })
  if (!revision) return null
  const rule = detail.data?.rules[0]
  const code = (text: string) => <pre className="json-block" style={{ whiteSpace: 'pre-wrap' }}>{text}</pre>

  return <>
    <Button size="small" onClick={() => setOpen(true)}>{t('temporalRuleAtAlert')}</Button>
    <Modal open={open} onCancel={() => setOpen(false)} footer={null} width={760} title={t('temporalRuleAtAlertTitle')} destroyOnHidden>
      {detail.isError ? <LoadError error={detail.error} onRetry={() => detail.refetch()} /> : rule && detail.data && <Space orientation="vertical" style={{ width: '100%' }}>
        <Descriptions size="small" column={1} items={[
          { key: 'rule', label: rule.id, children: <Space wrap><Typography.Text strong>{rule.title}</Typography.Text><SeverityTag value={rule.severity} /></Space> },
          { key: 'kind', label: t('temporalRuleGroupBy'), children: <Space wrap>
            <Tag>{t(rule.kind === 'event_count' ? 'temporalCount' : rule.kind === 'temporal' ? 'temporalUnordered' : 'temporalSequence')}</Tag>
            <Tag>{t(rule.groupBy === 'account' ? 'temporalGroupByAccount' : rule.groupBy === 'asset_source_ip' ? 'temporalGroupByAssetSourceIP' : 'temporalGroupByAsset')}</Tag>
            <Typography.Text type="secondary">{t('temporalRuleWindow', { seconds: rule.windowSeconds })}{rule.threshold ? ` · ${t('temporalRuleThreshold', { count: rule.threshold })}` : ''}{rule.minAssets > 1 ? ` · ${t('temporalRuleMinAssets', { count: rule.minAssets })}` : ''}</Typography.Text>
          </Space> },
          { key: 'revision', label: t('temporalGapsRevision'), children: <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{detail.data.revision}</Typography.Text> },
          { key: 'used', label: t('temporalRuleFirstUsed'), children: fmtTime(detail.data.createdAt) },
        ]} />
        <Typography.Text strong>{t('temporalRuleText')}</Typography.Text>
        {code(rule.source)}
        <Typography.Text strong>{t('temporalRuleBaseSource')}</Typography.Text>
        {rule.references.filter((id, i, all) => all.indexOf(id) === i).map(id => <div key={id}>{code(rule.base[id] ?? id)}</div>)}
      </Space>}
    </Modal>
  </>
}
