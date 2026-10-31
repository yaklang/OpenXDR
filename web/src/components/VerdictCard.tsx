import { CheckCircleFilled, ExclamationCircleFilled, WarningFilled } from '@ant-design/icons'
import { Alert, Card, Col, Collapse, Empty, Flex, Row, Space, Table, Timeline, Typography, theme } from 'antd'
import type { ReactNode } from 'react'
import type { RecordEvidence, Verdict } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { GeminiSparkle } from './Logo'

// 研判结论放在详情页最上面：先看结论与置信度，再看攻击链与处置建议
export function VerdictCard({ verdict }: { verdict: Verdict | null }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const META: Record<string, { key: MsgKey; color: string; bg: string; icon: ReactNode }> = {
    malicious: { key: 'verdictMalicious', color: token.colorError, bg: token.colorErrorBg, icon: <ExclamationCircleFilled /> },
    suspicious: { key: 'verdictSuspicious', color: token.colorWarning, bg: token.colorWarningBg, icon: <WarningFilled /> },
    benign: { key: 'verdictBenign', color: token.colorSuccess, bg: token.colorSuccessBg, icon: <CheckCircleFilled /> },
  }
  if (!verdict) return <Card title={<Space size={8}><GeminiSparkle size={16} />{t('aiVerdict')}</Space>}><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waitingVerdict')} /></Card>
  if (verdict.error) return <Card title={<Space size={8}><GeminiSparkle size={16} />{t('aiVerdict')}</Space>}><Alert type="warning" showIcon title={t('unparsableVerdict', { e: verdict.raw ?? verdict.error })} /></Card>
  const meta = META[verdict.verdict ?? '']
  const chain = verdict.kill_chain ?? []
  const actions = verdict.actions ?? []

  return (
    <Card styles={{ body: { padding: 0 } }}>
      <Flex align="center" gap={16} className="verdict-band" style={{ background: meta?.bg ?? token.colorFillQuaternary, borderLeftColor: meta?.color ?? token.colorBorder }}>
        <span style={{ fontSize: 30, color: meta?.color, lineHeight: 1 }}>{meta?.icon ?? <GeminiSparkle size={28} />}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}><Space size={4}><GeminiSparkle size={13} />{t('aiVerdict')}</Space></Typography.Text>
          <div style={{ fontSize: 20, fontWeight: 600, color: meta?.color }}>{meta ? t(meta.key) : verdict.verdict}</div>
        </div>
        {verdict.confidence != null && (
          <div style={{ textAlign: 'right' }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('confidence')}</Typography.Text>
            <div style={{ fontSize: 22, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{verdict.confidence}%</div>
          </div>
        )}
      </Flex>
      <div style={{ padding: '20px 24px 16px' }}>
        {!!verdict.evidence_observations?.length && <EvidenceObservations observations={verdict.evidence_observations} />}
        {verdict.summary && <>
          <Typography.Text type="secondary">{t('triageModelSummary')}</Typography.Text>
          <Typography.Paragraph style={{ lineHeight: 1.8 }}>{verdict.summary}</Typography.Paragraph>
        </>}
        {!!verdict.query_evidence?.length && <Collapse size="small" style={{ marginBottom: 16 }} items={[{
          key: 'coverage', label: t('triageQueryEvidence'), children: <>
            <Typography.Paragraph type="secondary">{t('triageQueryEvidenceHint')}</Typography.Paragraph>
            <ul style={{ paddingInlineStart: 20 }}>{verdict.query_evidence.map(e => <li key={e.id}>
              <Typography.Text code>{e.id} · {e.tool}</Typography.Text>{' '}
              {e.facts.status === 'ok' ? t('triageQueryOK') : t('triageQueryUnknown')}
              {e.facts.returned != null && ` · ${t('triageQueryReturned', { n: e.facts.returned })}`}
              {` · ${e.facts.truncated === true ? t('triageQueryTruncated') : e.facts.truncated === false ? t('triageQueryNotTruncated') : t('triageQueryTruncationUnknown')}`}
              {(e.facts.raw_truncated_records ?? 0) > 0 && ` · ${t('triageQueryRawTruncated', { n: e.facts.raw_truncated_records! })}`}
              {(e.facts.dns_omitted_records ?? 0) > 0 && ` · ${t('triageQueryDNSOmitted', { n: e.facts.dns_omitted_records! })}`}
              {e.facts.missing_ancestor === true && ` · ${t('triageQueryMissingAncestor')}`}
              {e.facts.baseline_status && <div style={{ marginBlock: 8 }}>
                <Typography.Text strong>{t('triageBaseline')}</Typography.Text>{' '}
                {e.facts.baseline_first_recorded_at || t('triageRecordUnknown')}
                <div><Typography.Text code>{e.facts.baseline_path || e.facts.exe_path}</Typography.Text></div>
                {e.facts.baseline_id && <Typography.Text type="secondary">ID: {e.facts.baseline_id}</Typography.Text>}
                <Typography.Paragraph type="secondary">{t('triageBaselineScope')}</Typography.Paragraph>
              </div>}
              {e.facts.collection_status && <div style={{ marginBlock: 8 }}>
                <Typography.Text strong>{t('triageCollectionSnapshot')}</Typography.Text>{' '}
                {e.facts.collection_received_at || t('triageRecordUnknown')}
                <Typography.Paragraph type="secondary">{t('triageCollectionScope')}</Typography.Paragraph>
                {Object.entries(e.facts.collection_states ?? {}).map(([name, state]) => <div key={name}>
                  <Typography.Text code>{name}</Typography.Text>: {state}
                </div>)}
              </div>}
              {!!e.records?.length && <EvidenceRecords records={e.records} />}
            </li>)}</ul>
          </>,
        }]} />}
        <Row gutter={[32, 8]}>
          {!!chain.length && (
            <Col xs={24} lg={actions.length ? 13 : 24}>
              <Typography.Title level={5} style={{ marginTop: 4 }}>{t('triageModelChain')}</Typography.Title>
              <Timeline items={chain.map(s => ({ color: meta?.color ?? token.colorPrimary, content: s }))} />
            </Col>
          )}
          {!!actions.length && (
            <Col xs={24} lg={chain.length ? 11 : 24}>
              <Typography.Title level={5} style={{ marginTop: 4 }}>{t('suggestedActions')}</Typography.Title>
              <ol className="action-list">{actions.map((s, i) => <li key={i}>{s}</li>)}</ol>
            </Col>
          )}
        </Row>
      </div>
    </Card>
  )
}

function EvidenceRecords({ records }: { records: RecordEvidence[] }) {
  const { t } = useI18n()
  const text = (value?: string) => <Typography.Text style={{ overflowWrap: 'anywhere' }}>{value || t('triageRecordUnknown')}</Typography.Text>
  return <details style={{ marginBlock: 8 }}>
    <summary style={{ cursor: 'pointer' }}>{t('triageRecordDetails', { n: records.length })}</summary>
    <Table<RecordEvidence> size="small" rowKey="id" pagination={false} dataSource={records} scroll={{ x: 900 }} columns={[
      { title: t('triageRecordReference'), width: 170, render: (_, r) => text(r.id) },
      { title: t('triageRecordEvent'), width: 240, render: (_, r) => <>{text(r.facts.event_id)}<br />{text(r.facts.ts)}</> },
      { title: t('triageRecordAsset'), width: 220, render: (_, r) => text(r.facts.asset_id) },
      { title: 'Process GUID', width: 220, render: (_, r) => text(r.facts.process_guid) },
      { title: 'Parent GUID', width: 220, render: (_, r) => text(r.facts.parent_process_guid) },
    ]} />
  </details>
}

function EvidenceObservations({ observations }: { observations: NonNullable<Verdict['evidence_observations']> }) {
  const { t } = useI18n()
  const list = (items: typeof observations) => <ul style={{ paddingInlineStart: 20, overflowWrap: 'anywhere' }}>
    {items.map(o => <li key={`${o.evidence_id}/${o.field}`}>
      <Typography.Text code>{o.evidence_id} · {o.field}</Typography.Text>
      <Typography.Paragraph ellipsis={{ rows: 3, expandable: 'collapsible', symbol: expanded => t(expanded ? 'triageExcerptCollapse' : 'triageExcerptExpand') }} style={{ marginBottom: 8 }}>
        {o.text}
      </Typography.Paragraph>
    </li>)}
  </ul>
  return <section aria-label={t('triageEvidenceObservations')} style={{ marginBottom: 16 }}>
    <Typography.Title level={5} style={{ marginTop: 0 }}>{t('triageEvidenceObservations')}</Typography.Title>
    <Typography.Paragraph type="secondary">{t('triageEvidenceObservationsHint')}</Typography.Paragraph>
    {list(observations.slice(0, 3))}
    {observations.length > 3 && <details>
      <summary style={{ cursor: 'pointer' }}>{t('triageExcerptMore', { n: observations.length - 3 })}</summary>
      {list(observations.slice(3))}
    </details>}
  </section>
}
