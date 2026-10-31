import { CheckCircleFilled, ExclamationCircleFilled, WarningFilled } from '@ant-design/icons'
import { Alert, Card, Collapse, Empty, Flex, Space, Table, Tag, Timeline, Typography, theme } from 'antd'
import type { ReactNode } from 'react'
import type { RecordEvidence, Verdict } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { GeminiSparkle } from './Logo'

const ACTION_CODE_LABELS: Record<string, { zh: string; en: string; color: string }> = {
  confirm_activity_source: { zh: '🔍 核实活动来源', en: '🔍 Confirm source', color: 'gold' },
  supplement_process_context: { zh: '🧬 补充进程血缘', en: '🧬 Check process lineage', color: 'processing' },
  supplement_network_context: { zh: '🌐 补充网络日志', en: '🌐 Check network logs', color: 'processing' },
  collect_missing_telemetry: { zh: '📡 补齐缺失遥测', en: '📡 Collect telemetry', color: 'default' },
  monitor_recurring_activity: { zh: '👁️ 持续观察复发', en: '👁️ Monitor recurrence', color: 'cyan' },
  close_benign_after_review: { zh: '✅ 复核后良性结案', en: '✅ Close as benign', color: 'success' },
  contain_confirmed_compromise: { zh: '🛑 隔离失陷主机', en: '🛑 Contain host', color: 'error' },
}

function splitVerdictSummary(summary?: string): { headline: string; detail: string } {
  const raw = (summary ?? '').trim()
  if (!raw) return { headline: '', detail: '' }
  const nl = raw.indexOf('\n')
  if (nl > 0) {
    return { headline: raw.slice(0, nl).trim(), detail: raw.slice(nl + 1).trim() }
  }
  // 兼容旧格式长段落：取第一句作为首屏核心结论，其余收进折叠区
  const m = raw.match(/^(.{12,110}?[。！？；])(.*)$/s)
  if (m && m[2].trim().length > 20) {
    return { headline: m[1].trim(), detail: m[2].trim() }
  }
  return { headline: raw, detail: '' }
}

// 研判结论放在详情页最上面：首屏看一句话核心结论、AI 自治取证进度与动作标签，详细依据与证据边界按需展开
export function VerdictCard({ verdict }: { verdict: Verdict | null }) {
  const { t, locale } = useI18n()
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
  const actionCodes = verdict.action_codes ?? []
  const queries = verdict.query_evidence ?? []
  const totalRecords = queries.reduce((acc, q) => acc + (q.facts.returned ?? (q.records?.length ?? 0)), 0)
  const toolCounts: Record<string, number> = {}
  for (const q of queries) {
    if (q.tool) toolCounts[q.tool] = (toolCounts[q.tool] ?? 0) + 1
  }
  const { headline, detail } = splitVerdictSummary(verdict.summary)
  const hasFoldContent = !!(detail || actions.length || verdict.evidence_observations?.length || queries.length)

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
      <div style={{ padding: '18px 24px 16px' }}>
        {headline && (
          <div style={{ marginBottom: 12 }}>
            <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>{t('triageCoreConclusion')}</Typography.Text>
            <Typography.Paragraph strong style={{ fontSize: 15, lineHeight: 1.65, marginBottom: 0 }}>{headline}</Typography.Paragraph>
          </div>
        )}
        {(queries.length > 0 || actionCodes.length > 0) && (
          <Flex wrap gap={8} align="center" style={{ marginBottom: 14 }}>
            {queries.length > 0 && (
              <Tag color="blue" style={{ margin: 0, padding: '2px 10px', fontSize: 12 }}>
                {t('triageAutonomyBadge', { n: queries.length, r: totalRecords })}
                {Object.keys(toolCounts).length > 0 && ` · ${Object.entries(toolCounts).map(([k, c]) => `${k}×${c}`).join(' / ')}`}
              </Tag>
            )}
            {actionCodes.map(code => {
              const info = ACTION_CODE_LABELS[code]
              return (
                <Tag key={code} color={info?.color ?? 'default'} style={{ margin: 0, padding: '2px 10px', fontSize: 12 }}>
                  {info ? (locale === 'en' ? info.en : info.zh) : code}
                </Tag>
              )
            })}
          </Flex>
        )}
        {!!chain.length && (
          <div style={{ marginBottom: 12 }}>
            <Typography.Title level={5} style={{ marginTop: 4, marginBottom: 10 }}>{t('triageModelChain')}</Typography.Title>
            <Timeline items={chain.map(s => ({ color: meta?.color ?? token.colorPrimary, content: s }))} />
          </div>
        )}
        {!actionCodes.length && !!actions.length && (
          <div style={{ marginBottom: 12 }}>
            <Typography.Title level={5} style={{ marginTop: 4 }}>{t('suggestedActions')}</Typography.Title>
            <ol className="action-list">{actions.map((s, i) => <li key={i}>{s}</li>)}</ol>
          </div>
        )}
        {hasFoldContent && (
          <Collapse size="small" items={[{
            key: 'details',
            label: t('triageFoldLabel'),
            children: (
              <Space orientation="vertical" size={12} style={{ width: '100%' }}>
                {detail && (
                  <div>
                    <Typography.Text type="secondary">{t('triageModelSummary')}</Typography.Text>
                    <Typography.Paragraph style={{ lineHeight: 1.75, marginBottom: 0, marginTop: 4 }}>{detail}</Typography.Paragraph>
                  </div>
                )}
                {!!actionCodes.length && !!actions.length && (
                  <div>
                    <Typography.Text type="secondary">{t('suggestedActions')}</Typography.Text>
                    <ol className="action-list" style={{ marginTop: 4, marginBottom: 0 }}>{actions.map((s, i) => <li key={i}>{s}</li>)}</ol>
                  </div>
                )}
                {!!verdict.evidence_observations?.length && <EvidenceObservations observations={verdict.evidence_observations} />}
                {!!queries.length && (
                  <div>
                    <Typography.Text strong>{t('triageQueryEvidence')}</Typography.Text>
                    <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>{t('triageQueryEvidenceHint')}</Typography.Paragraph>
                    <ul style={{ paddingInlineStart: 20, marginBottom: 0 }}>{queries.map(e => <li key={e.id}>
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
                  </div>
                )}
              </Space>
            ),
          }]} />
        )}
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
