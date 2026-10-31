import { useQuery } from '@tanstack/react-query'
import { Alert, Collapse, Empty, Skeleton, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { fetchAssetVulns, type VulnPackage } from '../api'
import { useI18n } from '../i18n'
import { fmtTime } from './format'
import { LoadError } from './LoadError'

// 分数着色与告警级别同一档：9 以上严重、7 以上高危、4 以上中危
export function ScoreTag({ score }: { score: number }) {
  if (!score) return <Tag>-</Tag>
  const color = score >= 9 ? 'red' : score >= 7 ? 'volcano' : score >= 4 ? 'gold' : 'default'
  return <Tag color={color}>{score.toFixed(1)}</Tag>
}

// 资产的软件漏洞：先给能马上做的（升级就修掉、暴露在外的排最前），暂无修复的折叠在后面
export function AssetVulns({ assetId }: { assetId: string }) {
  const { t } = useI18n()
  const q = useQuery({ queryKey: ['asset-vulns', assetId], queryFn: () => fetchAssetVulns(assetId) })
  if (q.isError) return <LoadError error={q.error} onRetry={() => q.refetch()} />
  if (q.isPending) return <Skeleton active />
  const rep = q.data
  if (!rep) return <Alert type="info" showIcon title={t('vulnNoInventory')} />
  if (!rep.ecosystem) return <Alert type="info" showIcon title={t('vulnUnsupported', { n: rep.packages })} />

  const table = (rows: VulnPackage[], upgrade: boolean) => (
    <Table<VulnPackage> size="small" rowKey="source" dataSource={rows} pagination={{ pageSize: 15, hideOnSinglePage: true }}
      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('vulnNone')} /> }}
      expandable={{
        expandedRowRender: p => (
          <Table size="small" rowKey="id" pagination={false} dataSource={p.vulns}
            columns={[
              { title: 'ID', dataIndex: 'id', width: 230, render: (v: string, x) => <Space size={4} wrap><a href={`https://osv.dev/vulnerability/${v}`} target="_blank" rel="noreferrer" className="mono">{v}</a>{x.aliases?.filter(a => a !== v).map(a => <Tag key={a} className="mono">{a}</Tag>)}</Space> },
              { title: t('vulnMaxScore'), dataIndex: 'score', width: 80, render: v => <ScoreTag score={v} /> },
              ...(upgrade ? [{ title: t('vulnUpgrade'), dataIndex: 'fixed', width: 200, render: (v: string) => <span className="mono">{v}</span> }] : []),
              { title: t('thSummary'), dataIndex: 'summary', ellipsis: true },
            ]} />
        ),
      }}
      columns={[
        {
          title: t('vulnPackage'), dataIndex: 'source',
          render: (v, p) => (
            <Space size={6} wrap>
              <Tooltip title={p.binaries.join(', ')}><Typography.Text strong className="mono">{v}</Typography.Text></Tooltip>
              {p.exposed && <Tooltip title={t('vulnExposedHint')}><Tag color="red">{t('vulnExposed')}</Tag></Tooltip>}
            </Space>
          ),
        },
        { title: upgrade ? t('vulnUpgrade') : t('thVersion'), width: 320, render: (_, p) => <span className="mono">{p.version}{upgrade && <> → <Typography.Text type="success">{p.fixedIn}</Typography.Text></>}</span> },
        { title: t('vulnMaxScore'), dataIndex: 'maxScore', width: 90, sorter: (a, b) => a.maxScore - b.maxScore, render: v => <ScoreTag score={v} /> },
        { title: t('vulnCount'), width: 80, align: 'right', sorter: (a, b) => a.vulns.length - b.vulns.length, render: (_, p) => p.vulns.length },
      ]} />
  )

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Text type="secondary">
        {t('vulnMeta', { eco: rep.ecosystem, n: rep.packages, at: rep.softwareAt ? fmtTime(rep.softwareAt) : '-', sync: rep.sync ? fmtTime(rep.sync.at) : '-' })}
      </Typography.Text>
      {!rep.sync && <Alert type="info" showIcon title={t('vulnNotSynced')} />}
      {rep.sync?.error && <Alert type="warning" showIcon title={t('vulnSyncError', { error: rep.sync.error })} />}
      <Typography.Title level={5} style={{ margin: 0 }}>{t('vulnFixable')} · {rep.fixable?.length ?? 0}</Typography.Title>
      {table(rep.fixable ?? [], true)}
      <Collapse ghost items={[{
        key: 'unfixed', label: `${t('vulnUnfixed')} · ${rep.unfixed?.length ?? 0}`,
        children: <><Typography.Paragraph type="secondary">{t('vulnUnfixedHint')}</Typography.Paragraph>{table(rep.unfixed ?? [], false)}</>,
      }]} />
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('vulnHint')}</Typography.Text>
    </Space>
  )
}
