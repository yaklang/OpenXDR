import { useQuery } from '@tanstack/react-query'
import { Alert, Empty, Space, Table, Tag, Typography } from 'antd'
import { fetchAssetChangeRecords, type AssetChangeRecordRow } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

export function AssetChangeRecords({ assetId }: { assetId: string }) {
  const { t } = useI18n()
  const query = useQuery({
    queryKey: ['assetChangeRecords', assetId],
    queryFn: () => fetchAssetChangeRecords(assetId, 30),
  })

  if (query.isError) {
    return <LoadError error={query.error} onRetry={() => query.refetch()} />
  }

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <Alert type="info" showIcon title={t('assetChangesDisclaimer')} />
      <Table<AssetChangeRecordRow>
        size="small"
        rowKey="id"
        loading={query.isPending}
        dataSource={query.data ?? []}
        scroll={{ x: 820 }}
        pagination={{ pageSize: 15, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('assetChangesEmpty')} /> }}
        expandable={{
          rowExpandable: r => Boolean(r.body || r.files.length > 0),
          expandedRowRender: r => (
            <Space orientation="vertical" size={8} style={{ width: '100%' }}>
              {r.body && (
                <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
                  {r.body}
                </Typography.Paragraph>
              )}
              {r.files.length > 0 && (
                <div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {t('changeFilesList')} ({r.fileCount}):
                  </Typography.Text>
                  <pre className="json-block" style={{ marginTop: 4, marginBottom: 0 }}>
                    {r.files.join('\n')}
                  </pre>
                </div>
              )}
            </Space>
          ),
        }}
        columns={[
          {
            title: t('changeCommittedAt'),
            dataIndex: 'committedAt',
            width: 170,
            render: fmtTime,
          },
          {
            title: t('changeRepoAndSha'),
            width: 240,
            render: (_, r) => (
              <Space size={6} wrap>
                <Typography.Text className="mono" style={{ fontSize: 12.5 }}>{r.repo}</Typography.Text>
                <Tag className="mono">{r.shortSha}</Tag>
              </Space>
            ),
          },
          {
            title: t('changeTitle'),
            dataIndex: 'title',
          },
          {
            title: t('changeAuthor'),
            dataIndex: 'author',
            width: 140,
            render: v => v || '—',
          },
          {
            title: t('changeFilesCount'),
            dataIndex: 'fileCount',
            width: 100,
          },
          {
            title: t('changeClues'),
            width: 190,
            render: (_, r) => (
              <Space size={[4, 4]} wrap>
                {r.clues.map(c => <Tag key={c} variant="filled" className="mono">{c}</Tag>)}
              </Space>
            ),
          },
        ]}
      />
    </Space>
  )
}
