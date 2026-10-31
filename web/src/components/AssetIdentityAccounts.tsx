import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Select, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { fetchAssetIdentityAccounts, type Asset, type IdentityAccount, type UnmatchedLogin } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { AccountName, BasisTag, LoginSummary } from './IdentityParts'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

const UNMATCHED: Record<UnmatchedLogin['state'], MsgKey> = {
  no_account: 'loginMatchNoAccount', no_snapshot: 'loginMatchNoSnapshot', snapshot_unavailable: 'loginMatchSnapshotUnavailable',
}

// 资产上登记过的账号、近期登录与所属身份；Linux 登录关联不上账号的单独列出，不做猜测
export function AssetIdentityAccounts({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const { me, groups } = useSession()
  const [hours, setHours] = useState(24)
  const scope = `${me.username}:${me.role}:${groups.map(g => `${g.id}:${g.role}`).sort().join(',')}:${asset.id}:${asset.groupId}`
  const query = useQuery({ queryKey: ['assetIdentityAccounts', scope, hours], queryFn: () => fetchAssetIdentityAccounts(asset.id, hours), gcTime: 0, refetchInterval: 30000 })
  const data = query.data
  return <Space orientation="vertical" size={14} style={{ width: '100%' }}>
    <Typography.Title level={5} style={{ margin: 0 }}>{t('assetAccountsTitle')}</Typography.Title>
    <Typography.Text type="secondary">{t('assetAccountsHint')}</Typography.Text>
    <div className="filter-bar" style={{ padding: '10px 14px' }}>
      <Space wrap className="filter-controls">
        <Select aria-label={t('thTime')} value={hours} style={{ width: 170 }} onChange={setHours}
          options={[1, 6, 24, 72, 168, 720].map(n => ({ value: n, label: t('lastHours', { n }) }))} />
        <Button loading={query.isFetching} onClick={() => query.refetch()}>{t('refresh')}</Button>
      </Space>
    </div>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
      {!!data?.pending && <Alert type="info" showIcon title={t('assetAccountsPending', { n: data.pending })} />}
      {data?.truncated && <Alert type="info" showIcon title={t('identityAccountsTruncated')} />}
      <Table<IdentityAccount> size="small" rowKey="id" loading={query.isPending} dataSource={data?.accounts ?? []} scroll={{ x: 720 }}
        pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('assetAccountsEmpty')} /> }}
        columns={[
          { title: t('thUser'), key: 'account', render: (_, a) => <AccountName account={a} /> },
          { title: t('identityLogins'), dataIndex: 'logins', width: 240, render: v => <LoginSummary stat={v} /> },
          { title: t('identityLastInInventory'), dataIndex: 'lastSeen', width: 170, render: fmtTime },
          {
            title: t('identityName'), key: 'identity', width: 200,
            render: (_, a) => a.identityId
              ? <Space size={4} wrap><BasisTag basis={a.basis} /><Link to={`/identities/${a.identityId}`}>{t('identityOpen')}</Link></Space>
              : <Typography.Text type="secondary">{t('identityNotLinked')}</Typography.Text>,
          },
        ]} />
      {(data?.unmatched.length ?? 0) > 0 && <>
        <Typography.Text strong>{t('assetAccountsUnmatched')}</Typography.Text>
        <Table<UnmatchedLogin> size="small" rowKey={u => `${u.name}:${u.state}`} dataSource={data?.unmatched ?? []} scroll={{ x: 720 }}
          pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
          columns={[
            { title: t('thUser'), dataIndex: 'name', render: v => <span style={{ overflowWrap: 'anywhere' }}>{v}</span> },
            { title: t('loginMatchState'), dataIndex: 'state', width: 200, render: (v: UnmatchedLogin['state']) => <Tag color="warning">{t(UNMATCHED[v] ?? 'identityUnknown')}</Tag> },
            { title: t('identityLogins'), key: 'logins', width: 240, render: (_, u) => <LoginSummary stat={u} /> },
          ]} />
      </>}
    </>}
  </Space>
}
