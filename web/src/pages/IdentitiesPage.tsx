import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Select, Space, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { fetchIdentities, type IdentitySummary } from '../api'
import { useSession } from '../app/session'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { HostLink } from '../components/HostLink'
import { AccountKindTag, IdentityKindTag } from '../components/IdentityParts'
import { accountLabel } from '../components/identityText'
import { LoadError } from '../components/LoadError'
import { FilterCard, Page, STICKY_HEADER } from '../components/Page'
import { useI18n } from '../i18n'

const PAGE = 100

// 身份列表：当前组内的全局身份。目录账号是锚点，没有目录锚点的主机账号各自是主机内身份
export function IdentitiesPage() {
  const { t } = useI18n()
  const { group, me, groups } = useSession()
  const [search, setSearch] = useState('')
  const [q, setQ] = useState('')
  const [kind, setKind] = useState('')
  const [offset, setOffset] = useState(0)
  // 系统账号（_apt、bin、daemon 这类没登录过的）默认不列，打开开关才显示
  const [system, setSystem] = useState(false)
  const membership = groups.map(g => `${g.id}:${g.role}`).sort().join(',')
  const query = useQuery({
    queryKey: ['identities', me.username, me.role, membership, group?.id, q, kind, offset, system],
    queryFn: () => fetchIdentities(group!.id, q, kind, offset, system),
    enabled: !!group,
  })
  const reset = () => { setSearch(''); setQ(''); setKind(''); setOffset(0); setSystem(false) }

  return (
    <Page title={t('navIdentities')} subtitle={t('identitiesSubtitle')}>
      <FilterCard
        filters={<>
          <Input.Search allowClear placeholder={t('identitiesSearch')} style={{ width: 260 }} value={search}
            onChange={e => setSearch(e.target.value)} onSearch={v => { setQ(v.trim()); setOffset(0) }} />
          <Select value={kind} style={{ width: 160 }} onChange={v => { setKind(v); setOffset(0) }} aria-label={t('identityKind')}
            options={[{ value: '', label: t('identityKindAll') }, { value: 'directory', label: t('identityKindDirectory') }, { value: 'host', label: t('identityKindHost') }]} />
          <Tooltip title={t('identitySystemHint')}>
            <Space size={6}>
              <Switch size="small" checked={system} onChange={v => { setSystem(v); setOffset(0) }} aria-label={t('identityShowSystem')} />
              <Typography.Text type="secondary">{t('identityShowSystem')}</Typography.Text>
            </Space>
          </Tooltip>
        </>}
        onReset={q || kind || system ? reset : undefined}
        extra={<Refreshed at={query.dataUpdatedAt} fetching={query.isFetching} onRefresh={() => query.refetch()} />}>
        {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : <>
          <Table<IdentitySummary> sticky={STICKY_HEADER} size="small" rowKey="id" loading={query.isPending && !!group} dataSource={query.data?.items ?? []} pagination={false}
            scroll={{ x: 720 }}
            locale={{ emptyText: <EmptyHint title={t('identitiesEmpty')} hint={t('identitiesEmptyHint')} /> }}
            columns={[
              {
                title: t('identityName'), key: 'name',
                render: (_, r) => <Space size={4} wrap>
                  <Link to={`/identities/${r.id}`} style={{ overflowWrap: 'anywhere' }}>{accountLabel(r)}</Link>
                  {r.manual && <Tag color="gold">{t('identityManualTag')}</Tag>}
                  {r.system && <Tag>{t('identitySystemTag')}</Tag>}
                </Space>,
              },
              { title: t('identityKind'), dataIndex: 'kind', width: 130, render: v => <IdentityKindTag kind={v} /> },
              {
                title: t('identityAnchor'), key: 'anchor', width: 220,
                render: (_, r) => <Space size={4} wrap>
                  <AccountKindTag kind={r.anchorKind} />
                  {r.assetId ? <HostLink id={r.assetId} fallback={r.hostname ?? undefined} /> : <Typography.Text type="secondary" style={{ overflowWrap: 'anywhere' }}>{r.authority}</Typography.Text>}
                </Space>,
              },
              { title: t('identityAccounts'), dataIndex: 'accounts', width: 90 },
              { title: t('identityHosts'), dataIndex: 'hosts', width: 90 },
              { title: t('identityLastSeen'), dataIndex: 'lastSeen', width: 120, render: v => <Ago iso={v} /> },
            ]} />
          {(offset > 0 || query.data?.truncated) && <Space style={{ padding: '16px 4px 2px', width: '100%', justifyContent: 'flex-end' }}>
            <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>{t('directoryPrevious')}</Button>
            <Button disabled={!query.data?.truncated} onClick={() => setOffset(offset + PAGE)}>{t('directoryNext')}</Button>
          </Space>}
        </>}
      </FilterCard>
      {!group && <Alert type="info" showIcon title={t('identitiesNoGroup')} />}
    </Page>
  )
}
