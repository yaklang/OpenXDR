import { useQuery } from '@tanstack/react-query'
import { Card, Col, Flex, Space, Tag, Tooltip, Typography } from 'antd'
import { Link } from 'react-router'
import { fetchFacts, fetchIntents, fetchSSHKeys } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { RefTag } from './ControlRefs'
import { factLive, shortKeyFp } from './control'
import { fmtTime } from './format'

// 资产详情的「事实与意图」：这台主机上的有效事实、覆盖它的进行中意图与本机 SSH 授权钥匙观测；都没有就不占地方
export function AssetControlCard({ assetId }: { assetId: string }) {
  const { t } = useI18n()
  const facts = useQuery({ queryKey: ['facts', 'asset', assetId], queryFn: () => fetchFacts({ assetId }) })
  const intents = useQuery({ queryKey: ['intents', 'active'], queryFn: () => fetchIntents(true) })
  const sshKeys = useQuery({ queryKey: ['ssh-keys', 'asset', assetId], queryFn: () => fetchSSHKeys(assetId) })
  const liveFacts = (facts.data ?? []).filter(f => factLive(f))
  const covering = (intents.data ?? []).filter(i => i.assetIds.includes(assetId))
  const hostKeys = sshKeys.data?.keys ?? []
  if (liveFacts.length + covering.length + hostKeys.length === 0) return null
  return (
    <Col span={24}>
      <Card size="small" title={t('controlAssetCard')} extra={<Link to="/control">{t('navControl')}</Link>}>
        <Flex vertical gap={8}>
          {liveFacts.map(f => (
            <Space key={f.id} size={6} wrap>
              <RefTag value={f.ref} />
              <Tag variant="filled">{t(`factKind_${f.kind}` as MsgKey)}</Tag>
              <Typography.Text>{f.content}</Typography.Text>
              {f.holder && <Typography.Text type="secondary">· {f.holderName || f.holder}</Typography.Text>}
            </Space>
          ))}
          {covering.map(i => (
            <Space key={i.id} size={6} wrap>
              <RefTag value={i.ref} />
              <Tag variant="filled" color="purple">{t(`intentCat_${i.category}` as MsgKey)}</Tag>
              <Typography.Text>{i.createdByName || i.createdBy}</Typography.Text>
              <Typography.Text type="secondary">{t('intentUntil', { at: fmtTime(i.expiresAt) })}</Typography.Text>
              {i.late && <Tag color="orange">{t('intentLate')}</Tag>}
            </Space>
          ))}
          {hostKeys.map(k => (
            <Space key={k.id} size={6} wrap>
              <Link to="/control?tab=keys">
                <Tag variant="filled">{t('controlKeys')}</Tag>
              </Link>
              <span className="mono" style={{ fontSize: 12.5 }}>{k.account}</span>
              <Tooltip title={k.fingerprint}>
                <Typography.Text className="mono" copyable={{ text: k.fingerprint }} style={{ fontSize: 12 }}>
                  {shortKeyFp(k.fingerprint)}
                </Typography.Text>
              </Tooltip>
              <Tag color={k.usageStatus === 'active' ? 'green' : undefined}>
                {t(k.usageStatus === 'active' ? 'keyActive' : 'keyIdle')}
              </Tag>
              {k.claimStatus === 'claimed' ? (
                <>
                  <Tag color="blue">{t('keyClaimed')}</Tag>
                  {k.factRef && <RefTag value={k.factRef} />}
                </>
              ) : (
                <Tag color="orange">{t('keyUnclaimed')}</Tag>
              )}
            </Space>
          ))}
        </Flex>
      </Card>
    </Col>
  )
}
