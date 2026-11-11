import { useQuery } from '@tanstack/react-query'
import { Card, Col, Flex, Space, Tag, Typography } from 'antd'
import { Link } from 'react-router'
import { fetchFacts, fetchIntents } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { RefTag } from './ControlRefs'
import { factLive } from './control'
import { fmtTime } from './format'

// 资产详情的「事实与意图」：这台主机上的有效事实与覆盖它的进行中意图；都没有就不占地方（连同栅格列一起不渲染，免得多出一道空行距）
export function AssetControlCard({ assetId }: { assetId: string }) {
  const { t } = useI18n()
  const facts = useQuery({ queryKey: ['facts', 'asset', assetId], queryFn: () => fetchFacts({ assetId }) })
  const intents = useQuery({ queryKey: ['intents', 'active'], queryFn: () => fetchIntents(true) })
  const liveFacts = (facts.data ?? []).filter(f => factLive(f))
  const covering = (intents.data ?? []).filter(i => i.assetIds.includes(assetId))
  if (liveFacts.length + covering.length === 0) return null
  return (
    <Col span={24}>
      <Card size="small" title={t('controlAssetCard')} extra={<Link to="/control">{t('navControl')}</Link>}>
        <Flex vertical gap={8}>
          {liveFacts.map(f => (
            <Space key={f.id} size={6} wrap>
              <RefTag value={f.ref} />
              <Tag variant="filled">{t(`factKind_${f.kind}` as MsgKey)}</Tag>
              <Typography.Text>{f.content}</Typography.Text>
              {f.holder && <Typography.Text type="secondary">· {f.holder}</Typography.Text>}
            </Space>
          ))}
          {covering.map(i => (
            <Space key={i.id} size={6} wrap>
              <RefTag value={i.ref} />
              <Tag variant="filled" color="purple">{t(`intentCat_${i.category}` as MsgKey)}</Tag>
              <Typography.Text>{i.createdBy}</Typography.Text>
              <Typography.Text type="secondary">{t('intentUntil', { at: fmtTime(i.expiresAt) })}</Typography.Text>
              {i.late && <Tag color="orange">{t('intentLate')}</Tag>}
            </Space>
          ))}
        </Flex>
      </Card>
    </Col>
  )
}
