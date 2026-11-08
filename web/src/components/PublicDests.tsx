import { ExportOutlined, RobotOutlined } from '@ant-design/icons'
import { Button, Space, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import type { PublicDest } from '../api'
import { useI18n } from '../i18n'
import { Ago } from './Ago'
import { useCanChat, useHandoff } from './Handoff'

// VirusTotal 判定：有引擎判恶意标红、可疑标橙，查过没检出给个中性标签，没查过不显示
function VTTag({ d }: { d: PublicDest }) {
  const { t } = useI18n()
  if (d.malicious) return <Tag color="error">{t('vtMalicious', { n: d.malicious })}</Tag>
  if (d.suspicious) return <Tag color="warning">{t('vtSuspicious', { n: d.suspicious })}</Tag>
  return d.checked ? <Tag>{t('vtClean')}</Tag> : null
}

// 公网外联明细：每个地址一行，先回答「这是什么」（反查域名、AI 用途、归属），再给连接事实。
// 认不出的地址可以交给 AI 上机调查；给了 host 才显示（需要知道是哪台主机连的）
export function PublicDestList({ items, host, limit = 8 }: {
  items: PublicDest[]
  host?: { id: string; name: string; groupId?: string | null }
  limit?: number
}) {
  const { t } = useI18n()
  const [all, setAll] = useState(false)
  const canChat = useCanChat()
  const handoff = useHandoff()
  const shown = all ? items : items.slice(0, limit)
  const investigate = (d: PublicDest) => host?.groupId && handoff.start(host.groupId, [], t('investigateEgressTitle', { host: host.name, ip: d.ip }),
    t('investigateEgressPrompt', { host: host.name, id: host.id, ip: d.ip, ports: d.ports.join(', '), process: d.processes?.join(', ') || '-' }))

  return (
    <div className="dest-list">
      {shown.map(d => {
        const name = d.ptr || d.domains?.[0]
        return (
          <div key={d.ip} className="dest-row">
            <div className="dest-main">
              <Space size={6} wrap>
                <Typography.Text className="mono" copyable={{ text: d.ip }}>{d.ip}</Typography.Text>
                {name && <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{name}</Typography.Text>}
                <VTTag d={d} />
              </Space>
              <div>
                {/* 调查或人工结论优先，其次资产标注时 AI 的推断 */}
                {d.note ? (
                  <Tooltip title={d.note.note}>
                    <Space size={4} wrap>
                      <Typography.Text strong>{d.note.name}</Typography.Text>
                      <Tag color={d.note.source === 'human' ? 'green' : 'blue'} variant="filled">{t(d.note.source === 'human' ? 'egressHuman' : 'egressInvestigated')}</Tag>
                      {d.note.risk && d.note.risk !== 'low' && <Tag color={d.note.risk === 'high' ? 'orange' : 'gold'}>{t(d.note.risk === 'high' ? 'riskHigh' : 'riskMedium')}</Tag>}
                    </Space>
                  </Tooltip>
                ) : d.purpose ? <Typography.Text strong>{d.purpose}</Typography.Text> : <Typography.Text type="secondary">{t('egressUnknown')}</Typography.Text>}
                {(d.owner || d.asn || d.country) && <Typography.Text type="secondary"> · {[d.owner, d.asn && `AS${d.asn}`, d.country].filter(Boolean).join(' · ')}</Typography.Text>}
              </div>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {d.ports.join(' ')}
                {d.processes?.length ? ` · ${d.processes.join(', ')}` : ''}
                {' · '}{t('connCount', { n: d.count.toLocaleString() })}{' · '}<Ago iso={d.lastSeen} />
              </Typography.Text>
            </div>
            <Space size={0} className="dest-actions">
              <Tooltip title={t('openVT')}>
                <Button type="text" size="small" icon={<ExportOutlined />} aria-label={t('openVT')}
                  href={`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(d.ip)}`} target="_blank" rel="noopener noreferrer" />
              </Tooltip>
              {host?.groupId && canChat(host.groupId) && !d.note && (
                <Tooltip title={t('investigateEgress')}>
                  <Button type="text" size="small" icon={<RobotOutlined />} aria-label={t('investigateEgress')} loading={handoff.busy} onClick={() => investigate(d)} />
                </Tooltip>
              )}
            </Space>
          </div>
        )
      })}
      {items.length > limit && (
        <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setAll(!all)}>
          {all ? t('collapse') : t('showAllN', { n: items.length })}
        </Button>
      )}
      {/* DB-IP Lite 是 CC BY 4.0：展示了它的数据就署名并链接 */}
      {shown.some(d => d.ipdb) && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">{t('ipdbAttribution')}</a>
        </Typography.Text>
      )}
    </div>
  )
}
