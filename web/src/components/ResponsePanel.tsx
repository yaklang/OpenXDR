import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Collapse, Empty, Input, Pagination, Select, Space, Typography } from 'antd'
import { useState } from 'react'
import { fetchCommandsPage, issueCommand } from '../api'
import { CommandDetailDrawer } from './CommandDetailDrawer'
import { LoadError } from './LoadError'
import { useI18n, type MsgKey } from '../i18n'
import { CommandStatusTag, commandKind, fmtTime, errText } from './format'

// 带目标的处置：正反成对，目标的写法与说明跟着动作走
const TARGETED: { kind: string; placeholder: MsgKey; hint: MsgKey }[] = [
  { kind: 'block_network', placeholder: 'targetNetwork', hint: 'actionNetworkHint' },
  { kind: 'unblock_network', placeholder: 'targetNetwork', hint: 'actionNetworkHint' },
  { kind: 'quarantine_file', placeholder: 'targetFile', hint: 'actionFileHint' },
  { kind: 'restore_file', placeholder: 'targetFile', hint: 'actionFileHint' },
  { kind: 'disable_account', placeholder: 'targetAccount', hint: 'actionAccountHint' },
  { kind: 'enable_account', placeholder: 'targetAccount', hint: 'actionAccountHint' },
]

// 响应处置：每个动作都在主机上真实生效，下发前必须二次确认，避免手滑隔离生产主机
export function ResponsePanel({ incidentId, assetId, canAct }: { incidentId: string; assetId: string | null; canAct: boolean }) {
  const { t } = useI18n()
  const { modal, message } = App.useApp()
  const client = useQueryClient()
  const [busy, setBusy] = useState(false)
  const [page, setPage] = useState(1)
  const [detail, setDetail] = useState<string | null>(null)
  const history = useQuery({ queryKey: ['commands', incidentId, page], queryFn: () => fetchCommandsPage({ incidentId }, page), refetchInterval: 5_000 })

  const [kind, setKind] = useState<string>()
  const [target, setTarget] = useState('')
  const picked = TARGETED.find(x => x.kind === kind)

  const issue = (kind: string, target?: string) => {
    if (!assetId) return
    const go = async () => {
      setBusy(true)
      try {
        await issueCommand({ kind, assetId, incidentId, target })
        message.success(t('cmdIssuedLive'))
        if (target) setTarget('')
      } catch (e) {
        message.error(errText(e, t))
      } finally {
        setBusy(false)
        client.invalidateQueries({ queryKey: ['commands', incidentId] })
      }
    }
    const title = target ? t('confirmTargeted', { kind: commandKind(kind, t), target }) : t('confirmLive', { kind: commandKind(kind, t) })
    modal.confirm({ title, okButtonProps: { danger: true }, onOk: go })
  }

  return (
    <Card title={t('responseTitle')}>
      {!assetId ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noAssetForResponse')} />
      ) : (
        <Space orientation="vertical" style={{ width: '100%' }}>
          {canAct && (
            <>
              <Space wrap>
                <Button danger loading={busy} onClick={() => issue('isolate_host')}>{t('isolateHost')}</Button>
                <Button loading={busy} onClick={() => issue('unisolate_host')}>{t('unisolateHost')}</Button>
              </Space>
              <Typography.Text type="secondary">{t('liveWarning')}</Typography.Text>
              <Collapse ghost size="small" items={[{
                key: 'more', label: t('moreActions'),
                children: (
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Select style={{ width: '100%' }} placeholder={t('pickAction')} value={kind} onChange={k => setKind(k)}
                      options={TARGETED.map(x => ({ value: x.kind, label: commandKind(x.kind, t) }))} />
                    {picked && (
                      <>
                        <Input aria-label={t(picked.placeholder)} placeholder={t(picked.placeholder)} value={target} maxLength={512}
                          onChange={e => setTarget(e.target.value)} onPressEnter={() => target.trim() && issue(picked.kind, target.trim())} />
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t(picked.hint)}</Typography.Text>
                        <Button danger loading={busy} disabled={!target.trim()} onClick={() => issue(picked.kind, target.trim())}>{t('issue')}</Button>
                      </>
                    )}
                  </Space>
                ),
              }]} />
            </>
          )}
          {/* 右侧窄栏放不下表格，记录按行排：动作 · 状态，下一行时间与结果 */}
          {history.isError && <LoadError error={history.error} onRetry={() => history.refetch()} />}
          {history.isPending ? null : (history.data?.items ?? []).length === 0 ? (
            <Typography.Text type="secondary">{t('noCommands')}</Typography.Text>
          ) : (
            <div className="cmd-list">
              {history.data!.items.map(c => (
                <div key={c.id} className="cmd-item">
                  <Space size={6} wrap>
                    <Typography.Text strong>{commandKind(c.kind, t)}</Typography.Text>
                    {c.target && <Typography.Text className="mono" style={{ fontSize: 12 }}>{c.target}</Typography.Text>}
                    <CommandStatusTag value={c.status} />
                  </Space>
                  <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12 }}>
                    {fmtTime(c.createdAt)}{c.issuedBy ? ` · ${c.issuedBy}` : ''}
                  </Typography.Text>
                  <Button type="link" size="small" onClick={() => setDetail(c.id)}>{t('commandViewDetail')}</Button>
                  {c.detail && <Typography.Text style={{ fontSize: 12 }} ellipsis={{ tooltip: c.detail }}>{c.detail}</Typography.Text>}
                </div>
              ))}
            </div>
          )}
        </Space>
      )}
      <Pagination size="small" current={page} pageSize={10} total={history.data?.total ?? 0} onChange={setPage} showSizeChanger={false} hideOnSinglePage />
      {detail && <CommandDetailDrawer id={detail} onClose={() => setDetail(null)} />}
    </Card>
  )
}
