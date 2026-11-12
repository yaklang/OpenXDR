import { useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { Alert, App, Button, Flex, Form, Input, InputNumber, Modal, Segmented, Select, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { claimSSHKey, proposeSSHKeyRemoval, type SSHKeyObservation, type SSHKeysResponse } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { Ago, EmptyHint } from './Ago'
import { Clamp } from './Clamp'
import { RefTag } from './ControlRefs'
import { HostLink } from './HostLink'
import { LoadError } from './LoadError'
import { STICKY_HEADER, TableCard } from './Page'
import { TableActions } from './TableActions'
import { shortKeyFp } from './control'
import { errText, fmtTime } from './format'

interface ClaimDraft {
  holder: string
  machine: string
  purpose: string
  groupId?: string
  expiresInDays: number
}

type KeyFilter = 'all' | 'unclaimed' | 'claimed' | 'idle'

export function ControlKeysTab({ sshKeys }: { sshKeys: UseQueryResult<SSHKeysResponse> }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin, groups } = useSession()
  const [filter, setFilter] = useState<KeyFilter>('all')
  const [claiming, setClaiming] = useState<SSHKeyObservation | null>(null)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm<ClaimDraft>()

  if (sshKeys.isError) return <LoadError error={sshKeys.error} onRetry={() => sshKeys.refetch()} />

  const all = sshKeys.data?.keys ?? []
  const hostConfigs = sshKeys.data?.hostConfigs ?? []
  const rows = all.filter(r => {
    if (filter === 'unclaimed') return r.claimStatus === 'unclaimed'
    if (filter === 'claimed') return r.claimStatus === 'claimed'
    if (filter === 'idle') return r.usageStatus === 'idle'
    return true
  })

  const canManageGroup = (groupId: string | null) =>
    isAdmin || (!!groupId && groups.some(g => g.id === groupId && g.role === 'admin'))

  const showActions = isAdmin || all.some(r => r.claimStatus === 'unclaimed' && canManageGroup(r.groupId))

  const submitClaim = async (draft: ClaimDraft) => {
    if (!claiming) return
    setBusy(true)
    try {
      const created = await claimSSHKey({
        fingerprint: claiming.fingerprint,
        holder: draft.holder.trim(),
        machine: draft.machine.trim(),
        purpose: draft.purpose.trim(),
        ...(draft.groupId ? { groupId: draft.groupId } : {}),
        expiresInDays: draft.expiresInDays,
      })
      message.success(t('keyClaimedOk', { ref: created.ref }))
      setClaiming(null)
      await Promise.all([
        client.invalidateQueries({ queryKey: ['ssh-keys'] }),
        client.invalidateQueries({ queryKey: ['facts'] }),
      ])
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  const triggerRemoval = async (row: SSHKeyObservation) => {
    setBusy(true)
    try {
      await proposeSSHKeyRemoval(row.id)
      message.success(t('keyRemovalProposed'))
      await Promise.all([
        client.invalidateQueries({ queryKey: ['ssh-keys'] }),
        client.invalidateQueries({ queryKey: ['approvals'] }),
      ])
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Flex vertical gap={16}>
      {hostConfigs.length > 0 && (
        <Alert
          type="info"
          showIcon
          title={t('keyDynamicCmdNote')}
          description={
            <Flex vertical gap={4}>
              {hostConfigs.map(hc => (
                <Flex key={hc.assetId} gap={8} wrap align="center">
                  <HostLink id={hc.assetId} fallback={hc.hostname} />
                  <code className="mono">{hc.authorizedKeysCommand}</code>
                  {hc.authorizedKeysCommandUser && <Tag>{hc.authorizedKeysCommandUser}</Tag>}
                </Flex>
              ))}
            </Flex>
          }
        />
      )}

      <div>
        <Segmented
          value={filter}
          onChange={v => setFilter(v as KeyFilter)}
          options={[
            { value: 'all', label: `${t('keyFilterAll')} ${all.length}` },
            { value: 'unclaimed', label: `${t('keyFilterUnclaimed')} ${all.filter(k => k.claimStatus === 'unclaimed').length}` },
            { value: 'claimed', label: `${t('keyFilterClaimed')} ${all.filter(k => k.claimStatus === 'claimed').length}` },
            { value: 'idle', label: `${t('keyFilterIdle')} ${all.filter(k => k.usageStatus === 'idle').length}` },
          ]}
        />
      </div>

      <TableCard>
        <Table<SSHKeyObservation>
          sticky={STICKY_HEADER}
          rowKey="id"
          loading={sshKeys.isPending}
          dataSource={rows}
          pagination={{ pageSize: 20, showSizeChanger: false, hideOnSinglePage: true }}
          scroll={{ x: 1280 }}
          locale={{ emptyText: <EmptyHint title={t('keyEmpty')} hint={t('keyEmptyHint')} /> }}
          columns={[
            {
              title: t('keyShortFp'),
              dataIndex: 'fingerprint',
              width: 210,
              render: (v: string, r) => (
                <Flex vertical gap={2} align="flex-start">
                  <Tooltip title={v}>
                    <Typography.Text className="mono" copyable={{ text: v }} style={{ fontSize: 12.5 }}>
                      {shortKeyFp(v)}
                    </Typography.Text>
                  </Tooltip>
                  <Typography.Text type="secondary" style={{ fontSize: 11.5 }}>{r.keyType}</Typography.Text>
                </Flex>
              ),
            },
            {
              title: t('keyComment'),
              dataIndex: 'comment',
              width: 220,
              render: (v: string) =>
                v ? (
                  <Flex gap={6} align="center" wrap>
                    <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>
                      <Clamp text={v} />
                    </Typography.Text>
                    <Tooltip title={t('keyHintOnlyTip')}>
                      <Tag variant="filled">{t('keyHintOnly')}</Tag>
                    </Tooltip>
                  </Flex>
                ) : (
                  <Typography.Text type="secondary">-</Typography.Text>
                ),
            },
            {
              title: t('thHostname'),
              key: 'host',
              width: 150,
              render: (_, r) => (
                <Tooltip title={r.filePath}>
                  <span><HostLink id={r.assetId} fallback={r.hostname} /></span>
                </Tooltip>
              ),
            },
            {
              title: t('keyAccount'),
              dataIndex: 'account',
              width: 120,
              render: (v: string, r) => {
                const who = [r.addedByUser, r.addedByIp, r.addedByKeyFp ? shortKeyFp(r.addedByKeyFp) : ''].filter(Boolean).join(' @ ')
                const node = <span className="mono" style={{ fontSize: 12.5 }}>{v}</span>
                return who ? <Tooltip title={t('keyAddedBy', { who })}>{node}</Tooltip> : node
              },
            },
            {
              title: t('keyOptions'),
              dataIndex: 'options',
              width: 180,
              render: (opts: string[]) =>
                opts && opts.length > 0 ? (
                  <Flex wrap gap={4}>
                    {opts.map((opt, idx) => (
                      <Tooltip key={idx} title={opt}>
                        <Tag className="mono" style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {opt}
                        </Tag>
                      </Tooltip>
                    ))}
                  </Flex>
                ) : (
                  <Typography.Text type="secondary">-</Typography.Text>
                ),
            },
            {
              title: t('keyLastLogin'),
              key: 'lastLogin',
              width: 190,
              render: (_, r) =>
                r.lastLoginAt ? (
                  <Flex vertical gap={0}>
                    <Tooltip title={fmtTime(r.lastLoginAt)}>
                      <span><Ago iso={r.lastLoginAt} /></span>
                    </Tooltip>
                    {r.lastLoginIp && (
                      <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
                        {r.lastLoginIp}
                      </Typography.Text>
                    )}
                  </Flex>
                ) : (
                  <Typography.Text type="secondary">{t('keyNoLogin')}</Typography.Text>
                ),
            },
            {
              title: t('thStatus'),
              key: 'status',
              width: 220,
              render: (_, r) => (
                <Flex wrap gap={4} align="center">
                  {r.usageStatus === 'active' ? (
                    <Tag color="green">{t('keyActive')}</Tag>
                  ) : (
                    <Tooltip title={t('keyIdleTip')}>
                      <Tag>{t('keyIdle')}</Tag>
                    </Tooltip>
                  )}
                  {r.claimStatus === 'claimed' ? (
                    <Tooltip title={[r.holderName || r.holder, r.factContent].filter(Boolean).join(' · ')}>
                      <Tag color="blue">{t('keyClaimed')}</Tag>
                    </Tooltip>
                  ) : (
                    <Tag color="orange">{t('keyUnclaimed')}</Tag>
                  )}
                  {r.factRef && <RefTag value={r.factRef} />}
                  {r.removalStatus === 'pending' && (
                    <Link to="/approvals">
                      <Tag color="processing">{t('keyRemovalPending')}</Tag>
                    </Link>
                  )}
                </Flex>
              ),
            },
            ...(showActions
              ? [
                  {
                    title: t('actions'),
                    key: 'act',
                    width: 150,
                    fixed: 'right' as const,
                    render: (_: unknown, r: SSHKeyObservation) => (
                      <TableActions>
                        {isAdmin && r.claimStatus === 'unclaimed' && (
                          <Button
                            type="link"
                            size="small"
                            disabled={busy}
                            onClick={() => {
                              form.resetFields()
                              setClaiming(r)
                            }}
                          >
                            {t('keyClaim')}
                          </Button>
                        )}
                        {r.claimStatus === 'unclaimed' && r.removalStatus !== 'pending' && canManageGroup(r.groupId) && (
                          <Button type="link" size="small" danger disabled={busy} onClick={() => triggerRemoval(r)}>
                            {t('keyProposeRemove')}
                          </Button>
                        )}
                      </TableActions>
                    ),
                  },
                ]
              : []),
          ]}
        />
      </TableCard>

      <Modal
        open={claiming !== null}
        title={t('keyClaimTitle')}
        onCancel={() => { if (!busy) setClaiming(null) }}
        onOk={() => form.submit()}
        confirmLoading={busy}
        width={560}
        destroyOnHidden
      >
        {claiming && (
          <Form<ClaimDraft>
            form={form}
            layout="vertical"
            disabled={busy}
            initialValues={{ expiresInDays: 0 }}
            onFinish={submitClaim}
          >
            <Form.Item label={t('factKeySubject')}>
              <Typography.Text className="mono" copyable style={{ fontSize: 12.5 }}>
                {claiming.fingerprint}
              </Typography.Text>
              {claiming.comment && (
                <div style={{ marginTop: 4 }}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {claiming.comment}
                  </Typography.Text>{' '}
                  <Tag variant="filled">{t('keyHintOnly')}</Tag>
                </div>
              )}
            </Form.Item>
            <Form.Item name="holder" label={t('factHolder')} extra={t('factHolderHint')} rules={[{ required: true, whitespace: true, max: 256 }]}>
              <Input placeholder="user:alice" />
            </Form.Item>
            <Form.Item name="machine" label={t('keyMachine')} extra={t('keyMachineHint')} rules={[{ required: true, whitespace: true, max: 256 }]}>
              <Input />
            </Form.Item>
            <Form.Item name="purpose" label={t('keyPurpose')} extra={t('keyPurposeHint')} rules={[{ required: true, whitespace: true, max: 600 }]}>
              <Input.TextArea rows={2} />
            </Form.Item>
            <Form.Item name="groupId" label={t('group')} extra={t('factGroupHint')}>
              <Select allowClear options={groups.map(g => ({ value: g.id, label: g.name }))} />
            </Form.Item>
            <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('factValidityHint')} rules={[{ required: true }]}>
              <InputNumber min={0} max={3650} />
            </Form.Item>
          </Form>
        )}
      </Modal>
    </Flex>
  )
}
