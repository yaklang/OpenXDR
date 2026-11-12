import { useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { Alert, App, Button, Card, Drawer, Flex, Form, Input, InputNumber, Modal, Popconfirm, Select, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import {
  createStandingRule,
  deleteStandingRule,
  fetchAssets,
  fetchStandingRuleRuns,
  fetchStandingRuleTemplates,
  updateStandingRule,
  type StandingRule,
  type StandingRuleRun,
  type StandingRuleTier,
} from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { Ago, EmptyHint } from './Ago'
import { Clamp } from './Clamp'
import { HostLink } from './HostLink'
import { LoadError } from './LoadError'
import { STICKY_HEADER, TableCard } from './Page'
import { TableActions } from './TableActions'
import { errText, fmtTime } from './format'

const TIER_COLORS: Record<StandingRuleTier, string> = {
  auto: 'green',
  propose: 'blue',
  human: 'gold',
}

const RUN_STATUS_COLORS: Record<string, string> = {
  succeeded: 'green',
  failed: 'red',
  pending_approval: 'processing',
  rejected: 'default',
  expired: 'warning',
  queued_human: 'gold',
  skipped: 'default',
}

interface RuleFormValues {
  actionTemplate: string
  name: string
  conditionSummary: string
  tier: StandingRuleTier
  groupId?: string
  assetIds?: string[]
  maintenanceWindow?: string
  cooldownMinutes: number
  enabled: boolean
  unitsText?: string
  pathsText?: string
  minAgeDays?: number
  allowedCidrsText?: string
  portsText?: string
}

function splitList(raw?: string): string[] {
  if (!raw) return []
  return raw
    .split(/[\n,]+/)
    .map(s => s.trim())
    .filter(Boolean)
}

function splitPortList(raw?: string): number[] {
  return splitList(raw)
    .map(s => Number(s))
    .filter(n => Number.isInteger(n) && n >= 1 && n <= 65535)
}

function readParamStrings(params: Record<string, unknown> | undefined, key: string): string[] {
  const v = params?.[key]
  return Array.isArray(v) ? v.map(x => String(x)) : []
}

function readParamNumber(params: Record<string, unknown> | undefined, key: string, fallback: number): number {
  const v = params?.[key]
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback
}

export function StandingRulesTab({
  rules,
  refId,
  adding,
  onCloseAdd,
}: {
  rules: UseQueryResult<StandingRule[]>
  refId: string
  adding: boolean
  onCloseAdd: () => void
}) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin, groups } = useSession()
  const [busyId, setBusyId] = useState<string | null>(null)
  const [editing, setEditing] = useState<StandingRule | null>(null)
  const [inspecting, setInspecting] = useState<StandingRule | null>(null)
  const [form] = Form.useForm<RuleFormValues>()
  const modalOpen = adding || editing !== null

  const templates = useQuery({
    queryKey: ['standingRuleTemplates'],
    queryFn: fetchStandingRuleTemplates,
    enabled: modalOpen,
  })
  const assets = useQuery({
    queryKey: ['assets'],
    queryFn: () => fetchAssets(),
    enabled: modalOpen,
  })
  const runs = useQuery({
    queryKey: ['standingRuleRuns', inspecting?.id],
    queryFn: () => fetchStandingRuleRuns(inspecting!.id),
    enabled: inspecting !== null,
  })

  const selectedGroup = Form.useWatch('groupId', form)
  const selectedTplKey = Form.useWatch('actionTemplate', form)
  const all = rules.data ?? []

  useEffect(() => {
    if (!refId || all.length === 0) return
    const hit = all.find(r => r.ref === refId)
    if (hit) {
      requestAnimationFrame(() => document.querySelector(`[data-row-key="${hit.id}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' }))
    }
  }, [refId, all])

  useEffect(() => {
    if (!modalOpen) return
    if (editing) {
      form.setFieldsValue({
        actionTemplate: editing.actionTemplate,
        name: editing.name,
        conditionSummary: editing.conditionSummary,
        tier: editing.tier,
        groupId: editing.groupId ?? undefined,
        assetIds: editing.assetIds ?? [],
        maintenanceWindow: editing.maintenanceWindow,
        cooldownMinutes: editing.cooldownMinutes,
        enabled: editing.enabled,
        unitsText: readParamStrings(editing.actionParams, 'units').join(', '),
        pathsText: readParamStrings(editing.actionParams, 'paths').join(', '),
        minAgeDays: readParamNumber(editing.actionParams, 'min_age_days', 7),
        allowedCidrsText: readParamStrings(editing.actionParams, 'allowed_cidrs').join(', '),
        portsText: readParamStrings(editing.actionParams, 'ports').join(', '),
      })
    } else {
      const customDefault = (templates.data ?? []).find(x => !x.builtin) ?? (templates.data ?? [])[0]
      form.resetFields()
      if (customDefault) {
        form.setFieldsValue({
          actionTemplate: customDefault.key,
          name: customDefault.name,
          conditionSummary: customDefault.conditionSummary,
          tier: customDefault.defaultTier,
          maintenanceWindow: customDefault.defaultWindow ?? '',
          cooldownMinutes: customDefault.defaultCooldownMinutes,
          enabled: false,
          minAgeDays: 7,
        })
      }
    }
  }, [modalOpen, editing, templates.data, form])

  const mutate = async (id: string, fn: () => Promise<unknown>, after?: () => void) => {
    setBusyId(id)
    try {
      await fn()
      after?.()
      await client.invalidateQueries({ queryKey: ['standingRules'] })
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusyId(null)
    }
  }

  const onPickTemplate = (key: string) => {
    const tpl = (templates.data ?? []).find(x => x.key === key)
    if (!tpl || editing) return
    form.setFieldsValue({
      name: tpl.name,
      conditionSummary: tpl.conditionSummary,
      tier: tpl.defaultTier,
      maintenanceWindow: tpl.defaultWindow ?? '',
      cooldownMinutes: tpl.defaultCooldownMinutes,
      pathsText: readParamStrings(tpl.defaultParams, 'paths').join(', '),
      portsText: readParamStrings(tpl.defaultParams, 'ports').join(', '),
    })
  }

  const buildActionParams = (v: RuleFormValues, base?: Record<string, unknown>): Record<string, unknown> => {
    const next: Record<string, unknown> = { ...(base ?? {}) }
    if (v.actionTemplate === 'restart_failed_service') {
      next.units = splitList(v.unitsText)
    }
    if (v.actionTemplate === 'reclaim_disk' || v.actionTemplate === 'old_backup_compress') {
      next.paths = splitList(v.pathsText)
      next.min_age_days = v.minAgeDays ?? 7
    }
    if (v.actionTemplate === 'mgmt_port_restrict') {
      next.allowed_cidrs = splitList(v.allowedCidrsText)
      const ports = splitPortList(v.portsText)
      if (ports.length > 0) next.ports = ports
    }
    return next
  }

  if (rules.isError) return <LoadError error={rules.error} onRetry={() => rules.refetch()} />

  const activeTpl = (templates.data ?? []).find(x => x.key === (editing?.actionTemplate ?? selectedTplKey))
  const allowedTiers: StandingRuleTier[] = activeTpl?.allowedTiers ?? editing?.allowedTiers ?? ['propose', 'human']
  const linuxAssets = (assets.data ?? []).filter(a => (!selectedGroup || a.groupId === selectedGroup) && (!a.os || a.os.toLowerCase() === 'linux'))

  return (
    <>
      <TableCard>
        <Table<StandingRule>
          sticky={STICKY_HEADER}
          rowKey="id"
          loading={rules.isPending}
          dataSource={all}
          pagination={{ pageSize: 20, showSizeChanger: false, hideOnSinglePage: true }}
          rowClassName={r => (r.ref === refId ? 'row-focus' : '')}
          scroll={{ x: 1280 }}
          locale={{ emptyText: <EmptyHint title={t('ruleEmpty')} /> }}
          columns={[
            {
              title: t('factRef'),
              dataIndex: 'ref',
              width: 135,
              render: (v: string, r) => (
                <Flex vertical gap={2} align="flex-start">
                  <Typography.Text className="mono" copyable style={{ fontSize: 12.5 }}>{v}</Typography.Text>
                  <Tag variant="filled" color={r.builtinKey ? 'geekblue' : 'default'} style={{ fontSize: 11 }}>
                    {r.builtinKey ? t('ruleBuiltin') : t('ruleCustom')}
                  </Tag>
                </Flex>
              ),
            },
            {
              title: t('ruleName'),
              dataIndex: 'name',
              width: 240,
              render: (v: string, r) => (
                <Flex vertical gap={3}>
                  <Typography.Text strong>{v}</Typography.Text>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {r.groupId
                      ? `${r.groupName || r.groupId} · ${(r.hostnames && r.hostnames.length > 0) ? r.hostnames.join(', ') : t('ruleScopeAllHosts')}`
                      : t('ruleScopeGlobal')}
                    {r.maintenanceWindow ? ` · ${r.maintenanceWindow}` : ''}
                  </Typography.Text>
                </Flex>
              ),
            },
            {
              title: t('ruleCondition'),
              dataIndex: 'conditionSummary',
              render: (v: string) => <Clamp text={v} />,
            },
            {
              title: t('ruleTier'),
              dataIndex: 'tier',
              width: 195,
              render: (tier: StandingRuleTier, r) => (
                <Flex vertical gap={4} align="flex-start">
                  {isAdmin && r.allowedTiers.length > 1 ? (
                    <Select<StandingRuleTier>
                      size="small"
                      style={{ width: 175 }}
                      value={tier}
                      disabled={busyId === r.id}
                      onChange={next => mutate(r.id, () => updateStandingRule(r.id, { tier: next }))}
                      options={r.allowedTiers.map(x => ({ value: x, label: t(`ruleTier_${x}` as MsgKey) }))}
                    />
                  ) : (
                    <Tag color={TIER_COLORS[tier]}>{t(`ruleTier_${tier}` as MsgKey)}</Tag>
                  )}
                  {r.degradedAt && (
                    <Tooltip title={`${r.degradedReason ?? ''} · ${fmtTime(r.degradedAt)}`}>
                      <Tag color="orange">{t('ruleDegraded')}</Tag>
                    </Tooltip>
                  )}
                </Flex>
              ),
            },
            {
              title: t('ruleHits'),
              key: 'hits',
              width: 140,
              align: 'right',
              sorter: (a, b) => a.hits30d - b.hits30d,
              render: (_, r) => (
                <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                  <strong>{r.hitsToday}</strong> / {r.hits30d}
                </span>
              ),
            },
            {
              title: t('ruleLastRun'),
              dataIndex: 'lastRunAt',
              width: 165,
              render: (v: string | null, r) =>
                v ? (
                  <Flex vertical gap={2} align="flex-start">
                    <Ago iso={v} />
                    {r.lastRunStatus && (
                      <Tag color={RUN_STATUS_COLORS[r.lastRunStatus] ?? 'default'} style={{ fontSize: 11 }}>
                        {t(`ruleRunStatus_${r.lastRunStatus}` as MsgKey)}
                      </Tag>
                    )}
                  </Flex>
                ) : (
                  <Typography.Text type="secondary">{t('ruleNeverRun')}</Typography.Text>
                ),
            },
            {
              title: t('ruleEnabled'),
              dataIndex: 'enabled',
              width: 95,
              render: (v: boolean, r) =>
                isAdmin ? (
                  <Switch
                    size="small"
                    checked={v}
                    loading={busyId === r.id}
                    onChange={checked => mutate(r.id, () => updateStandingRule(r.id, { enabled: checked }))}
                  />
                ) : (
                  <Tag color={v ? 'green' : 'default'}>{t(v ? 'ruleEnabledOn' : 'ruleEnabledOff')}</Tag>
                ),
            },
            {
              title: t('actions'),
              key: 'act',
              width: isAdmin ? 175 : 95,
              fixed: 'right',
              render: (_, r) => (
                <TableActions>
                  <Button type="link" size="small" onClick={() => setInspecting(r)}>{t('ruleRuns')}</Button>
                  {isAdmin && (
                    <Button type="link" size="small" onClick={() => setEditing(r)}>{t('factEdit')}</Button>
                  )}
                  {isAdmin && !r.builtinKey && (
                    <Popconfirm title={t('ruleConfirmDelete')} onConfirm={() => mutate(r.id, () => deleteStandingRule(r.id))}>
                      <Button type="link" size="small" danger disabled={busyId === r.id}>{t('ruleDelete')}</Button>
                    </Popconfirm>
                  )}
                </TableActions>
              ),
            },
          ]}
        />
      </TableCard>

      <Drawer
        open={inspecting !== null}
        title={inspecting ? `${inspecting.ref} · ${inspecting.name} — ${t('ruleRunsTitle')}` : t('ruleRunsTitle')}
        width={720}
        onClose={() => setInspecting(null)}
        destroyOnHidden
      >
        {inspecting && (
          <Flex vertical gap={14}>
            {inspecting.degradedAt && (
              <Alert
                type="warning"
                showIcon
                title={t('ruleDegraded')}
                description={`${inspecting.degradedReason ?? ''} (${fmtTime(inspecting.degradedAt)})`}
              />
            )}
            <Card size="small" title={t('ruleRollbackHint')}>
              <Typography.Text className="mono" style={{ fontSize: 12.5, whiteSpace: 'pre-wrap' }}>
                {inspecting.rollbackHint}
              </Typography.Text>
            </Card>
            {runs.isError ? (
              <LoadError error={runs.error} onRetry={() => runs.refetch()} />
            ) : (runs.data ?? []).length === 0 && !runs.isPending ? (
              <EmptyHint title={t('ruleRunsEmpty')} />
            ) : (
              (runs.data ?? []).map((run: StandingRuleRun) => (
                <Card key={run.id} size="small" loading={runs.isPending}>
                  <Flex justify="space-between" align="center" wrap gap={8} style={{ marginBottom: 8 }}>
                    <Flex gap={6} align="center" wrap>
                      <Tag color={TIER_COLORS[run.tier] ?? 'default'}>{t(`ruleTier_${run.tier}` as MsgKey)}</Tag>
                      <Tag color={RUN_STATUS_COLORS[run.status] ?? 'default'}>
                        {t(`ruleRunStatus_${run.status}` as MsgKey)}
                      </Tag>
                      <HostLink id={run.assetId} fallback={run.hostname} />
                      {run.approvalId && run.status === 'pending_approval' && (
                        <Link to="/approvals"><Tag color="blue">/approvals</Tag></Link>
                      )}
                    </Flex>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {fmtTime(run.completedAt ?? run.createdAt)}
                    </Typography.Text>
                  </Flex>
                  <Typography.Paragraph style={{ marginBottom: 8 }}>{run.hitSummary}</Typography.Paragraph>
                  {run.command && (
                    <div style={{ marginBottom: 8 }}>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('ruleCommand')}：</Typography.Text>
                      <Typography.Paragraph className="mono" copyable style={{ fontSize: 12, marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                        {run.command}
                      </Typography.Paragraph>
                    </div>
                  )}
                  {run.result && (
                    <div style={{ marginBottom: 8 }}>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('ruleResult')}：</Typography.Text>
                      <Typography.Paragraph style={{ fontSize: 12.5, marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                        {run.result}
                      </Typography.Paragraph>
                    </div>
                  )}
                  {run.rollback && (
                    <div>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('ruleRollback')}：</Typography.Text>
                      <Typography.Paragraph className="mono" copyable style={{ fontSize: 12, marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                        {run.rollback}
                      </Typography.Paragraph>
                    </div>
                  )}
                </Card>
              ))
            )}
          </Flex>
        )}
      </Drawer>

      <Modal
        open={modalOpen}
        title={editing ? t('ruleEdit') : t('ruleAdd')}
        width={640}
        confirmLoading={busyId === 'modal'}
        onCancel={() => {
          if (busyId === 'modal') return
          setEditing(null)
          onCloseAdd()
        }}
        onOk={() => form.submit()}
        destroyOnHidden
      >
        <Form<RuleFormValues>
          form={form}
          layout="vertical"
          disabled={busyId === 'modal'}
          onFinish={v => {
            const actionParams = buildActionParams(v, editing?.actionParams)
            if (editing) {
              void mutate(
                'modal',
                () =>
                  updateStandingRule(editing.id, {
                    name: v.name.trim(),
                    conditionSummary: v.conditionSummary.trim(),
                    tier: v.tier,
                    groupId: v.groupId || null,
                    clearGroup: !v.groupId,
                    assetIds: v.groupId ? (v.assetIds ?? []) : [],
                    maintenanceWindow: (v.maintenanceWindow ?? '').trim(),
                    cooldownMinutes: v.cooldownMinutes,
                    enabled: v.enabled,
                    actionParams,
                  }),
                () => setEditing(null),
              )
            } else {
              void mutate(
                'modal',
                () =>
                  createStandingRule({
                    actionTemplate: v.actionTemplate,
                    name: v.name.trim(),
                    conditionSummary: v.conditionSummary.trim(),
                    tier: v.tier,
                    groupId: v.groupId || null,
                    assetIds: v.groupId ? (v.assetIds ?? []) : [],
                    maintenanceWindow: (v.maintenanceWindow ?? '').trim(),
                    cooldownMinutes: v.cooldownMinutes,
                    enabled: v.enabled,
                    actionParams,
                  }),
                onCloseAdd,
              )
            }
          }}
        >
          <Form.Item name="actionTemplate" label={t('ruleTemplate')} rules={[{ required: true }]}>
            <Select
              disabled={editing !== null}
              onChange={onPickTemplate}
              options={(templates.data ?? []).map(x => ({ value: x.key, label: `${x.name} (${x.key})` }))}
            />
          </Form.Item>
          <Form.Item name="name" label={t('ruleName')} rules={[{ required: true, whitespace: true, max: 200 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="conditionSummary" label={t('ruleCondition')} rules={[{ required: true, whitespace: true, max: 500 }]}>
            <Input.TextArea rows={2} />
          </Form.Item>
          <Flex gap={12}>
            <Form.Item name="tier" label={t('ruleTier')} style={{ flex: 1 }} rules={[{ required: true }]}>
              <Select options={allowedTiers.map(x => ({ value: x, label: t(`ruleTier_${x}` as MsgKey) }))} />
            </Form.Item>
            <Form.Item name="cooldownMinutes" label={t('ruleCooldown')} extra={t('ruleCooldownHint')} style={{ flex: 1 }} rules={[{ required: true }]}>
              <InputNumber min={60} max={10080} style={{ width: '100%' }} />
            </Form.Item>
          </Flex>
          <Form.Item name="maintenanceWindow" label={t('ruleWindow')} extra={t('ruleWindowHint')}>
            <Input className="mono" placeholder="02:00-05:00" />
          </Form.Item>
          <Form.Item name="groupId" label={t('group')} rules={[{ required: Boolean(activeTpl?.requiresHostScope) }]}>
            <Select allowClear options={groups.map(g => ({ value: g.id, label: g.name }))} />
          </Form.Item>
          {selectedGroup && (
            <Form.Item name="assetIds" label={t('intentHosts')} rules={[{ required: Boolean(activeTpl?.requiresHostScope) }]}>
              <Select
                mode="multiple"
                allowClear
                showSearch
                optionFilterProp="label"
                options={linuxAssets.map(a => ({ value: a.id, label: a.hostname }))}
              />
            </Form.Item>
          )}
          {(editing?.actionTemplate ?? selectedTplKey) === 'restart_failed_service' && (
            <Form.Item name="unitsText" label={t('ruleUnits')} extra={t('ruleUnitsHint')} rules={[{ required: true, whitespace: true }]}>
              <Input className="mono" placeholder="worker-sync.service, report-export.service" />
            </Form.Item>
          )}
          {((editing?.actionTemplate ?? selectedTplKey) === 'reclaim_disk' || (editing?.actionTemplate ?? selectedTplKey) === 'old_backup_compress') && (
            <>
              <Form.Item name="pathsText" label={t('rulePaths')} extra={t('rulePathsHint')} rules={[{ required: true, whitespace: true }]}>
                <Input className="mono" placeholder="/var/backups" />
              </Form.Item>
              <Form.Item name="minAgeDays" label={t('ruleMinAgeDays')} rules={[{ required: true }]}>
                <InputNumber min={1} max={3650} />
              </Form.Item>
            </>
          )}
          {(editing?.actionTemplate ?? selectedTplKey) === 'mgmt_port_restrict' && (
            <>
              <Form.Item name="allowedCidrsText" label={t('ruleAllowedCidrs')} extra={t('ruleAllowedCidrsHint')}>
                <Input className="mono" placeholder="10.8.0.0/24, 10.1.1.36/32" />
              </Form.Item>
              <Form.Item name="portsText" label={t('rulePorts')}>
                <Input className="mono" placeholder="3389, 5900, 8006, 9090" />
              </Form.Item>
            </>
          )}
          <Form.Item name="enabled" label={t('ruleEnabled')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}
