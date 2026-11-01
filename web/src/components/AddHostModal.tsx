import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Collapse, Empty, Flex, Input, List, Modal, Segmented, Select, Space, Spin, Tabs, Tag, Typography, Popconfirm } from 'antd'
import { useState } from 'react'
import { createEnrollToken, fetchEnrollStatus, fetchEnrollTokens, revokeEnrollToken, type EnrollKind, type EnrollToken } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime, errText } from './format'

// 安装命令里的控制台地址就是用户现在访问的这个，主机必须能访问到它
function commands(token: string) {
  const base = window.location.origin
  return {
    linux: `curl -fsSL ${base}/api/enroll/install.sh | sudo sh -s -- ${base} ${token}`,
    windows: `& ([scriptblock]::Create((irm ${base}/api/enroll/install.ps1))) ${base} ${token}`,
  }
}

// 流量探针只有 Linux；不带网卡时脚本只列出本机网卡后退出，不替用户猜抓哪块
function sensorCommand(token: string, iface: string) {
  const base = window.location.origin
  return `curl -fsSL ${base}/api/enroll/sensor-install.sh | sudo sh -s -- ${base} ${token}${iface ? ` ${iface}` : ''}`
}
// 与安装脚本同一套网卡名校验，命令里不会混进别的东西
const IFACE_RE = /^[A-Za-z0-9._-]{1,15}$/

function Command({ text }: { text: string }) {
  return (
    <Typography.Paragraph className="mono" copyable={{ text }} style={{ margin: 0, padding: '14px 16px', borderRadius: 14, background: 'var(--ant-color-fill-tertiary)', border: '1px solid var(--ant-color-border-secondary)', wordBreak: 'break-all' }}>
      {text}
    </Typography.Paragraph>
  )
}

// 添加主机：选组 → 生成一条命令 → 到主机上执行。令牌管理收在折叠面板里，平时不用看
export function AddHostModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups, group, isAdmin } = useSession()
  const adminGroups = groups.filter(g => g.role === 'admin')
  // 组列表可能晚于弹窗挂载才到：没选过就跟着默认组走
  const [picked, setGroupId] = useState<string>()
  const groupId = adminGroups.some(g => g.id === picked) ? picked : (group?.role === 'admin' ? group.id : adminGroups[0]?.id)
  const [days, setDays] = useState(7)
  const [issued, setIssued] = useState<EnrollToken>()
  // 流量探针令牌只有平台管理员能签：探针的会话会归到任意组的资产上
  const [kind, setKind] = useState<EnrollKind>('agent')
  const [iface, setIface] = useState('')

  const status = useQuery({ queryKey: ['enroll-status'], queryFn: fetchEnrollStatus, enabled: open })
  const tokens = useQuery({ queryKey: ['enroll-tokens', groupId], queryFn: () => fetchEnrollTokens(groupId!), enabled: open && !!groupId })
  const generate = useMutation({
    mutationFn: () => createEnrollToken(groupId!, days, kind),
    onSuccess: tok => {
      setIssued(tok)
      client.invalidateQueries({ queryKey: ['enroll-tokens'] })
    },
    onError: e => message.error(errText(e, t)),
  })
  const revoke = useMutation({
    mutationFn: revokeEnrollToken,
    onSuccess: (_, id) => {
      setIssued(current => current?.id === id ? undefined : current)
      return client.invalidateQueries({ queryKey: ['enroll-tokens'] })
    },
    onError: e => message.error(errText(e, t)),
  })

  const busy = generate.isPending || revoke.isPending
  const close = () => {
    if (busy) return
    setIssued(undefined)
    onClose()
  }
  const current = issued?.token && issued.groupId === groupId && (issued.kind ?? 'agent') === kind ? issued.token : undefined
  const cmds = current && kind === 'agent' ? commands(current) : undefined
  const ifaceOK = !iface || IFACE_RE.test(iface)
  const sensorCmd = current && kind === 'sensor' && ifaceOK ? sensorCommand(current, iface) : undefined
  const kindEnabled = kind === 'sensor' ? status.data?.sensorEnabled : status.data?.enabled
  const kindReason = kind === 'sensor' ? status.data?.sensorReason : status.data?.reason
  const tokenState = (tok: EnrollToken) =>
    tok.revoked ? <Tag>{t('tokenRevoked')}</Tag>
      : Date.parse(tok.expiresAt) < Date.now() ? <Tag>{t('tokenExpired')}</Tag>
        : <Popconfirm title={t('revokeTokenConfirm')} okButtonProps={{ danger: true }} onConfirm={() => revoke.mutateAsync(tok.id)}>
          <Button disabled={busy} size="small" danger type="link">{t('revoke')}</Button>
        </Popconfirm>

  return (
    <Modal title={t('addHost')} open={open} onCancel={close} footer={null} width={720} closable={!busy} maskClosable={!busy} keyboard={!busy} destroyOnHidden>
      {window.location.protocol !== 'https:' ? (
        <Alert type="warning" showIcon title={t('hostHTTPSRequired')} />
      ) : status.isError ? (
        <LoadError error={status.error} onRetry={() => status.refetch()} />
      ) : status.isPending ? (
        <Spin />
      ) : status.data && !status.data.enabled && !(isAdmin && status.data.sensorEnabled) ? (
        <Alert type="warning" showIcon title={t('addHostDisabled')} description={status.data.reason} />
      ) : adminGroups.length === 0 ? (
        <Alert type="info" showIcon title={t('addHostNoGroup')} />
      ) : (
        <Flex vertical gap={16}>
          {isAdmin && (
            <Segmented<EnrollKind> disabled={busy} value={kind} onChange={k => { setKind(k); setIssued(undefined) }}
              options={[{ value: 'agent', label: t('addHostKindAgent') }, { value: 'sensor', label: t('addHostKindSensor') }]} />
          )}
          {kind === 'sensor' && <Typography.Text type="secondary">{t('addSensorIntro')}</Typography.Text>}
          {!kindEnabled && <Alert type="warning" showIcon title={t('addHostDisabled')} description={kindReason} />}
          <div className="filter-bar" style={{ padding: '12px 18px' }}>
            <Space wrap size={14} className="filter-controls">
              <Space size={8}>
                <span>{t('addHostGroup')}</span>
                <Select aria-label={t('addHostGroup')} showSearch optionFilterProp="label" disabled={busy} style={{ width: 200 }} value={groupId} onChange={g => { setGroupId(g); setIssued(undefined) }}
                  options={adminGroups.map(g => ({ value: g.id, label: g.name }))} />
              </Space>
              <Space size={8}>
                <span>{t('addHostDays')}</span>
                <Select aria-label={t('addHostDays')} disabled={busy} style={{ width: 100 }} value={days} onChange={setDays}
                  options={[1, 7, 30].map(n => ({ value: n, label: t('addHostDaysUnit', { n }) }))} />
              </Space>
              <Button type="primary" loading={generate.isPending} disabled={busy || !groupId || !kindEnabled} onClick={() => generate.mutate()}>{t('addHostGenerate')}</Button>
            </Space>
          </div>
          {kind === 'sensor' && (
            <Space wrap>
              <span>{t('addSensorIface')}</span>
              <Input aria-label={t('addSensorIface')} style={{ width: 200 }} value={iface} status={ifaceOK ? undefined : 'error'}
                placeholder={t('addSensorIfacePlaceholder')} onChange={e => setIface(e.target.value.trim())} />
              {!ifaceOK && <Typography.Text type="danger">{t('addSensorIfaceInvalid')}</Typography.Text>}
            </Space>
          )}
          {sensorCmd && (
            <>
              <Typography.Text type="secondary">{t(iface ? 'addSensorHint' : 'addSensorHintNoIface')}</Typography.Text>
              <Command text={sensorCmd} />
              <Alert type="success" showIcon title={t('addSensorDone')} />
            </>
          )}
          {cmds && (
            <>
              <Typography.Text type="secondary">{t('addHostHint')}</Typography.Text>
              <Tabs items={[
                { key: 'linux', label: t('addHostLinux'), children: <Command text={cmds.linux} /> },
                { key: 'windows', label: t('addHostWindows'), children: <Command text={cmds.windows} /> },
              ]} />
              <Alert type="success" showIcon title={t('addHostDone')} />
            </>
          )}
          <Collapse ghost size="small" items={[{
            key: 'tokens',
            label: t('addHostTokens'),
            children: tokens.isError ? <LoadError error={tokens.error} onRetry={() => tokens.refetch()} /> : tokens.isPending ? <Spin /> : tokens.data?.length ? (
              <List size="small" dataSource={tokens.data} renderItem={tok => (
                <List.Item actions={[tokenState(tok)]}>
                  <Space wrap>
                    <Tag>{t(tok.kind === 'sensor' ? 'addHostKindSensor' : 'addHostKindAgent')}</Tag>
                    <span>{fmtTime(tok.createdAt)}</span>
                    <Typography.Text type="secondary">{tok.createdBy}</Typography.Text>
                    <span>{t('tokenUses', { n: tok.uses })}</span>
                    <Typography.Text type="secondary">{t('tokenExpires', { time: fmtTime(tok.expiresAt) })}</Typography.Text>
                  </Space>
                </List.Item>
              )} />
            ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('tokenNone')} />,
          }]} />
        </Flex>
      )}
    </Modal>
  )
}
