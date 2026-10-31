import {
  CaretRightOutlined, CheckCircleFilled, CloseCircleFilled, ExclamationCircleFilled, CodeOutlined, DatabaseOutlined, EditOutlined, EditFilled,
  FileTextOutlined, LoadingOutlined, ReadOutlined, RobotOutlined, ToolOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Avatar, Button, Card, Col, Empty, Flex, Form, Modal, Row, Segmented, Space, Switch, Table, Tag, Tooltip, Typography, theme } from 'antd'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import {
  fetchAssets, fetchSessionMessages, fetchTaskRuns, fetchTasks, runTask, setTaskGroup, updateTask,
  type SessionMessage, type TaskCategory, type TaskRow, type TaskRunRow,
} from '../api'
import { useSession } from '../app/session'
import { Ago } from '../components/Ago'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { ScheduleEditor, describeCron } from '../components/Schedule'
import { SessionStatusTag, errText, fmtTime } from '../components/format'
import { activitiesOf, type Activity } from '../components/workerActivity'
import { useI18n, type MsgKey } from '../i18n'

const ICON: Record<Activity['kind'], ReactNode> = {
  exec: <CodeOutlined />, query: <DatabaseOutlined />, record: <EditFilled />, report: <FileTextOutlined />,
  read: <ReadOutlined />, sandbox: <ToolOutlined />, think: <EditOutlined />,
}

// 运行失败的原因翻成人话；认不出的原样显示
const ERRORS: [RegExp, MsgKey][] = [
  [/context canceled/, 'workerErrInterrupted'],
  [/deadline exceeded|超时/, 'workerErrTimeout'],
  [/max_turns/, 'workerErrTurns'],
  [/模型用量已到上限/, 'workerErrBudget'],
  [/没有提交报告/, 'workerErrNoReport'],
  [/并发上限/, 'workerErrSkipped'],
]
const errorText = (err: string, t: (k: MsgKey) => string) => {
  const hit = ERRORS.find(([re]) => re.test(err))
  return hit ? t(hit[1]) : err
}

const CATEGORY: Record<Exclude<TaskCategory, ''>, { color: string; key: MsgKey }> = {
  ops: { color: 'blue', key: 'taskCatOps' },
  security: { color: 'red', key: 'taskCatSecurity' },
  report: { color: 'purple', key: 'taskCatReport' },
}

// 任务在某个组上跑不跑：本组单独设置优先，没设置的跟全局默认；没有当前组时看全局默认
const enabledIn = (task: TaskRow, groupId?: string) =>
  groupId && groupId in task.groupEnabled ? task.groupEnabled[groupId] : task.enabled
const anyEnabled = (task: TaskRow) => task.enabled || Object.values(task.groupEnabled).some(Boolean)

function duration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h ? `${h}h${m}m` : m ? `${m}m${s % 60}s` : `${s}s`
}

// 每秒走一次的时钟，只在有人在岗时开
function useNow(active: boolean) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [active])
  return now
}

// 正在跑的会话：按 seq 增量拉消息，只留最近的步骤
function useActivities(sessionId: string | null, hosts: Record<string, string>) {
  const { t } = useI18n()
  const [messages, setMessages] = useState<SessionMessage[]>([])
  const last = useRef(0)
  useEffect(() => { setMessages([]); last.current = 0 }, [sessionId])
  useQuery({
    queryKey: ['workerFeed', sessionId],
    enabled: !!sessionId,
    refetchInterval: 3_000,
    queryFn: async () => {
      const rows = await fetchSessionMessages(sessionId!, last.current)
      if (rows.length) {
        last.current = rows[rows.length - 1].seq
        setMessages(prev => [...prev, ...rows].slice(-200))
      }
      return rows.length
    },
  })
  return activitiesOf(messages, hosts, t)
}

// 在岗：干到第几步、正在做什么，最近几步滚动显示
function OnDuty({ run, groupName, hosts, now }: { run: TaskRunRow; groupName: string; hosts: Record<string, string>; now: number }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const acts = useActivities(run.sessionId, hosts)
  const recent = acts.slice(-5).reverse()
  return (
    <div style={{ marginTop: 14, padding: '14px 18px', borderRadius: 16, background: token.colorSuccessBg }}>
      <Space wrap size={8} style={{ marginBottom: 8 }}>
        <Tag color="success" variant="filled" icon={<LoadingOutlined />}>{t('workerWorking')}</Tag>
        <Typography.Text type="secondary">{t('workerShift', { group: groupName, elapsed: duration(now - Date.parse(run.startedAt)), steps: acts.length })}</Typography.Text>
        {run.sessionId && <Link to={`/chat/${run.sessionId}`}>{t('workerWatch')}</Link>}
      </Space>
      {recent.length === 0 ? <Typography.Text type="secondary">{t('workerStarting')}</Typography.Text> : recent.map((a, i) => (
        <div key={`${a.seq}-${a.text}`} style={{ display: 'flex', gap: 8, alignItems: 'baseline', opacity: i === 0 ? 1 : 0.55 - i * 0.08, fontSize: i === 0 ? 14 : 12 }}>
          <span style={{ color: token.colorSuccess }}>{ICON[a.kind]}</span>
          <span className={a.kind === 'exec' || a.kind === 'sandbox' ? 'mono' : undefined} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.text}</span>
          {i === 0 && <span className="worker-typing" aria-hidden><i /><i /><i /></span>}
        </div>
      ))}
    </div>
  )
}

// 上一班：几点到几点、做了多少步、交了什么
function LastShift({ run }: { run: TaskRunRow }) {
  const { t } = useI18n()
  const ok = run.status === 'succeeded'
  const interrupted = run.status === 'interrupted'
  const skipped = run.status === 'skipped'
  const partial = ok && run.partial
  const took = run.finishedAt ? duration(Date.parse(run.finishedAt) - Date.parse(run.startedAt)) : '-'
  return (
    <Space wrap size={8} style={{ marginTop: 12 }}>
      {partial || interrupted || skipped ? <ExclamationCircleFilled style={{ color: 'var(--ant-color-warning)' }} />
        : ok ? <CheckCircleFilled style={{ color: 'var(--ant-color-success)' }} />
          : <CloseCircleFilled style={{ color: 'var(--ant-color-error)' }} />}
      <Typography.Text>{t(partial ? 'workerLastPartial' : ok ? 'workerLastOk' : interrupted ? 'workerLastInterrupted' : skipped ? 'workerLastSkipped' : 'workerLastFailed')}</Typography.Text>
      {!skipped && <Typography.Text type="secondary"><Ago iso={run.finishedAt ?? run.startedAt} /> · {t('workerTook', { took })} · {t('workerSteps', { n: run.steps })}</Typography.Text>}
      {run.reportId && <a href={`/api/agent-reports/${run.reportId}/html`} target="_blank" rel="noreferrer"><FileTextOutlined /> {run.reportTitle}</a>}
      {!ok && !interrupted && !skipped && run.error && <Tooltip title={run.error}><Typography.Text type="danger" ellipsis style={{ maxWidth: 360 }}>{errorText(run.error, t)}</Typography.Text></Tooltip>}
      {run.sessionId && <Link to={`/chat/${run.sessionId}`}>{t('openSession')}</Link>}
    </Space>
  )
}

// 最近几班：一格一班，颜色看成败，悬停看详情
function ShiftStrip({ runs }: { runs: TaskRunRow[] }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const color = { succeeded: token.colorSuccess, failed: token.colorError, interrupted: token.colorWarning, skipped: token.colorTextQuaternary, running: token.colorPrimary }
  return (
    <Space size={3} wrap>
      {[...runs].slice(0, 20).reverse().map(r => (
        <Tooltip key={r.id} title={<>{fmtTime(r.startedAt)}<br />{t('workerSteps', { n: r.steps })}{r.partial && <><br />{t('runPartial')}</>}{r.reportTitle && <><br />{r.reportTitle}</>}{r.error && <><br />{errorText(r.error, t)}</>}</>}>
          <span style={{ display: 'inline-block', width: 10, height: 18, borderRadius: 3, background: r.partial ? token.colorWarning : color[r.status], opacity: r.status === 'running' ? 1 : 0.8 }} />
        </Tooltip>
      ))}
    </Space>
  )
}

function Runs({ runs, loading }: { runs: TaskRunRow[]; loading: boolean }) {
  const { t } = useI18n()
  const { groups } = useSession()
  return (
    <Table<TaskRunRow>
      scroll={{ x: 900 }}
      size="small"
      rowKey="id"
      loading={loading}
      dataSource={runs}
      pagination={{ pageSize: 10, hideOnSinglePage: true }}
      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noTaskRuns')} /> }}
      columns={[
        { title: t('thStartedAt'), dataIndex: 'startedAt', render: fmtTime, width: 170 },
        { title: t('thFinishedAt'), dataIndex: 'finishedAt', render: fmtTime, width: 170 },
        { title: t('group'), dataIndex: 'groupId', width: 120, render: v => groups.find(g => g.id === v)?.name ?? v.slice(0, 8) },
        { title: t('thStatus'), dataIndex: 'status', width: 90, render: (v, r) => r.partial ? <Tag color="warning">{t('runPartial')}</Tag> : <SessionStatusTag value={v} /> },
        { title: t('workerStepsTh'), dataIndex: 'steps', width: 70, align: 'right' },
        { title: t('thDetail'), key: 'detail', ellipsis: true, render: (_, r) => (r.reportId ? <a href={`/api/agent-reports/${r.reportId}/html`} target="_blank" rel="noreferrer">{r.reportTitle}</a> : r.error ? errorText(r.error, t) : '-') },
        { title: '', dataIndex: 'sessionId', width: 90, render: v => v && <Link to={`/chat/${v}`}>{t('openSession')}</Link> },
      ]}
    />
  )
}

// 一位 AI 员工：头像在岗时会呼吸，下面是此刻在做什么，或者上一班的结果与下一次上班的时间
function Worker({ task, busy, hosts, onToggle, onGroup, onRun, onEdit }: {
  task: TaskRow
  busy: boolean
  hosts: Record<string, string>
  onToggle: (enabled: boolean) => void
  onGroup: (enabled: boolean | null) => void
  onRun: () => void
  onEdit: () => void
}) {
  const { t, locale } = useI18n()
  const { token } = theme.useToken()
  const { isAdmin, groups, group } = useSession()
  // 主开关管当前组：组管理员就能开关本组；平台 admin 另有一个全局默认开关
  const groupId = group?.id
  const canGroup = !!groupId && (isAdmin || group?.role === 'admin')
  const overridden = !!groupId && groupId in task.groupEnabled
  const enabled = enabledIn(task, groupId)
  const name = locale === 'en' && task.nameEn ? task.nameEn : task.name
  const description = locale === 'en' ? task.descriptionEn || task.description : task.description
  const [showRuns, setShowRuns] = useState(false)
  const runsQuery = useQuery({ queryKey: ['taskRuns', task.id], queryFn: () => fetchTaskRuns(task.id), refetchInterval: 10_000 })
  const runs = runsQuery.data ?? []
  const working = runs.filter(r => r.status === 'running')
  const last = runs.find(r => r.status !== 'running')
  const now = useNow(working.length > 0)
  const spec = task.customSchedule ?? task.schedule
  // 各组开跑时间按组错峰；选了组看本组的，没选看最早的
  const nextRun = groupId ? task.nextRuns[groupId] : task.nextRun
  // 职责优先用任务说明；没有说明的旧任务取提示词第一句，截在冒号上的（「……覆盖：」）去掉冒号
  const duty = description || task.prompt.split(/[。\n]/)[0].replace(/[：:]\s*$/, '')
  const state = working.length ? 'working' : enabled ? 'idle' : 'off'
  const ring = { working: token.colorSuccess, idle: token.colorPrimary, off: token.colorTextQuaternary }[state]

  return (
    <Card styles={{ body: { padding: 22 } }} style={{ height: '100%' }}>
      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        <div className={state === 'working' ? 'worker-pulse' : undefined} style={{ borderRadius: '50%', boxShadow: `0 0 0 3px ${ring}`, flexShrink: 0 }}>
          <Avatar size={48} icon={<RobotOutlined />} style={{ background: state === 'off' ? token.colorFillSecondary : ring }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <Space size={8} wrap>
            <Typography.Text strong style={{ fontSize: 16 }}>{name}</Typography.Text>
            {task.category && <Tag color={CATEGORY[task.category].color}>{t(CATEGORY[task.category].key)}</Tag>}
            {task.targetGroup !== '*' && <Tag>{task.targetGroup}</Tag>}
          </Space>
          <Tooltip title={<pre className="tooltip-pre">{task.prompt}</pre>}>
            <Typography.Paragraph type="secondary" ellipsis={{ rows: 2 }} style={{ margin: '2px 0 0' }}>{duty}</Typography.Paragraph>
          </Tooltip>
          <Space size={6} wrap style={{ marginTop: 6, fontSize: 13 }}>
            <Typography.Text type="secondary">{t('workerRoster')}</Typography.Text>
            <Tooltip title={<span className="mono">{spec}</span>}>{describeCron(spec, t, locale) ?? <code>{spec}</code>}</Tooltip>
            {task.customSchedule && <Tag color="blue">{t('taskCustom')}</Tag>}
            {isAdmin && <Button type="link" size="small" aria-label={t('taskEditSchedule')} disabled={busy} icon={<EditOutlined />} onClick={onEdit} />}
            {state === 'idle' && nextRun && <Typography.Text type="secondary">· {t('workerNext', { time: fmtTime(nextRun) })}</Typography.Text>}
          </Space>
        </div>
        <Space orientation="vertical" align="end" size={6}>
          {groupId ? (
            <Tooltip title={t('taskForGroup', { name: group?.name ?? '' })}>
              <Switch aria-label={t('taskForGroup', { name: group?.name ?? '' })} checked={enabled} disabled={!canGroup || busy} loading={busy} onChange={onGroup} checkedChildren={t('taskEnabled')} unCheckedChildren={t('taskDisabled')} />
            </Tooltip>
          ) : (
            <Switch aria-label={t('taskGlobalDefault')} checked={task.enabled} disabled={!isAdmin || busy} loading={busy} onChange={onToggle} checkedChildren={t('taskEnabled')} unCheckedChildren={t('taskDisabled')} />
          )}
          {groupId && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {overridden
                ? <>{t('taskGroupOverride')}{canGroup && <> · <Button type="link" size="small" style={{ padding: 0, height: 'auto', fontSize: 12 }} disabled={busy} onClick={() => onGroup(null)}>{t('taskResetGroup')}</Button></>}</>
                : t('taskFollowDefault')}
            </Typography.Text>
          )}
          {groupId && isAdmin && (
            <Space size={4} style={{ fontSize: 12 }}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('taskGlobalDefault')}</Typography.Text>
              <Switch size="small" aria-label={t('taskGlobalDefault')} checked={task.enabled} disabled={busy} onChange={onToggle} />
            </Space>
          )}
          {isAdmin && <Button size="small" icon={<CaretRightOutlined />} disabled={!anyEnabled(task) || busy || working.length > 0} onClick={onRun}>{t('workerRunNow')}</Button>}
        </Space>
      </div>

      {working.map(r => <OnDuty key={r.id} run={r} hosts={hosts} now={now} groupName={groups.find(g => g.id === r.groupId)?.name ?? ''} />)}
      {!working.length && (last ? <LastShift run={last} /> : <Typography.Paragraph type="secondary" style={{ margin: '12px 0 0' }}>{t('workerNoShift')}</Typography.Paragraph>)}

      {runs.length > 0 && (
        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <ShiftStrip runs={runs} />
          <Button type="link" size="small" onClick={() => setShowRuns(v => !v)}>{t(showRuns ? 'workerHideRuns' : 'workerAllRuns')}</Button>
        </div>
      )}
      {showRuns && (runsQuery.isError ? <LoadError error={runsQuery.error} onRetry={() => runsQuery.refetch()} /> : <Runs runs={runs} loading={runsQuery.isPending} />)}
    </Card>
  )
}

// 定时任务即 AI 员工：定义来自仓库 tasks/*.yml，这里看它们在不在岗、正在做什么、交了什么；admin 可启停、改排班、叫它立即上班
export function TasksPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const pending = useRef(new Set<string>())
  const [busy, setBusy] = useState<string[]>([])
  const [editing, setEditing] = useState<TaskRow | null>(null)
  const [form] = Form.useForm<{ schedule: string }>()
  const { group } = useSession()
  const [category, setCategory] = useState<TaskCategory | 'all'>('all')
  const [onlyEnabled, setOnlyEnabled] = useState(false)
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks, refetchInterval: 60_000 })
  // 在本组启用的排前面；分类与「只看已启用」只是筛选，不改变任务本身
  const tasks = (data ?? [])
    .filter(task => (category === 'all' || task.category === category) && (!onlyEnabled || enabledIn(task, group?.id)))
    .sort((a, b) => Number(enabledIn(b, group?.id)) - Number(enabledIn(a, group?.id)))
  const { data: hosts = {} } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, select: as => Object.fromEntries(as.map(a => [a.id, a.hostname])) })

  const perform = async (id: string, action: () => Promise<void>) => {
    if (pending.current.has(id)) return false
    pending.current.add(id)
    setBusy([...pending.current])
    try { await action(); return true }
    catch (e) { message.error(errText(e, t)); return false }
    finally { pending.current.delete(id); setBusy([...pending.current]) }
  }
  const update = (id: string, body: { enabled?: boolean; customSchedule?: string }) => perform(id, async () => {
    await updateTask(id, body)
    await client.invalidateQueries({ queryKey: ['tasks'] })
  })
  const toggleGroup = (id: string, groupId: string, enabled: boolean | null) => perform(id, async () => {
    await setTaskGroup(id, groupId, enabled)
    await client.invalidateQueries({ queryKey: ['tasks'] })
  })
  const runNow = (id: string) => perform(id, async () => {
    await runTask(id)
    message.success(t('taskRunQueued'))
    await client.invalidateQueries({ queryKey: ['taskRuns', id] })
  })

  // 与 YAML 一致就清掉自定义，免得 YAML 后续改了周期却被旧覆盖值挡住
  const saveSchedule = async ({ schedule }: { schedule: string }) => {
    if (!editing) return
    const v = schedule.trim()
    if (await update(editing.id, { customSchedule: v === editing.schedule ? '' : v })) setEditing(null)
  }

  const saving = !!editing && busy.includes(editing.id)
  return (
    <Page title={t('navTasks')} subtitle={t('tasksSubtitle')}>
      {isError ? <LoadError error={error} onRetry={() => refetch()} />
        : isPending ? <Card loading />
        : !data?.length ? <Card><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noTasks')} /></Card>
        : (
          <>
            <Flex gap={12} wrap align="center" justify="space-between" style={{ marginBottom: 16 }}>
              <Segmented value={category} onChange={v => setCategory(v as TaskCategory | 'all')} options={[
                { value: 'all', label: t('taskCatAll') },
                ...(['ops', 'security', 'report'] as const).map(c => ({ value: c, label: t(CATEGORY[c].key) })),
              ]} />
              <Space size={8}>
                <Switch size="small" checked={onlyEnabled} onChange={setOnlyEnabled} aria-label={t('taskOnlyEnabled')} />
                <Typography.Text type="secondary">{t('taskOnlyEnabled')}</Typography.Text>
                <Typography.Text type="secondary">· {t('taskEnabledCount', { n: data.filter(task => enabledIn(task, group?.id)).length, total: data.length })}</Typography.Text>
              </Space>
            </Flex>
            {!tasks.length ? <Card><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noMatch')} /></Card> : (
          <Row gutter={[20, 20]}>
            {tasks.map(task => (
              <Col key={task.id} xs={24} lg={12}>
                <Worker task={task} hosts={hosts} busy={busy.includes(task.id)}
                  onToggle={enabled => update(task.id, { enabled })} onRun={() => runNow(task.id)}
                  onGroup={enabled => group && toggleGroup(task.id, group.id, enabled)}
                  onEdit={() => { form.setFieldsValue({ schedule: task.customSchedule ?? task.schedule }); setEditing(task) }} />
              </Col>
            ))}
          </Row>
            )}
          </>
        )}
      <Modal open={!!editing} title={t('taskEditSchedule')} onCancel={() => { if (!saving) setEditing(null) }} confirmLoading={saving} closable={!saving} maskClosable={!saving} keyboard={!saving} cancelButtonProps={{ disabled: saving }} onOk={() => form.submit()} destroyOnHidden>
        <Form disabled={saving} form={form} layout="vertical" onFinish={saveSchedule}>
          <Form.Item name="schedule" label={editing?.name} rules={[{ required: true, pattern: /^(CRON_TZ=\S+\s+)?\S/, message: t('schedCustomHint') }]}>
            <ScheduleEditor fallback={editing?.schedule ?? ''} />
          </Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
