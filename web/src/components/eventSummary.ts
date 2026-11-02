import type { MsgKey, T } from '../i18n'

// 事件体是 OCSF 风格的 JSON，字段随类别不同；这里只读、不信任，取不到就跳过
type Raw = Record<string, any>

const ACTIVITY: Record<number, Record<number, MsgKey>> = {
  1007: { 1: 'evLaunch', 2: 'evExit', 99: 'evPeriodic' },
  1001: { 1: 'evCreate', 3: 'evUpdate', 4: 'evDelete' },
  1005: { 1: 'evLoad', 4: 'evUnload' },
  201002: { 1: 'evCreate', 3: 'evUpdate', 4: 'evDelete' },
}

const join = (...parts: unknown[]) => parts.filter(p => p !== undefined && p !== null && p !== '').join(' ')
const endpoint = (e: Raw | undefined) => (e?.ip ? (e.port ? `${e.ip}:${e.port}` : e.ip) : undefined)

// 容器或虚拟机：有名字用名字，没有用 运行时 + ID
export const containerLabel = (c: Raw | undefined) => (c?.uid ? c.name || `${c.runtime} ${c.uid}` : undefined)
const inContainer = (r: Raw) => {
  const label = containerLabel(r.container)
  return label ? `[${label}]` : undefined
}

// 运行时长：毫秒到天，取最大的两级
export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const units: [number, string][] = [[86_400_000, 'd'], [3_600_000, 'h'], [60_000, 'm'], [1000, 's']]
  const i = units.findIndex(([u]) => ms >= u)
  const [big, a] = units[i]
  const [small, b] = units[i + 1]
  const rest = Math.floor((ms % big) / small)
  return `${Math.floor(ms / big)}${a}${rest ? `${rest}${b}` : ''}`
}

// DNS 结果码：0 是正常应答，其余直接用协议里的名字
export const RCODE: Record<number, string> = { 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' }

// 动作：启动 / 退出 / 创建 / 删除 / 登录成功或失败……tone 给列表上色用（bad 失败或删除、warn 非零退出）
export function eventAction(classUid: number, raw: unknown, t: T): { label: string; tone: 'ok' | 'bad' | 'warn' | 'neutral' } | null {
  const r = (raw ?? {}) as Raw
  if (classUid === 3002 && r.activity_id < 10) return r.status_id === 1 ? { label: t('evLoginOk'), tone: 'ok' } : { label: t('evLoginFail'), tone: 'bad' }
  const key = ACTIVITY[classUid]?.[r.activity_id]
  if (!key) return null
  const exitCode = r.process?.exit_code
  const tone = key === 'evDelete' || key === 'evUnload' ? 'bad' : classUid === 1007 && r.activity_id === 2 && exitCode != null && exitCode !== 0 ? 'warn' : 'neutral'
  return { label: t(key), tone }
}

// 一行说清这条事件是什么：谁、做了什么、对象是谁。列表里不用再点开读 JSON。
// withAction=false 时不带动作词（列表把动作单独画成标签）
export function eventSummary(classUid: number, raw: unknown, t: T, withAction = true): string {
  const r = (raw ?? {}) as Raw
  const key = ACTIVITY[classUid]?.[r.activity_id]
  const act = key && withAction ? t(key) : undefined
  switch (classUid) {
    case 1007: {
      const p = r.process ?? {}
      // 周期行为汇总：谁反复拉起了什么、这个窗口里多少次
      if (r.activity_id === 99) {
        return join(act, p.parent_process?.name ? `${p.parent_process.name} →` : undefined, p.name || p.file?.path,
          p.cmd_line && p.cmd_line !== p.name ? `· ${p.cmd_line}` : undefined, t('evPeriodicCount', { n: r.periodic?.count ?? 0 }))
      }
      const exit = r.activity_id === 2 && p.exit_code != null ? t('evExitCode', { n: p.exit_code }) : undefined
      const ran = r.activity_id === 2 && typeof r.duration_ms === 'number' ? `· ${fmtDuration(r.duration_ms)}` : undefined
      return join(inContainer(r), act, p.name || p.file?.path, p.cmd_line && p.cmd_line !== p.name ? `· ${p.cmd_line}` : undefined, exit, ran)
    }
    case 1001:
      return join(act, r.file?.path, r.process?.name ? `· ${r.process.name}` : undefined)
    case 3002: {
      if (r.activity_id >= 10) return join(r.user?.name, r.group_name, r.target_server, r.policy_category)
      const ok = !withAction ? undefined : r.status_id === 1 ? t('evLoginOk') : t('evLoginFail')
      return join(ok, r.user?.name, r.src_endpoint?.ip ? `← ${r.src_endpoint.ip}` : undefined, r.service?.name ? `(${r.service.name})` : undefined)
    }
    case 2004:
      return join(r.suricata?.alert?.signature, endpoint(r.src_endpoint), '→', endpoint(r.dst_endpoint))
    case 4001: {
      const host = r.tls?.sni || r.http_request?.hostname || r.dst_endpoint?.hostname
      const udp = r.connection_info?.protocol_name === 'udp' ? 'UDP' : undefined
      // 入站：进程是本机服务，箭头指向它；出站：进程是发起方
      const flow = r.connection_info?.direction === 'inbound'
        ? [endpoint(r.dst_endpoint), '←', endpoint(r.src_endpoint)]
        : [endpoint(r.src_endpoint), '→', endpoint(r.dst_endpoint)]
      const tlsTag = [r.tls?.version, r.tls?.alpn].filter(Boolean).join('/')
      return join(inContainer(r), r.process?.name, udp, ...flow, host ? `(${host})` : undefined, tlsTag ? `[${tlsTag}]` : undefined)
    }
    case 4003: {
      const answers = Array.isArray(r.answers) ? r.answers.map((a: Raw) => a.ip || a.rdata).filter(Boolean).join(', ') : ''
      const rcode = r.query?.rcode_id
      const result = rcode == null ? `(${t('evNoAnswer')})` : rcode ? RCODE[rcode] ?? `RCODE ${rcode}` : answers ? `→ ${answers}` : undefined
      const type = r.query?.type && r.query.type !== 'A' ? r.query.type : undefined
      // 解析器转发的查询：标出真正问的客户端
      const forClient = r.requester?.ip ? t('evForClient', { ip: r.requester.ip }) : undefined
      return join(inContainer(r), r.process?.name, forClient, r.query?.hostname, type, result)
    }
    case 1005:
      return join(act, r.module?.file?.name || r.module?.file?.path)
    case 201002:
      return join(act, r.reg_key?.path, r.reg_value?.data != null ? `= ${r.reg_value.data}` : undefined)
    case 100001:
      return join(r.device?.hostname, r.message)
    default:
      return ''
  }
}
