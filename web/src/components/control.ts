import type { Fact, FactKind } from '../api'

export const FACT_KINDS: FactKind[] = ['key', 'channel', 'asset_role', 'decision', 'change']
// 与后端 facts.Categories 一致：研判只看类别
export const INTENT_CATEGORIES = ['deploy', 'troubleshoot', 'migrate', 'inspect', 'test', 'maintenance', 'backup']

// 编号对应总控里的条目：F- 是事实，I- 是意图
export function controlLink(ref: string) {
  return `/control?tab=${ref.startsWith('I-') ? 'intents' : 'facts'}&ref=${ref}`
}

export function factLive(f: Fact, now = Date.now()) {
  return !f.retiredAt && (!f.expiresAt || Date.parse(f.expiresAt) > now)
}

// 单个地址的通道存成 /32、/128，显示时去掉
export function bareAddr(cidr: string) {
  return cidr.replace(/\/(32|128)$/, '')
}

export function shortKeyFp(v: string) {
  return v.length > 24 ? `${v.slice(0, 15)}…${v.slice(-6)}` : v
}
