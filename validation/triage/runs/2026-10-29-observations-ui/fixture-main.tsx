import { createRoot } from 'react-dom/client'
import { ConfigProvider } from 'antd'
import { VerdictCard } from '../src/components/VerdictCard'
import { I18nProvider } from '../src/i18n'
import '../src/index.css'
const mode = new URLSearchParams(location.search).get('case')
const observations = Array.from({ length: 30 }, (_, i) => ({evidence_id: `query-${i + 1}`, field: 'returned', text: `本次查询返回 ${i} 条；返回数量不代表实际发生总量，零条不证明没有发生。`}))
observations[10] = {evidence_id:'query-11/items-1', field:'parent_process_guid', text:'这条归一化事件记录的父进程 GUID 为 "' + 'long-id-'.repeat(50) + '"；仅对应此记录，不证明更长的进程链或操作授权。'}
const verdict = mode === 'pending' ? null : mode === 'error' ? {error:'failed',raw:'invalid JSON'} : {
 verdict: 'suspicious' as const, confidence:60, summary:'测试摘要：证据不足，仍需核实来源；不能因为没有工单推断没有其他批准记录。',
 kill_chain:['测试推断：操作关联仍需核实'],actions:['持续监测本事件相关资产与行为，收集新增证据后重新研判。'],
 ...(mode === 'legacy' ? {} : {evidence_observations:observations, query_evidence:[{id:'query-1',tool:'query_events',facts:{status:'ok',returned:0,truncated:false}}]})
}
createRoot(document.getElementById('root')!).render(<ConfigProvider><I18nProvider><main style={{maxWidth:1100,margin:'24px auto',padding:'0 12px'}}><VerdictCard verdict={verdict}/></main></I18nProvider></ConfigProvider>)
