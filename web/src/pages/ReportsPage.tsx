import { TableActions } from '../components/TableActions'
import { ExportOutlined, FilePdfOutlined, FileSearchOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Collapse, Drawer, Empty, Input, Segmented, Space, Table, Tag, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { downloadAgentPdf, fetchAgentReports, markAllReportsRead, markReportRead, reportHtmlUrl, type AgentReport } from '../api'
import { useSession } from '../app/session'
import { GeminiSparkle } from '../components/Logo'
import { Markdown } from '../components/Markdown'
import { EmptyHint, Refreshed } from '../components/Ago'
import { FilterCard, Page, STICKY_HEADER, WIDE_ONLY, useWideTable } from '../components/Page'
import { fmtTime, errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'
import { LoadError } from '../components/LoadError'

function splitReportMarkdown(raw: string): { top: string; fold: string } {
  const md = raw.replace(/^\s*#\s+[^\n]*\n/, '').trim()
  const lines = md.split('\n')
  const topBlocks: string[] = []
  const foldBlocks: string[] = []
  let cur: string[] = []
  let curIsFold = false
  const flush = () => {
    if (!cur.length) return
    const block = cur.join('\n').trim()
    if (block) {
      if (curIsFold) foldBlocks.push(block)
      else topBlocks.push(block)
    }
    cur = []
  }
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith('## ') && !trimmed.startsWith('### ')) {
      flush()
      const h = trimmed.slice(3).replace(/^[^\u4e00-\u9fa5a-zA-Z]+|[一二三四五六七八九十、.\s]+/g, '')
      curIsFold = h.startsWith('证据') || h.startsWith('推断') || h.startsWith('未验证')
    }
    cur.push(line)
  }
  flush()
  return { top: topBlocks.join('\n\n'), fold: foldBlocks.join('\n\n') }
}

// 报告级别：无异常的只存档，有事项与紧急的会推送通知
const LEVEL: Record<AgentReport['level'], { color: string; key: MsgKey; rank: number }> = {
  ok: { color: 'success', key: 'reportLevelOk', rank: 1 },
  attention: { color: 'warning', key: 'reportLevelAttention', rank: 2 },
  urgent: { color: 'error', key: 'reportLevelUrgent', rank: 3 },
}

// 报告中心：Pi 会话（含定时巡检）提交的报告，按当前组列出
export function ReportsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { group } = useSession()
  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState<'all' | 'action' | 'unread'>('all')
  const queryClient = useQueryClient()
  // 窄屏只留标题（带结论）与级别：时间、来源会话与导出挪进预览抽屉，表格不再被挤成一字一行
  const wideTable = useWideTable()
  const [downloads, setDownloads] = useState<Set<string>>(new Set())
  const [preview, setPreview] = useState<AgentReport | null>(null)
  const { data, isPending, isError, error, refetch, isFetching, dataUpdatedAt } = useQuery({
    queryKey: ['reports', group?.id],
    queryFn: () => fetchAgentReports(group!.id),
    enabled: !!group,
    refetchInterval: 30_000,
  })
  useEffect(() => { setPreview(null); setSearch('') }, [group?.id])
  // 看过就标已读：预览在这里标，HTML / PDF 由后端在打开时标，回来刷新列表与菜单计数
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['reports', group?.id] })
  const open = (r: AgentReport) => {
    setPreview(r)
    if (!r.read) markReportRead(r.id).then(refresh, e => message.error(errText(e, t)))
  }
  const html = (r: AgentReport) => {
    window.open(reportHtmlUrl(r.id), '_blank', 'noopener')
    if (!r.read) setTimeout(refresh, 1500)
  }
  const pdf = async (r: AgentReport) => {
    if (downloads.has(r.id)) return
    setDownloads(previous => new Set(previous).add(r.id))
    try { await downloadAgentPdf(r); if (!r.read) refresh() }
    catch (e) { message.error(errText(e, t)) }
    finally { setDownloads(previous => { const next = new Set(previous); next.delete(r.id); return next }) }
  }
  const readAll = async () => {
    try { await markAllReportsRead(group!.id); message.success(t('reportMarkedAllRead')); refresh() }
    catch (e) { message.error(errText(e, t)) }
  }
  const unread = (data ?? []).filter(r => !r.read).length
  const q = search.trim().toLowerCase()
  const rows = (data ?? []).filter(r => (r.title.toLowerCase().includes(q) || (r.summary ?? '').toLowerCase().includes(q)) &&
    (level === 'all' || (level === 'action' && r.level !== 'ok') || (level === 'unread' && !r.read)))

  if (!group) return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  return (
    <Page title={t('navReports')} subtitle={t('reportsSubtitle', { name: group.name })}>
      <FilterCard
        filters={<>
          <Input allowClear prefix={<SearchOutlined aria-hidden />} aria-label={t('searchReports')} placeholder={t('searchReports')} value={search} onChange={e => setSearch(e.target.value)} style={{ width: 280, maxWidth: '100%' }} />
          <Segmented value={level} onChange={v => setLevel(v as 'all' | 'action' | 'unread')} options={[{ value: 'all', label: t('reportLevelAll') }, { value: 'action', label: t('reportLevelAction') }, { value: 'unread', label: `${t('reportUnreadOnly')}${unread ? ` (${unread})` : ''}` }]} />
          <Button disabled={!unread} onClick={readAll}>{t('reportMarkAllRead')}</Button>
        </>}
        onReset={search || level !== 'all' ? () => { setSearch(''); setLevel('all') } : undefined}
        extra={<Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />}
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<AgentReport>
          sticky={STICKY_HEADER}
          scroll={wideTable ? { x: 800 } : undefined}
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ defaultPageSize: 20, showSizeChanger: true, hideOnSinglePage: true }}
          locale={{ emptyText: search ? <EmptyHint title={t('noMatch')} /> : <EmptyHint title={t('noReports')} hint={t('noReportsHint')}
            action={canChat && <Link to={`/chat?${new URLSearchParams({ prompt: t('reportPrompt') })}`}><Button type="primary">{t('reportAskAI')}</Button></Link>} /> }}
          columns={[
            {
              title: t('reportTitle'), dataIndex: 'title',
              sorter: (a, b) => a.title.localeCompare(b.title),
              render: (v, r) => (
                <div>
                  <Button type="link" className="report-title-button" icon={<FileSearchOutlined aria-hidden />} onClick={() => open(r)} style={r.read ? undefined : { fontWeight: 600 }}>{v}</Button>
                  {!r.read && <Tag color="processing">{t('reportUnread')}</Tag>}
                  {r.summary && <Typography.Paragraph type="secondary" ellipsis={{ rows: 2 }} style={{ margin: '0 0 0 22px' }}>{r.summary}</Typography.Paragraph>}
                </div>
              ),
            },
            { title: t('reportLevel'), dataIndex: 'level', width: 95, sorter: (a, b) => (LEVEL[a.level]?.rank ?? 0) - (LEVEL[b.level]?.rank ?? 0), render: (v: AgentReport['level']) => <Tag color={LEVEL[v]?.color}>{t(LEVEL[v]?.key ?? 'reportLevelAttention')}</Tag> },
            { responsive: WIDE_ONLY, title: t('thCreatedAt'), dataIndex: 'created_at', width: 190, sorter: (a, b) => a.created_at.localeCompare(b.created_at), render: fmtTime },
            { responsive: WIDE_ONLY, title: t('sourceSession'), dataIndex: 'session_id', width: 140, render: v => <Link to={`/chat/${v}`}>{t('openSession')}</Link> },
            {
              responsive: WIDE_ONLY, title: t('actions'), width: 200,
              render: (_, r) => (
                <TableActions>
                  <Button size="small" icon={<ExportOutlined aria-hidden />} onClick={() => html(r)}>HTML</Button>
                  <Button size="small" icon={<FilePdfOutlined aria-hidden />} loading={downloads.has(r.id)} onClick={() => pdf(r)}>PDF</Button>
                </TableActions>
              ),
            },
          ]}
        />}
      </FilterCard>
      <Drawer
        size={760}
        open={!!preview}
        title={preview?.title}
        onClose={() => setPreview(null)}
        extra={preview && (
          <Space>
            <Button shape="round" icon={<ExportOutlined aria-hidden />} onClick={() => html(preview)}>HTML</Button>
            <Button shape="round" icon={<FilePdfOutlined aria-hidden />} loading={downloads.has(preview.id)} onClick={() => pdf(preview)}>PDF</Button>
          </Space>
        )}
      >
        {preview && (() => {
          const { top, fold } = splitReportMarkdown(preview.markdown)
          return <>
            {/* 页头由平台给：级别、时间与一句话结论，各报告一致；正文是模型写的 */}
            <div className="cmd-item" style={{ marginBottom: 14, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
              <Space wrap size={8}>
                <Tag color={LEVEL[preview.level]?.color}>{t(LEVEL[preview.level]?.key ?? 'reportLevelAttention')}</Tag>
                <Typography.Text type="secondary">{fmtTime(preview.created_at)}</Typography.Text>
              </Space>
              <Link to={`/chat/${preview.session_id}`}>{t('openSession')}</Link>
            </div>
            {preview.summary && (
              <div className="gemini-report-summary">
                <GeminiSparkle size={18} />
                <Typography.Paragraph strong style={{ margin: 0, flex: 1 }}>{preview.summary}</Typography.Paragraph>
              </div>
            )}
            <Markdown text={top} />
            {fold && (
              <Collapse size="small" style={{ marginTop: 16 }} items={[{
                key: 'evidence',
                label: t('reportFoldLabel'),
                children: <Markdown text={fold} />,
              }]} />
            )}
          </>
        })()}
      </Drawer>
    </Page>
  )
}
