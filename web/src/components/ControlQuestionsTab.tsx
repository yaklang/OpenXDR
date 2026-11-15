import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Checkbox, Flex, Form, Input, InputNumber, Modal, Radio, Segmented, Select, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { answerQuestion, fetchQuestion, fetchQuestions, fetchStandingRules, type Question, type QuestionKind } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { Ago, EmptyHint } from './Ago'
import { RefTag } from './ControlRefs'
import { LoadError } from './LoadError'
import { STICKY_HEADER, TableCard } from './Page'
import { errText, fmtTime } from './format'

const KIND_COLORS: Record<QuestionKind, string> = { owner: 'blue', authorization: 'gold', policy: 'cyan', permission: 'purple' }

// 问题的一句话：类型决定问法，对象用服务端给的短标签（域名已去链接化）
function useSentence() {
  const { t } = useI18n()
  return (q: Question) => {
    const subject = `${t(`questionSubject_${q.subjectKind}` as MsgKey)} ${q.subjectLabel}`
    const key = q.subjectKind === 'fact' ? 'questionAsk_renewal' : `questionAsk_${q.kind}`
    return t(key as MsgKey, { subject })
  }
}

// 待答问题：按主题合并的卡片，证据（含攻击者可控原文）只在展开后显示；只有平台管理员能作答，没有批量同意
export function ControlQuestionsTab() {
  const { t } = useI18n()
  const [view, setView] = useState<'open' | 'answered' | 'voided'>('open')
  const open = useQuery({ queryKey: ['questions', 'open'], queryFn: () => fetchQuestions('open') })
  const answered = useQuery({ queryKey: ['questions', 'answered'], queryFn: () => fetchQuestions('answered'), enabled: view === 'answered' })
  const voided = useQuery({ queryKey: ['questions', 'voided'], queryFn: () => fetchQuestions('voided'), enabled: view === 'voided' })
  const current = view === 'open' ? open : view === 'answered' ? answered : voided
  if (current.isError) return <LoadError error={current.error} onRetry={() => current.refetch()} />
  return (
    <Flex vertical gap={14}>
      <Typography.Text type="secondary">{t('questionsHint')}</Typography.Text>
      <Segmented value={view} onChange={v => setView(v as 'open' | 'answered' | 'voided')} style={{ alignSelf: 'flex-start' }}
        options={[
          { value: 'open', label: `${t('questionsOpen')} ${open.data?.length ?? ''}` },
          { value: 'answered', label: t('questionsAnswered') },
          { value: 'voided', label: t('questionsVoided') },
        ]} />
      {view === 'open'
        ? <OpenList rows={open.data ?? []} loading={open.isPending} />
        : view === 'answered'
          ? <AnsweredTable rows={answered.data ?? []} loading={answered.isPending} />
          : <VoidedList rows={voided.data ?? []} loading={voided.isPending} />}
    </Flex>
  )
}

function VoidedList({ rows, loading }: { rows: Question[]; loading: boolean }) {
  const { t } = useI18n()
  if (loading) return <Card loading />
  if (rows.length === 0) return <EmptyHint title={t('questionsVoidedEmpty')} />
  return (
    <Flex vertical gap={12}>
      {rows.map(q => <QuestionCard key={q.id} q={q} />)}
    </Flex>
  )
}

function OpenList({ rows, loading }: { rows: Question[]; loading: boolean }) {
  const { t } = useI18n()
  const [answering, setAnswering] = useState<Question | null>(null)
  if (loading) return <Card loading />
  if (rows.length === 0) return <EmptyHint title={t('questionsEmpty')} hint={t('questionsEmptyHint')} />
  // 同一注册域下的多个主机名放在一组展示，方便一次看完；每个问题仍各自作答，范围各自选
  const groups: { key: string; domain?: string; items: Question[] }[] = []
  for (const q of rows) {
    const key = q.domainGroup ? `domain:${q.domainGroup}` : q.id
    const g = groups.find(x => x.key === key)
    if (g) g.items.push(q)
    else groups.push({ key, domain: q.domainGroup, items: [q] })
  }
  return (
    <Flex vertical gap={12}>
      {groups.map(g => g.domain && g.items.length > 1
        ? (
          <Card key={g.key} size="small" title={t('questionDomainGroup', { domain: g.domain, n: g.items.length })} styles={{ body: { display: 'flex', flexDirection: 'column', gap: 10 } }}>
            {g.items.map(q => <QuestionCard key={q.id} q={q} onAnswer={() => setAnswering(q)} />)}
          </Card>
        )
        : g.items.map(q => <QuestionCard key={q.id} q={q} onAnswer={() => setAnswering(q)} />))}
      {answering && <AnswerModal q={answering} onClose={() => setAnswering(null)} />}
    </Flex>
  )
}

function voidedLabel(q: Question, t: (k: MsgKey) => string): string {
  if (q.answer?.choice === 'voided_resolved') return t('questionVoided_resolved')
  if (q.answer?.choice === 'voided_retired') return t('questionVoided_retired')
  return t('questionsVoided')
}

function QuestionCard({ q, onAnswer }: { q: Question; onAnswer?: () => void }) {
  const { t } = useI18n()
  const { isAdmin } = useSession()
  const sentence = useSentence()
  const [expanded, setExpanded] = useState(false)
  return (
    <Card size="small" id={q.ref}>
      <Flex justify="space-between" align="flex-start" gap={12} wrap>
        <Flex vertical gap={6} style={{ minWidth: 0, flex: 1 }}>
          <Space size={6} wrap>
            <Tag className="mono">{q.ref}</Tag>
            <Tag color={KIND_COLORS[q.kind]}>{t(`questionKind_${q.kind}` as MsgKey)}</Tag>
            {q.status === 'voided' && <Tag>{voidedLabel(q, t)}</Tag>}
            <Typography.Text strong>{sentence(q)}</Typography.Text>
          </Space>
          {q.status === 'voided' && q.answer?.content && q.answer.choice !== 'voided_resolved' && (
            <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>{q.answer.content}</Typography.Text>
          )}
          <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>
            {t('questionImpact', { incidents: q.incidentCount, findings: q.findingCount, asked: q.askedCount })} · <Ago iso={q.answeredAt ?? q.updatedAt} />
          </Typography.Text>
        </Flex>
        <Space>
          <Button size="small" onClick={() => setExpanded(v => !v)}>{expanded ? t('questionCollapse') : t('questionEvidence')}</Button>
          {isAdmin && q.status === 'open' && onAnswer && <Button size="small" type="primary" onClick={onAnswer}>{t('questionAnswer')}</Button>}
        </Space>
      </Flex>
      {expanded && <QuestionEvidence id={q.id} />}
    </Card>
  )
}

function QuestionEvidence({ id }: { id: string }) {
  const { t } = useI18n()
  const detail = useQuery({ queryKey: ['question', id], queryFn: () => fetchQuestion(id) })
  if (detail.isError) return <LoadError error={detail.error} onRetry={() => detail.refetch()} />
  if (!detail.data) return <Card loading />
  const d = detail.data
  return (
    <Flex vertical gap={10} style={{ marginTop: 12 }}>
      {d.incidents.length > 0 && (
        <div>
          <Typography.Text type="secondary">{t('questionIncidents')}</Typography.Text>
          <Flex vertical gap={2}>{d.incidents.map(i => <Link key={i.id} to={`/incidents/${i.id}`}>{i.title || i.id} <Tag>{i.status}</Tag></Link>)}</Flex>
        </div>
      )}
      {d.findings.length > 0 && (
        <div>
          <Typography.Text type="secondary">{t('questionFindings')}</Typography.Text>
          <Flex vertical gap={2}>{d.findings.map(f => <Link key={f.id} to={`/findings?${new URLSearchParams({ ids: f.id, status: 'all' })}`}>{f.hostname}：{f.title} <Tag>{f.status}</Tag></Link>)}</Flex>
        </div>
      )}
      <div>
        <Typography.Text type="secondary">{t('questionEvidenceList')}</Typography.Text>
        <Alert type="warning" showIcon style={{ margin: '6px 0' }} message={t('questionUntrusted')} />
        <Flex vertical gap={6}>
          {d.evidence.map((e, i) => (
            <div key={i} style={{ fontSize: 12.5 }}>
              <Space size={6} wrap>
                <Typography.Text type="secondary">{fmtTime(e.at)}</Typography.Text>
                <Tag>{t(`questionSource_${e.source}` as MsgKey) || e.source}</Tag>
                {e.ref && <Typography.Text code>{e.ref}</Typography.Text>}
              </Space>
              {/* 原文按纯文本显示，不解析链接与标记 */}
              {e.note && <Typography.Paragraph style={{ margin: '2px 0 0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }} type="secondary">{e.note}</Typography.Paragraph>}
            </div>
          ))}
        </Flex>
      </div>
    </Flex>
  )
}

interface AnswerValues {
  choice: string
  scope?: string
  holder?: string
  content?: string
  ruleId?: string
  tier?: 'auto' | 'propose' | 'human'
  expiresInDays?: number
  siblings?: boolean
}

// 作答表单按问题类型给结构化选项；默认写入为事实。授权类必须有到期（默认 30 天）
function AnswerModal({ q, onClose }: { q: Question; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const queryClient = useQueryClient()
  const sentence = useSentence()
  const [form] = Form.useForm<AnswerValues>()
  const [saving, setSaving] = useState(false)
  const rules = useQuery({ queryKey: ['standingRules'], queryFn: fetchStandingRules, enabled: q.kind === 'policy' })
  const renewal = q.subjectKind === 'fact'
  const grantLike = renewal || q.kind === 'authorization' || q.kind === 'permission'
  const choices = renewal
    ? ['grant', 'deny']
    : q.kind === 'owner' ? ['claim', 'unknown'] : q.kind === 'policy' ? ['decision', 'rule'] : ['grant', 'deny']
  const choice = Form.useWatch('choice', form)
  const scope = Form.useWatch('scope', form)
  const batch = (q.siblings?.length ?? 0) > 0
  const ruleId = Form.useWatch('ruleId', form)
  const rule = rules.data?.find(r => r.id === ruleId)
  const choiceLabel = (c: string) => {
    if (renewal) return t(c === 'grant' ? 'questionChoice_renew' : 'questionChoice_noRenew')
    if (q.kind === 'permission') return t(c === 'grant' ? 'questionChoice_permit' : 'questionChoice_noPermit')
    return t(`questionChoice_${c}` as MsgKey)
  }
  const submit = async () => {
    const v = await form.validateFields()
    setSaving(true)
    try {
      const res = await answerQuestion(q.id, { ...v, scope: v.scope || undefined, expiresInDays: grantLike ? v.expiresInDays : undefined, siblings: batch && !v.scope && v.siblings })
      message.success(t('questionAnswered', { ref: res.factRef ?? res.ruleRef ?? q.ref, n: res.requeuedFindings }) + (res.siblingsAnswered ? t('questionSiblingsAnswered', { n: res.siblingsAnswered }) : ''))
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['questions'] }),
        queryClient.invalidateQueries({ queryKey: ['facts'] }),
        queryClient.invalidateQueries({ queryKey: ['standingRules'] }),
      ])
      onClose()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setSaving(false)
    }
  }
  return (
    <Modal open title={`${q.ref} ${sentence(q)}`} onCancel={onClose} onOk={submit} confirmLoading={saving} okText={t('questionSubmit')} destroyOnHidden width={560}>
      <Form form={form} layout="vertical" initialValues={{ choice: choices[0], scope: '', expiresInDays: 30, siblings: true, ruleId: q.subjectKind === 'rule' ? q.subject : undefined }}>
        <Form.Item name="choice" label={t('questionChoice')}>
          <Radio.Group optionType="button" options={choices.map(c => ({ value: c, label: choiceLabel(c) }))} />
        </Form.Item>
        {q.subjectKind === 'domain' && choice !== 'rule' && (
          <Form.Item name="scope" label={t('questionDomainScope')} extra={q.scopes?.length ? t('questionDomainScopeHint') : t('questionDomainShared')}>
            <Select options={[
              { value: '', label: t('questionScopeExact', { host: q.subject }) },
              ...(q.scopes ?? []).map(d => ({ value: d, label: t('questionScopeTree', { domain: d }) })),
            ]} />
          </Form.Item>
        )}
        {q.kind === 'owner' && (
          <>
            <Form.Item name="holder" label={t('questionHolder')} extra={t('questionHolderHint')} rules={[{ required: choice === 'claim', whitespace: true, max: 200 }]}>
              <Input disabled={choice !== 'claim'} placeholder="user:zachary" />
            </Form.Item>
            <Form.Item name="content" label={t(choice === 'claim' ? 'questionPurpose' : 'questionNote')} rules={[{ required: choice === 'claim', whitespace: true, max: 1000 }]}>
              <Input.TextArea rows={2} />
            </Form.Item>
          </>
        )}
        {grantLike && (
          <>
            {!renewal && (
              <Form.Item name="content" label={t('questionScope')} extra={t('questionScopeHint')} rules={[{ required: true, whitespace: true, max: 1000 }]}>
                <Input.TextArea rows={3} />
              </Form.Item>
            )}
            {(choice === 'grant' || !renewal) && (
              <Form.Item name="expiresInDays" label={t('questionExpiry')} extra={t('questionExpiryHint')} rules={[{ required: true }]}>
                <InputNumber min={1} max={365} addonAfter={t('questionDaysUnit')} />
              </Form.Item>
            )}
          </>
        )}
        {batch && !scope && (
          <Form.Item name="siblings" valuePropName="checked" extra={q.siblings!.map(s => `${s.ref} ${s.subjectLabel}`).join('、')}>
            <Checkbox>{t('questionSiblings', { n: q.siblings!.length })}</Checkbox>
          </Form.Item>
        )}
        {q.kind === 'policy' && choice === 'rule' && (
          <>
            <Form.Item name="ruleId" label={t('questionRule')} rules={[{ required: true }]}>
              <Select disabled={q.subjectKind === 'rule'} loading={rules.isPending} options={(rules.data ?? []).map(r => ({ value: r.id, label: `${r.ref} ${r.name}` }))} />
            </Form.Item>
            <Form.Item name="tier" label={t('questionTier')} rules={[{ required: true }]}>
              <Select options={(rule?.allowedTiers ?? []).map(x => ({ value: x, label: t(`ruleTier_${x}` as MsgKey) }))} />
            </Form.Item>
          </>
        )}
        {q.kind === 'policy' && choice === 'decision' && (
          <Form.Item name="content" label={t('questionDecision')} rules={[{ required: true, whitespace: true, max: 1000 }]}>
            <Input.TextArea rows={3} />
          </Form.Item>
        )}
      </Form>
    </Modal>
  )
}

function AnsweredTable({ rows, loading }: { rows: Question[]; loading: boolean }) {
  const { t } = useI18n()
  const sentence = useSentence()
  return (
    <TableCard>
      <Table<Question> rowKey="id" size="middle" loading={loading} dataSource={rows} sticky={STICKY_HEADER} pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
        locale={{ emptyText: <EmptyHint title={t('questionsAnsweredEmpty')} /> }}
        columns={[
          { title: t('questionTitle'), key: 'q', render: (_, q) => <Space size={6} wrap><Tag className="mono">{q.ref}</Tag><Tag color={KIND_COLORS[q.kind]}>{t(`questionKind_${q.kind}` as MsgKey)}</Tag>{sentence(q)}</Space> },
          {
            title: t('questionResult'), key: 'a', width: 280, render: (_, q) => (
              <Space size={4} wrap>
                {q.answer && <Tag>{q.subjectKind === 'fact' ? t(q.answer.choice === 'grant' ? 'questionChoice_renew' : 'questionChoice_noRenew') : t(`questionChoice_${q.answer.choice}` as MsgKey)}</Tag>}
                {q.subjectKind === 'domain' && <Tag>{q.answer?.scope ? t('questionScopeTree', { domain: q.answer.scope }) : t('questionScopeExact', { host: q.subject })}</Tag>}
                {q.factRef && <RefTag value={q.factRef} />}
                {q.ruleRef && <RefTag value={q.ruleRef} />}
                {!q.factRef && !q.ruleRef && q.answer?.content && (
                  <Typography.Text type="secondary" ellipsis={{ tooltip: q.answer.content }} style={{ fontSize: 12, maxWidth: 220 }}>
                    {q.answer.content}
                  </Typography.Text>
                )}
                {q.answer?.expiresAt && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('questionUntil', { at: fmtTime(q.answer.expiresAt) })}</Typography.Text>}
              </Space>
            ),
          },
          { title: t('questionImpactCol'), key: 'n', width: 130, render: (_, q) => t('questionImpactShort', { incidents: q.incidentCount, findings: q.findingCount }) },
          { title: t('questionAnsweredBy'), dataIndex: 'answeredBy', width: 110 },
          { title: t('questionAnsweredAt'), dataIndex: 'answeredAt', width: 130, render: v => <Ago iso={v} /> },
        ]} />
    </TableCard>
  )
}
