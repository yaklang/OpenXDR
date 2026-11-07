import { useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Input, Popconfirm, Space, Tag, Typography } from 'antd'
import { importIntel, lookupThreatBook, type ThreatBookResult } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { errText, fmtTime } from './format'

export function ThreatBookLookup() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { canWrite } = useSession()
  const client = useQueryClient()
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const [ip, setIP] = useState('')
  const [result, setResult] = useState<ThreatBookResult>()
  const [error, setError] = useState('')
  const run = async (action: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError('')
    try { await action() } catch (e) { setError(errText(e, t)) }
    finally { lock.current = false; setBusy(false) }
  }
  return <Card title={t('threatBookLookup')}>
    <Typography.Paragraph type="secondary">{t('threatBookLookupHint')}</Typography.Paragraph>
    <Input.Search aria-label={t('threatBookIP')} placeholder={t('threatBookIP')} style={{ width: '100%', maxWidth: 340 }}
        value={ip} onChange={e => { setIP(e.target.value); setResult(undefined) }}
        disabled={!canWrite || busy} loading={busy}
        onSearch={value => run(async () => { setResult(undefined); setResult(await lookupThreatBook(value.trim())) })} />
    {error && <Alert type="error" showIcon title={error} style={{ marginTop: 12 }} />}
    {result && <div style={{ marginTop: 16 }}>
      <Space wrap>
        <Typography.Text strong copyable>{result.ip}</Typography.Text>
        <Tag>threatbook</Tag>
        {result.cached && <Tag>{t('threatBookCached')}</Tag>}
        {result.judgments.length ? result.judgments.map(j => <Tag key={j}>{j}</Tag>) : <Typography.Text type="secondary">{t('threatBookUnknown')}</Typography.Text>}
      </Space>
      <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
        {t('threatBookTimes', { queried: fmtTime(result.queriedAt), expires: fmtTime(result.expiresAt) })}
      </Typography.Paragraph>
      <Popconfirm title={t('threatBookImportConfirm')} onConfirm={() => run(async () => {
        const r = await importIntel({ text: result.ip, source: 'threatbook:manual', severity: 4, expiresInDays: 1 })
        message.success(t('intelImported', { n: r.imported, skipped: r.skipped }))
        await client.invalidateQueries({ queryKey: ['intel'] })
      })}>
        <Button disabled={!canWrite || busy}>{t('threatBookImport')}</Button>
      </Popconfirm>
      <details className="ev-raw"><summary>{t('threatBookEvidence')}</summary>
        <pre className="json-block">{JSON.stringify(result.data, null, 2)}</pre>
      </details>
    </div>}
  </Card>
}
