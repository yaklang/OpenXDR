import { useEffect, useState } from 'react'
import { fetchRules, type RuleRow } from './api'
import { useI18n, type MsgKey } from './i18n'

const CLASS_KEY: Record<number, MsgKey> = {
  1001: 'classFile',
  1007: 'classProcess',
  3002: 'classAuth',
  201002: 'classRegistry',
  4001: 'classNetwork',
  4003: 'classDNS',
  100001: 'classLog',
}

/// 规则清单。规则库支持热重载，这里看到的就是引擎里正在跑的版本；
/// "无数据源"标记提醒运营：这条规则加载了但没有采集面供数，纯摆设。
export function RulesView({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<RuleRow[]>([])

  useEffect(() => {
    fetchRules().then(setRows).catch(() => {})
  }, [])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('rulesTitle', { n: rows.length })}</h3>
        <table>
          <thead>
            <tr>
              <th>{t('thRule')}</th><th>{t('thSeverity')}</th><th>{t('thClass')}</th>
              <th>{t('thPlatform')}</th><th>{t('thDataSource')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id}>
                <td title={r.id}>{r.title || r.id}</td>
                <td><span className={`sev-${r.severity}`}>{r.severity}</span></td>
                <td>{CLASS_KEY[r.classUid] ? t(CLASS_KEY[r.classUid]) : r.classUid || t('allClasses')}</td>
                <td className="muted">{r.product || '-'}</td>
                <td>
                  {r.ingested ? (
                    <span className="muted">{r.source}</span>
                  ) : (
                    <span className="sev-3">{t('noDataSource')}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
