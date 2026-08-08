import { useEffect, useState } from 'react'
import { fetchAttack, type AttackCoverage } from './api'
import { useI18n } from './i18n'

// 战术显示名。ATT&CK 官方 slug → 中英文标签由 i18n 提供，
// 这里只保留顺序（后端已按杀伤链排好）与 slug→key 的映射。
const TACTIC_LABEL: Record<string, string> = {
  reconnaissance: '侦察',
  'resource-development': '资源开发',
  'initial-access': '初始访问',
  execution: '执行',
  persistence: '持久化',
  'privilege-escalation': '提权',
  'defense-evasion': '防御规避',
  'credential-access': '凭据访问',
  discovery: '发现',
  'lateral-movement': '横向移动',
  collection: '收集',
  'command-and-control': '命令控制',
  exfiltration: '数据外传',
  impact: '影响',
}

const TACTIC_LABEL_EN: Record<string, string> = {
  reconnaissance: 'Recon',
  'resource-development': 'Resource Dev',
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Priv Esc',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Cred Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  'command-and-control': 'C2',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}

/// ATT&CK 覆盖矩阵。空列不是排版问题，是检测缺口——
/// 这张图的价值全在于让"我们没防住哪一环"无法被忽略。
export function AttackMatrixView({ onClose }: { onClose: () => void }) {
  const { t, locale } = useI18n()
  const [cov, setCov] = useState<AttackCoverage | null>(null)
  const labels = locale === 'zh' ? TACTIC_LABEL : TACTIC_LABEL_EN

  useEffect(() => {
    fetchAttack().then(setCov).catch(() => {})
  }, [])

  const covered = cov?.tactics.filter(c => c.rules > 0).length ?? 0

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('attackMatrix')}</h3>
        {cov && (
          <>
            <p className="muted">
              {t('attackSummary', { covered, total: cov.tactics.length })}
              {cov.untagged > 0 && ' · ' + t('attackUntagged', { n: cov.untagged })}
              {cov.noDataSource > 0 && ' · ' + t('attackNoData', { n: cov.noDataSource })}
            </p>
            <div className="matrix">
              {cov.tactics.map(col => (
                <div key={col.tactic} className={`matrix-col ${col.rules === 0 ? 'matrix-gap' : ''}`}>
                  <div className="matrix-head" title={col.tactic}>
                    {labels[col.tactic] ?? col.tactic}
                    <span className="muted"> {col.rules}</span>
                  </div>
                  {(col.techniques ?? []).map(cell => (
                    <div
                      key={cell.id}
                      className={`matrix-cell ${cell.hasData ? '' : 'matrix-cell-nodata'}`}
                      title={cell.hasData
                        ? t('attackCellRules', { n: cell.rules })
                        : t('noDataSource')}
                    >
                      {cell.id}
                    </div>
                  ))}
                  {col.rules === 0 && <div className="matrix-empty">{t('attackNoCoverage')}</div>}
                </div>
              ))}
            </div>
          </>
        )}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
