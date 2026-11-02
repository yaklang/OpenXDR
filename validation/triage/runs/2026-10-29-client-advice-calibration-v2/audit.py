"""核对固定答案实验的输入隔离、源码快照和完整报告，不判定模型语义。"""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
samples = json.loads((root / 'samples.json').read_text())
cases = json.loads((root / 'cases.json').read_text())
case = next(c for c in cases if c['id'] == 'mixed_clients')
by_key = {(s['id'], s['variant']): s for s in samples}
assert len(by_key) == len(samples) == 4
for sample_id in {s['id'] for s in samples}:
    original = by_key[sample_id, 'original']['answer']
    revised = by_key[sample_id, 'revised']['answer']
    assert {k: v for k, v in original.items() if k != 'actions'} == {
        k: v for k, v in revised.items() if k != 'actions'
    }
    assert len(original['actions']) == len(revised['actions'])
    assert sum(a != b for a, b in zip(original['actions'], revised['actions'])) == 1
for name, digest in json.loads((root / 'source-sha256.json').read_text()).items():
    assert hashlib.sha256((root / 'source' / name).read_bytes()).hexdigest() == digest, name
report = root / 'report.jsonl'
rows = [json.loads(line) for line in report.read_text().splitlines()]
assert len(rows) == 14
meta, summary = rows[0], rows[-1]
assert meta['kind'] == 'metadata' and meta['repeats'] == 2
assert meta['samples_sha256'] == hashlib.sha256((root / 'samples.json').read_bytes()).hexdigest()
controls = {'base_negative': case['negative'], **{c['id']: c for c in case['controls']}}
calibration = [r for r in rows if r['kind'] == 'calibration']
assert len(calibration) == len(controls) == 4
assert {r['control'] for r in calibration} == set(controls)
for row in calibration:
    control = controls[row['control']]
    assert row['answer'] == control['answer']
    assert row['expected_reject'] == control['reject']
    assessment = row['assessment'] or {}
    expected = all(assessment.get(d, {}).get('status') == 'fail' for d in control['reject']) if control['reject'] else all(assessment.get(d, {}).get('status') == 'pass' for d in ('facts', 'uncertainty', 'actions'))
    assert row['matched'] == (not row.get('error_detail') and expected)
comparisons = [r for r in rows if r['kind'] == 'comparison']
assert len(comparisons) == 8
assert {(r['id'], r['variant'], r['repeat']) for r in comparisons} == {
    (s['id'], s['variant'], repeat) for s in samples for repeat in (1, 2)
}
for row in comparisons:
    sample = by_key[row['id'], row['variant']]
    assert row['answer'] == sample['answer']
    assert row['expected_actions'] == sample['expected_actions']
    expected = (row.get('assessment') or {}).get('actions', {}).get('status') == sample['expected_actions']
    assert row['actions_matched'] == (not row.get('error_detail') and expected)
failed = sum(not r['matched'] for r in calibration) + sum(not r['actions_matched'] for r in comparisons)
assert summary['kind'] == 'summary' and summary['complete'] is True
assert summary['controls'] == 4 and summary['comparisons'] == 8
assert summary['unmatched_checks'] == failed
assert summary['product_semantic_gate'] == 'not_evaluated'
print(json.dumps({'report_sha256': hashlib.sha256(report.read_bytes()).hexdigest(), 'rows': len(rows), 'unmatched_checks': failed, 'integrity': 'verified', 'semantic_acceptance': 'not_evaluated'}, indent=2))
