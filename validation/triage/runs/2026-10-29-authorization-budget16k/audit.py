import collections, hashlib, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
data = (root / 'report.jsonl').read_bytes()
rows = [json.loads(line) for line in data.splitlines()]
assert rows[0]['kind'] == 'metadata' and rows[-1]['kind'] == 'summary'
meta, final = rows[0], rows[-1]
assert final['complete'] is True
judge_source = (root / 'source/server/internal/triageeval/eval.go').read_text()
for name, key in [('judgePrompt', 'judge_prompt_sha256'), ('actionPrompt', 'action_prompt_sha256')]:
    prompt = re.search(r'const ' + name + r' = `([^`]+)`', judge_source).group(1)
    assert hashlib.sha256(prompt.encode()).hexdigest() == meta[key]
cases_data = (root / 'cases.json').read_bytes()
assert hashlib.sha256(cases_data).hexdigest() == meta['cases_sha256']
cases = json.loads(cases_data)
expected_controls = {(c['id'], x['id']): x.get('reject', []) for c in cases for x in [dict(c['negative'], id='base_negative'), *c.get('controls', [])]}
expected_answers = {(c['id'], x['id']): x['answer'] for c in cases for x in [dict(c['negative'], id='base_negative'), *c.get('controls', [])]}
expected_evals = {(c['id'], i): c['expected_verdict'] for c in cases for i in range(1, meta['repeats'] + 1)}
controls, evaluations = {}, {}
for r in rows[1:-1]:
    if r['kind'] == 'calibration':
        key = (r['case'], r['control'])
        assert key in expected_controls and key not in controls
        controls[key] = r
        assert r['answer'] == expected_answers[key]
        assert (r.get('expected_reject') or []) == expected_controls[key]
        checks = r.get('assessment') or {}
        required = expected_controls[key]
        matched = all(checks.get(d, {}).get('status') == 'fail' for d in required) if required else all(checks.get(d, {}).get('status') == 'pass' for d in ['facts', 'uncertainty', 'actions'])
        assert r['passed'] == (not r.get('error_stage') and matched)
    elif r['kind'] == 'evaluation':
        key = (r['case'], r['repeat'])
        assert key in expected_evals and key not in evaluations
        evaluations[key] = r
        assert r['expected_verdict'] == expected_evals[key]
        if r.get('answer'):
            assert r['verdict_match'] == (r['answer']['verdict'] == expected_evals[key])
            assert r['generation_attempts'] and r['generation_attempts'][-1]['structural_valid']
        checks = r.get('assessment') or {}
        passed = not r.get('error_stage') and r.get('verdict_match', False) and all(checks.get(d, {}).get('status') == 'pass' for d in ['facts', 'uncertainty', 'actions'])
        assert r['automated_pass'] == passed
    else:
        raise AssertionError('Unexpected row kind')
assert set(controls) == set(expected_controls) and set(evaluations) == set(expected_evals)
failed = sum(not r['passed'] for r in controls.values()) + sum(not r['automated_pass'] for r in evaluations.values())
assert final['evaluations'] == len(evaluations) and final['calibration_controls'] == len(controls)
assert final['failed_checks'] == failed and final['automated_pass'] == (failed == 0)
for name, digest in json.loads((root / 'source-sha256.json').read_text()).items():
    assert hashlib.sha256((root / 'source' / name).read_bytes()).hexdigest() == digest
negative = [r for k, r in controls.items() if expected_controls[k]]
positive = [r for k, r in controls.items() if not expected_controls[k]]
print(json.dumps({
    'complete': True, 'report_sha256': hashlib.sha256(data).hexdigest(), 'rows': len(rows),
    'calibration_pass': sum(r['passed'] for r in controls.values()), 'calibration_count': len(controls),
    'negative_pass': sum(r['passed'] for r in negative), 'negative_count': len(negative),
    'positive_pass': sum(r['passed'] for r in positive), 'positive_count': len(positive),
    'automated_evaluation_pass': sum(r['automated_pass'] for r in evaluations.values()), 'evaluation_count': len(evaluations),
    'errors': [dict(case=r['case'], control=r.get('control'), repeat=r.get('repeat'), detail=r.get('error_detail')) for r in rows if r.get('error_stage')],
    'failed_checks': failed, 'automated_pass': failed == 0, 'engineering_review': 'pending', 'independent_human_review': 'pending',
    'scope': 'frozen_snapshot_report_integrity_only'
}, ensure_ascii=False, indent=2))
