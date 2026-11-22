"""验证探测目标边界和 PowerShell 参数不会被解释成新指令。"""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verify_response', Path(__file__).with_name('verify-response.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProbeSafetyTest(unittest.TestCase):
    def test_literal_preserves_quotes_as_data(self):
        value = "C:\\Temp\\a';Remove-Item C:\\*;'"
        script, expected = module.script_for({'kind': 'restore_file', 'target': value})
        self.assertIn("$p='C:\\Temp\\a'';Remove-Item C:\\*;'''", script)
        self.assertEqual(expected, {'exists': True})
        self.assertIn('-LiteralPath $p', script)

    def test_block_probe_must_be_inside_original_target(self):
        command = {'kind': 'block_network', 'target': '10.0.0.0/24'}
        self.assertEqual(module.script_for(command, '10.0.0.12:18080')[1], {'reachable': False})
        with self.assertRaises(ValueError):
            module.script_for(command, '10.0.2.12:18080')

    def test_ambiguous_network_targets_rejected(self):
        for probe in ('example.com:443', '10.0.0.12', '10.0.0.12:443?x=y', 'user@10.0.0.12:443'):
            with self.subTest(probe=probe), self.assertRaises(ValueError):
                module.script_for({'kind': 'isolate_host'}, probe)
        with self.assertRaises(ValueError):
            module.script_for({'kind': 'block_network', 'target': 'example.com'}, '10.0.0.12:443')

    def test_ipv6_and_inverse_action(self):
        script, expected = module.script_for({'kind': 'unblock_network', 'target': '2001:db8::/32'}, '[2001:db8::1]:443')
        self.assertIn("'2001:db8::1',443", script)
        self.assertEqual(expected, {'reachable': True})

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            module.script_for({'kind': 'kill_process', 'target': '1234'})


if __name__ == '__main__':
    unittest.main()
