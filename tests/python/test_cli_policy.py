"""Python smoke tests for the typesec CLI policy boundary.

Run from the repository root with:

    uv run python -m unittest discover -s tests/python

These tests intentionally use only the Python standard library. They model the
same integration seam a LangChain tool or Python REPL experiment would use:
construct a policy on the fly, ask `typesec check` for a decision, and gate the
Python-side action on the CLI result.
"""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class TypesecCliPolicyTests(unittest.TestCase):
    def run_typesec_check(
        self,
        *,
        policy: str,
        subject: str,
        action: str,
        resource: str,
        purpose: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write(textwrap.dedent(policy))
            policy_path = Path(handle.name)

        try:
            command = [
                "cargo",
                "run",
                "-q",
                "-p",
                "typesec-cli",
                "--",
                "check",
                "--policy",
                str(policy_path),
                "--subject",
                subject,
                "--action",
                action,
                "--resource",
                resource,
            ]
            if purpose is not None:
                command.extend(["--purpose", purpose])

            return subprocess.run(
                command,
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        finally:
            policy_path.unlink(missing_ok=True)

    def test_python_can_gate_rbac_tool_calls(self) -> None:
        policy = """
        roles:
          - name: analyst
            permissions: [read]
            resources: ["reports/*"]
        assignments:
          - subject: "agent:analyst"
            roles: [analyst]
        """

        allow = self.run_typesec_check(
            policy=policy,
            subject="agent:analyst",
            action="read",
            resource="reports/q1",
        )
        self.assertEqual(allow.returncode, 0, allow.stdout + allow.stderr)
        self.assertIn("ALLOW", allow.stdout)

        deny = self.run_typesec_check(
            policy=policy,
            subject="agent:analyst",
            action="write",
            resource="reports/q1",
        )
        self.assertNotEqual(deny.returncode, 0, deny.stdout + deny.stderr)
        self.assertIn("DENY", deny.stdout)

    def test_python_can_supply_odrl_runtime_context(self) -> None:
        policy = """
        policies:
          - uid: "policy:purpose-read"
            type: Set
            rules:
              - type: permission
                assigner: "org:acme"
                assignee: "agent:summarizer"
                action: read
                target: "asset:customer-data"
                constraints:
                  - leftOperand: purpose
                    operator: eq
                    rightOperand: "analytics"
        """

        allow = self.run_typesec_check(
            policy=policy,
            subject="agent:summarizer",
            action="read",
            resource="customer-data",
            purpose="analytics",
        )
        self.assertEqual(allow.returncode, 0, allow.stdout + allow.stderr)

        blocked = self.run_typesec_check(
            policy=policy,
            subject="agent:summarizer",
            action="read",
            resource="customer-data",
            purpose="billing",
        )
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)


if __name__ == "__main__":
    unittest.main()
