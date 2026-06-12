"""Smoke tests for the TypeDID framework adapter examples."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PATH = REPO_ROOT / "examples" / "typedid_framework_adapters.py"


def load_example_module():
    spec = importlib.util.spec_from_file_location("typedid_framework_adapters", EXAMPLE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TypeDidFrameworkAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.example = load_example_module()

    def test_langchain_style_wrapper_gates_before_tool_invocation(self) -> None:
        result = self.example.run_langchain_style_demo()
        self.assertIn("summary(", result)

    def test_pydantic_style_deps_gate_before_tool_invocation(self) -> None:
        result = self.example.run_pydantic_style_demo()
        self.assertIn("summary(", result)

    def test_denied_message_does_not_run_tool(self) -> None:
        result = self.example.run_denied_demo()
        self.assertIn("blocked as expected", result)
        self.assertIn("agent:deploy-bot", result)
        self.assertIn("read_sensitive", result)

    def test_mcp_headers_preserve_envelope_trace_context(self) -> None:
        message = self.example.demo_message()
        middleware = self.example.LangChainTypeDidMiddleware(self.example.TypesecJsonGate())
        headers = middleware.mcp_headers(message)
        self.assertEqual(headers["x-typedid-envelope-id"], "typedid-msg-1")
        self.assertEqual(headers["x-typedid-profile"], message.conversation.profile)


if __name__ == "__main__":
    unittest.main()
