"""Smoke tests for the complete Pydantic AI capability example."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PATH = REPO_ROOT / "examples" / "pydantic_ai_capabilities.py"


def load_example_module():
    spec = importlib.util.spec_from_file_location("pydantic_ai_capabilities", EXAMPLE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PydanticAiCapabilityExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.example = load_example_module()

    def test_agent_uses_typesec_capability_for_allowed_payload(self) -> None:
        result = asyncio.run(self.example.run_allowed_agent())
        self.assertIn("summarize_report", result)
        self.assertIn("summary(46 bytes)", result)

    def test_agent_blocks_denied_payload(self) -> None:
        result = asyncio.run(self.example.run_denied_agent())
        self.assertIn("blocked as expected", result)
        self.assertIn("agent:deploy-bot", result)

    def test_capability_metadata_carries_typesec_requirement(self) -> None:
        capability = self.example.build_typesec_report_capability()
        toolset = capability.get_toolset()
        self.assertIsNotNone(toolset)


if __name__ == "__main__":
    unittest.main()
