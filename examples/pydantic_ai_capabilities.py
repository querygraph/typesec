"""Complete Pydantic AI v2 capability example for TypeDID + Typesec.

The example uses Pydantic AI's real `Capability` and `Agent` APIs with
`TestModel`, so it runs without provider credentials:

    uv run python examples/pydantic_ai_capabilities.py

The flow is:

1. A trusted TypeDID opener has already verified and decrypted a message.
2. A Pydantic AI v2 capability registers a tool for the verified payload.
3. The tool receives `RunContext[TypesecPydanticDeps]`.
4. The tool checks Typesec before reading the payload.
5. A denied subject cannot make the tool run.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import Capability
from pydantic_ai.models.test import TestModel


REPO_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = REPO_ROOT / "examples" / "typedid_framework_adapters.py"


def load_adapter_module() -> Any:
    spec = importlib.util.spec_from_file_location("typedid_framework_adapters", ADAPTER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ADAPTER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adapter = load_adapter_module()


@dataclass
class TypesecPydanticDeps:
    gate: Any
    message: Any


def build_typesec_report_capability(*, defer_loading: bool = False) -> Capability[TypesecPydanticDeps]:
    """Build the Pydantic AI capability that exposes Typesec-protected tools."""

    spec = adapter.pydantic_typesec_capability_spec()
    capability = Capability[TypesecPydanticDeps](
        id=spec.id,
        description=spec.description,
        instructions=spec.instructions,
        defer_loading=defer_loading,
    )

    @capability.tool(
        name=spec.tools[0].name,
        description=spec.tools[0].description,
        metadata={
            "typesec_required_permission": spec.tools[0].required_permission,
            "typesec_resource_id": spec.tools[0].resource_id,
        },
    )
    async def summarize_report(ctx: RunContext[TypesecPydanticDeps]) -> str:
        ctx.deps.gate.require(ctx.deps.message)
        return adapter.summarize_report(ctx.deps.message.payload)

    return capability


def build_agent() -> Agent[TypesecPydanticDeps, str]:
    return Agent(
        TestModel(call_tools=["summarize_report"]),
        deps_type=TypesecPydanticDeps,
        output_type=str,
        instructions=(
            "Use the Typesec report capability for verified TypeDID report "
            "payloads. Never summarize protected payloads without the tool."
        ),
        capabilities=[build_typesec_report_capability()],
    )


async def run_allowed_agent() -> str:
    deps = TypesecPydanticDeps(
        gate=adapter.TypesecJsonGate(),
        message=adapter.demo_message(subject="agent:data-pipeline"),
    )
    result = await build_agent().run("Summarize the verified report.", deps=deps)
    return str(result.output)


async def run_denied_agent() -> str:
    deps = TypesecPydanticDeps(
        gate=adapter.TypesecJsonGate(),
        message=adapter.demo_message(subject="agent:deploy-bot"),
    )
    try:
        await build_agent().run("Summarize the verified report.", deps=deps)
    except PermissionError as exc:
        return f"blocked as expected: {exc}"
    raise AssertionError("denied subject unexpectedly received the protected payload")


async def run_demo() -> list[str]:
    return [
        await run_allowed_agent(),
        await run_denied_agent(),
    ]


def main() -> None:
    for line in asyncio.run(run_demo()):
        print(line)


if __name__ == "__main__":
    main()
