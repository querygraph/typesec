"""Pydantic AI Typesec adapter for the company graph example.

The integration uses Pydantic AI's normal dependency injection (`deps_type`) and
tool hooks. No Pydantic fork or monkeypatching is needed: each tool receives a
`RunContext[CompanyGraphDeps]`, checks Typesec, then mutates the shared graph.

Install Pydantic AI to run the agent-backed path:

    uv sync --group dev
    uv run python examples/company_graph/pydantic_company_graph.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from company_graph_core import CompanyGraph, EMPLOYEES, REPORTING_LINES, TypesecGate

try:
    from pydantic_ai import Agent, RunContext
except ImportError:  # pragma: no cover - optional example dependency
    Agent = None  # type: ignore[assignment]
    RunContext = object  # type: ignore[assignment,misc]


@dataclass
class CompanyGraphDeps:
    subject: str
    gate: TypesecGate
    graph: CompanyGraph


def build_company_graph_agent() -> Any:
    """Build a real Pydantic AI agent with Typesec-gated tools.

    Constructing an OpenAI-backed Pydantic AI agent may validate provider
    credentials, so the example keeps this behind an explicit function. The
    deterministic smoke path below exercises the same policy boundary without an
    API key.
    """

    if Agent is None:
        raise RuntimeError("pydantic-ai is not installed")

    company_graph_agent = Agent(
        "openai:gpt-5",
        deps_type=CompanyGraphDeps,
        output_type=str,
        system_prompt=(
            "You maintain a company graph. Use the registered tools for all "
            "employee and reporting-line writes."
        ),
    )

    @company_graph_agent.tool
    async def add_employee(
        ctx: RunContext[CompanyGraphDeps],
        employee_id: str,
        visibility: str,
    ) -> str:
        resource = f"employee/{visibility}/{employee_id}"
        await ctx.deps.gate.arequire(ctx.deps.subject, "write", resource)
        return ctx.deps.graph.add_employee(employee_id, **EMPLOYEES[employee_id])

    @company_graph_agent.tool
    async def add_reports_to(
        ctx: RunContext[CompanyGraphDeps],
        employee_id: str,
        manager_id: str,
    ) -> str:
        resource = f"relationship/reports_to/{employee_id}/{manager_id}"
        await ctx.deps.gate.arequire(ctx.deps.subject, "write", resource)
        return ctx.deps.graph.add_reports_to(employee_id, manager_id)

    @company_graph_agent.tool
    async def read_sensitive_network(ctx: RunContext[CompanyGraphDeps]) -> dict[str, object]:
        await ctx.deps.gate.arequire(
            ctx.deps.subject,
            "read_sensitive",
            "network/org-chart",
        )
        return ctx.deps.graph.sensitive_network_snapshot()

    return company_graph_agent


async def run_scripted_pydantic_flow() -> list[str]:
    """Exercise the same Pydantic dependency/tool security boundary without an LLM."""

    gate = TypesecGate()
    graph = CompanyGraph()
    events: list[str] = []

    # These calls mirror what the registered Pydantic tools do: policy first,
    # side effect second. Keeping this path deterministic makes it useful in CI.
    await gate.arequire(
        "agent:executive-chief",
        "write",
        "employee/executive/employee:evelyn",
    )
    events.append(graph.add_employee("employee:evelyn", **EMPLOYEES["employee:evelyn"]))

    for employee_id in ["employee:priya", "employee:marco", "employee:nia", "employee:omar"]:
        await gate.arequire("agent:hr-onboarding", "write", f"employee/private/{employee_id}")
        events.append(graph.add_employee(employee_id, **EMPLOYEES[employee_id]))

    for employee_id, manager_id in REPORTING_LINES:
        await gate.arequire(
            "agent:hr-onboarding",
            "write",
            f"relationship/reports_to/{employee_id}/{manager_id}",
        )
        events.append(graph.add_reports_to(employee_id, manager_id))

    try:
        await gate.arequire(
            "agent:employee-nia",
            "read_sensitive",
            "network/org-chart",
        )
    except PermissionError as exc:
        events.append(f"blocked as expected: {exc}")

    await gate.arequire("agent:executive-chief", "read_sensitive", "network/org-chart")
    events.append(str(graph.sensitive_network_snapshot()))
    return events


def main() -> None:
    if Agent is None:
        print("pydantic-ai is not installed; running the deterministic tool-boundary flow")
    else:
        print("pydantic-ai is installed; running the deterministic tool-boundary flow")

    import asyncio

    for event in asyncio.run(run_scripted_pydantic_flow()):
        print(event)


if __name__ == "__main__":
    main()
