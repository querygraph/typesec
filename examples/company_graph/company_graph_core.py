"""Framework-neutral Typesec helpers for the company graph examples."""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar


REPO_ROOT = Path(__file__).resolve().parents[2]
GRAPH_POLICY_PATH = REPO_ROOT / "policies" / "graph-corporate-example.yaml"

T = TypeVar("T")


EMPLOYEES: dict[str, dict[str, Any]] = {
    "employee:evelyn": {
        "name": "Evelyn Chen",
        "title": "Chief Executive Officer",
        "department": "Executive",
        "level": "Executive",
        "compensation_band": "exec-1",
    },
    "employee:priya": {
        "name": "Priya Raman",
        "title": "VP Engineering",
        "department": "Engineering",
        "level": "VP",
        "compensation_band": "vp-2",
    },
    "employee:marco": {
        "name": "Marco Silva",
        "title": "Engineering Manager",
        "department": "Engineering",
        "level": "M2",
        "compensation_band": "m2-3",
    },
    "employee:nia": {
        "name": "Nia Patel",
        "title": "Senior Software Engineer",
        "department": "Engineering",
        "level": "IC4",
        "compensation_band": "ic4-4",
    },
    "employee:omar": {
        "name": "Omar Haddad",
        "title": "Data Engineer",
        "department": "Data",
        "level": "IC3",
        "compensation_band": "ic3-2",
    },
}

REPORTING_LINES = [
    ("employee:priya", "employee:evelyn"),
    ("employee:marco", "employee:priya"),
    ("employee:nia", "employee:marco"),
    ("employee:omar", "employee:marco"),
]


@dataclass
class CompanyGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    relationships: list[dict[str, Any]] = field(default_factory=list)

    def add_employee(self, employee_id: str, **props: Any) -> str:
        self.nodes[employee_id] = {"label": "Employee", "id": employee_id, **props}
        return f"node:{employee_id}"

    def add_reports_to(self, employee_id: str, manager_id: str) -> str:
        rel = {
            "type": "REPORTS_TO",
            "from": employee_id,
            "to": manager_id,
            "visibility": "employee-network",
        }
        self.relationships.append(rel)
        return f"relationship:{employee_id}->REPORTS_TO->{manager_id}"

    def sensitive_network_snapshot(self) -> dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "relationship_count": len(self.relationships),
            "relationships": self.relationships,
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    subject: str
    action: str
    resource: str
    reason: str | None = None


class TypesecGate:
    """Policy gate with a Rust-native fast path and CLI fallback.

    The optional native path comes from the `typesec_native` PyO3 module in
    `crates/typesec-python`. The fallback keeps examples runnable from a source
    checkout without building the Python wheel first.
    """

    def __init__(self, policy_path: Path = GRAPH_POLICY_PATH, *, policy_format: str = "graph"):
        self.policy_path = Path(policy_path)
        self.policy_format = policy_format
        self._native_gate: Any | None = None
        try:
            from typesec_native import TypesecGate as NativeTypesecGate
        except ImportError:
            return

        self._native_gate = NativeTypesecGate.from_file(
            str(self.policy_path),
            format=self.policy_format,
        )

    def check(self, subject: str, action: str, resource: str) -> PolicyDecision:
        if self._native_gate is not None:
            decision = self._native_gate.check(subject, action, resource)
            return PolicyDecision(
                allowed=decision.allowed,
                subject=decision.subject,
                action=decision.action,
                resource=decision.resource,
                reason=decision.reason,
            )

        result = subprocess.run(
            [
                "cargo",
                "run",
                "-q",
                "-p",
                "typesec-cli",
                "--",
                "check",
                "--policy",
                str(self.policy_path),
                "--format",
                self.policy_format,
                "--subject",
                subject,
                "--action",
                action,
                "--resource",
                resource,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        return PolicyDecision(
            allowed=result.returncode == 0,
            subject=subject,
            action=action,
            resource=resource,
            reason=None if result.returncode == 0 else result.stdout.strip() or result.stderr.strip(),
        )

    def require(self, subject: str, action: str, resource: str) -> PolicyDecision:
        decision = self.check(subject, action, resource)
        if not decision.allowed:
            reason = decision.reason or f"{subject} cannot {action} {resource}"
            raise PermissionError(reason)
        return decision

    async def arequire(self, subject: str, action: str, resource: str) -> PolicyDecision:
        return await asyncio.to_thread(self.require, subject, action, resource)


def secure_tool(
    gate: TypesecGate,
    *,
    subject: str,
    action: str,
    resource: str,
    fn: Callable[[], T],
) -> T:
    gate.require(subject, action, resource)
    return fn()


def build_company_graph(gate: TypesecGate) -> tuple[CompanyGraph, list[str]]:
    graph = CompanyGraph()
    events: list[str] = []

    events.append("executive writes executive node")
    events.append(
        secure_tool(
            gate,
            subject="agent:executive-chief",
            action="write",
            resource="employee/executive/employee:evelyn",
            fn=lambda: graph.add_employee("employee:evelyn", **EMPLOYEES["employee:evelyn"]),
        )
    )

    events.append("HR writes non-executive employees and reporting lines")
    for employee_id in ["employee:priya", "employee:marco", "employee:nia", "employee:omar"]:
        events.append(
            secure_tool(
                gate,
                subject="agent:hr-onboarding",
                action="write",
                resource=f"employee/private/{employee_id}",
                fn=lambda employee_id=employee_id: graph.add_employee(
                    employee_id, **EMPLOYEES[employee_id]
                ),
            )
        )

    for employee_id, manager_id in REPORTING_LINES:
        events.append(
            secure_tool(
                gate,
                subject="agent:hr-onboarding",
                action="write",
                resource=f"relationship/reports_to/{employee_id}/{manager_id}",
                fn=lambda employee_id=employee_id, manager_id=manager_id: graph.add_reports_to(
                    employee_id, manager_id
                ),
            )
        )

    events.append("employee self-service updates only their public profile")
    events.append(
        secure_tool(
            gate,
            subject="agent:employee-nia",
            action="write",
            resource="employee/public/employee:nia",
            fn=lambda: graph.add_employee(
                "employee:nia",
                **{**EMPLOYEES["employee:nia"], "preferred_name": "Nia"},
            ),
        )
    )

    for subject, action, resource in [
        ("agent:hr-onboarding", "write", "employee/executive/employee:evelyn"),
        ("agent:employee-nia", "read_sensitive", "network/org-chart"),
    ]:
        try:
            secure_tool(
                gate,
                subject=subject,
                action=action,
                resource=resource,
                fn=lambda: "should not run",
            )
        except PermissionError as exc:
            events.append(f"blocked as expected: {exc}")

    if gate.check("agent:executive-chief", "read_sensitive", "network/org-chart").allowed:
        events.append(f"executive sensitive network read: {graph.sensitive_network_snapshot()}")

    return graph, events
