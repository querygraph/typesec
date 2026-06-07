"""Self-contained LangChain-style Typesec example for a company graph.

This script does not call an LLM and does not require LangChain to be installed.
It uses the same shape as a LangChain tool wrapper: each side-effecting graph
tool is wrapped by a Typesec policy check before it mutates the in-memory graph.

Run from the repository root:

    python3 examples/langchain_company_graph.py

The generated graph mirrors `company_graph_grust_sail.rs`; the Rust example
persists the same network through Grust's Sail backend when Sail is available.
"""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]

POLICY = """
roles:
  - name: executive_graph_admin
    permissions: [read_sensitive, write]
    resources:
      - "company/*"
      - "employee/**"
      - "relationship/**"
      - "network/**"

  - name: hr_graph_writer
    permissions: [write]
    resources:
      - "employee/public/**"
      - "employee/private/employee:*"
      - "relationship/reports_to/**"

  - name: employee_self_service
    permissions: [write]
    resources:
      - "employee/public/employee:nia"

assignments:
  - subject: "agent:executive-chief"
    roles: [executive_graph_admin]
  - subject: "agent:hr-onboarding"
    roles: [hr_graph_writer]
  - subject: "agent:employee-nia"
    roles: [employee_self_service]
"""


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


class TypesecGate:
    def __init__(self, policy: str) -> None:
        self._policy_file = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        self._policy_file.write(textwrap.dedent(policy))
        self._policy_file.close()
        self.policy_path = Path(self._policy_file.name)

    def close(self) -> None:
        self.policy_path.unlink(missing_ok=True)

    def allowed(self, subject: str, action: str, resource: str) -> bool:
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
        return result.returncode == 0


def secure_tool(
    gate: TypesecGate,
    *,
    subject: str,
    action: str,
    resource: str,
    fn: Callable[[], str],
) -> str:
    if not gate.allowed(subject, action, resource):
        raise PermissionError(f"{subject} cannot {action} {resource}")
    return fn()


def main() -> None:
    gate = TypesecGate(POLICY)
    graph = CompanyGraph()

    employees = {
        "employee:evelyn": {
            "name": "Evelyn Chen",
            "title": "Chief Executive Officer",
            "department": "Executive",
            "level": "E",
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

    try:
        print("executive writes executive node")
        print(
            secure_tool(
                gate,
                subject="agent:executive-chief",
                action="write",
                resource="employee/executive/employee:evelyn",
                fn=lambda: graph.add_employee("employee:evelyn", **employees["employee:evelyn"]),
            )
        )

        print("HR writes non-executive employees and reporting lines")
        for employee_id in ["employee:priya", "employee:marco", "employee:nia", "employee:omar"]:
            print(
                secure_tool(
                    gate,
                    subject="agent:hr-onboarding",
                    action="write",
                    resource=f"employee/private/{employee_id}",
                    fn=lambda employee_id=employee_id: graph.add_employee(
                        employee_id, **employees[employee_id]
                    ),
                )
            )

        for employee_id, manager_id in [
            ("employee:priya", "employee:evelyn"),
            ("employee:marco", "employee:priya"),
            ("employee:nia", "employee:marco"),
            ("employee:omar", "employee:marco"),
        ]:
            print(
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

        print("employee self-service updates only their public profile")
        print(
            secure_tool(
                gate,
                subject="agent:employee-nia",
                action="write",
                resource="employee/public/employee:nia",
                fn=lambda: graph.add_employee(
                    "employee:nia",
                    **{**employees["employee:nia"], "preferred_name": "Nia"},
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
                print(f"blocked as expected: {exc}")

        print("executive sensitive network read:")
        if gate.allowed("agent:executive-chief", "read_sensitive", "network/org-chart"):
            print(
                {
                    "node_count": len(graph.nodes),
                    "relationship_count": len(graph.relationships),
                    "relationships": graph.relationships,
                }
            )
    finally:
        gate.close()


if __name__ == "__main__":
    main()
