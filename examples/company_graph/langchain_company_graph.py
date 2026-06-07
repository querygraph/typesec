"""LangChain-style Typesec adapter for the company graph example.

This script intentionally does not import LangChain. It shows the same wrapper
shape a LangChain tool would use while keeping the reusable policy gate and
domain model in `company_graph_core.py`.

Run from the repository root:

    uv run python examples/company_graph/langchain_company_graph.py
"""

from __future__ import annotations

from company_graph_core import TypesecGate, build_company_graph


def main() -> None:
    _graph, events = build_company_graph(TypesecGate())
    for event in events:
        print(event)


if __name__ == "__main__":
    main()
