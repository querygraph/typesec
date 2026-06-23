"""TypeDID framework adapter sketches for LangChain and Pydantic AI v2.

This example intentionally uses only the Python standard library. It models the
boundary a Python framework should see *after* a local TypeDID gateway has
verified the signature and decrypted the payload:

    VerifiedTypeDidMessageView -> Typesec JSON policy check -> framework tool

Run from the repository root:

    uv run python examples/typedid_framework_adapters.py
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generic, TypeVar


REPO_ROOT = Path(__file__).resolve().parents[1]
RBAC_POLICY_PATH = REPO_ROOT / "policies" / "rbac-example.yaml"

T = TypeVar("T")


@dataclass(frozen=True)
class TypeDidConversationView:
    conversation_id: str
    mode: str
    profile: str
    protocol: str


@dataclass(frozen=True)
class VerifiedTypeDidMessageView:
    """Framework-neutral view produced by a trusted TypeDID opener.

    Python examples do not perform DID cryptography. In production this view
    should be created by the Rust `TypeDidGateway` or a future native binding
    after signature verification, recipient checks, decryption, and replay
    checks have already succeeded.
    """

    subject: str
    action: str
    resource: str
    privacy: str
    payload: bytes
    conversation: TypeDidConversationView
    envelope_id: str
    envelope_digest: str


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    allowed: bool
    subject: str
    action: str
    resource: str
    reason: str | None = None


class TypesecJsonGate:
    """Policy gate using `typesec check --json` as the Python integration seam."""

    def __init__(self, policy_path: Path = RBAC_POLICY_PATH, *, policy_format: str = "rbac"):
        self.policy_path = Path(policy_path)
        self.policy_format = policy_format

    def check(self, message: VerifiedTypeDidMessageView) -> PolicyDecision:
        result = subprocess.run(
            [
                "cargo",
                "run",
                "-q",
                "-p",
                "typesec-cli",
                "--",
                "check",
                "--json",
                "--policy",
                str(self.policy_path),
                "--format",
                self.policy_format,
                "--subject",
                message.subject,
                "--action",
                message.action,
                "--resource",
                message.resource,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.stdout:
            body = json.loads(result.stdout)
            return PolicyDecision(
                decision=body["decision"],
                allowed=body["allowed"],
                subject=body["subject"],
                action=body["action"],
                resource=body["resource"],
                reason=body.get("reason") or body.get("delegate_to"),
            )
        return PolicyDecision(
            decision="error",
            allowed=False,
            subject=message.subject,
            action=message.action,
            resource=message.resource,
            reason=result.stderr.strip() or f"typesec exited {result.returncode}",
        )

    def require(self, message: VerifiedTypeDidMessageView) -> PolicyDecision:
        decision = self.check(message)
        if not decision.allowed:
            reason = decision.reason or f"{message.subject} cannot {message.action} {message.resource}"
            raise PermissionError(reason)
        return decision


class LangChainTypeDidMiddleware:
    """Tiny LangChain-shaped tool gate.

    A real LangChain integration would call this from middleware or a tool
    wrapper. This version keeps the dependency surface zero while preserving the
    control flow: gate first, reveal/use second.
    """

    def __init__(self, gate: TypesecJsonGate):
        self.gate = gate

    def invoke_tool(
        self,
        message: VerifiedTypeDidMessageView,
        tool: Callable[[bytes], T],
    ) -> T:
        self.gate.require(message)
        return tool(message.payload)

    def mcp_headers(self, message: VerifiedTypeDidMessageView) -> dict[str, str]:
        """Headers a LangChain MCP HTTP auth hook could attach for tracing."""

        return {
            "x-typedid-envelope-id": message.envelope_id,
            "x-typedid-envelope-digest": message.envelope_digest,
            "x-typedid-profile": message.conversation.profile,
            "x-typedid-protocol": message.conversation.protocol,
        }


@dataclass
class PydanticTypeDidDeps:
    """Pydantic AI-style dependency object."""

    gate: TypesecJsonGate
    message: VerifiedTypeDidMessageView


class PydanticTypeDidTool(Generic[T]):
    """Pydantic AI-style tool wrapper for dependency-injected tools.

    A Pydantic AI v2 tool receives `RunContext[PydanticTypeDidDeps]` and reads
    `ctx.deps`. This wrapper models that dependency boundary without requiring
    the optional `pydantic-ai` package during smoke tests.
    """

    def __init__(self, handler: Callable[[bytes], T]):
        self.handler = handler

    def __call__(self, deps: PydanticTypeDidDeps) -> T:
        deps.gate.require(deps.message)
        return self.handler(deps.message.payload)


@dataclass(frozen=True)
class PydanticTypesecToolSpec:
    """Serializable Typesec metadata for a Pydantic AI v2 tool."""

    name: str
    description: str
    required_permission: str
    resource_id: str


@dataclass(frozen=True)
class PydanticTypesecCapabilitySpec:
    """Framework-neutral mirror of `pydantic_ai.capabilities.Capability`."""

    id: str
    description: str
    instructions: str
    defer_loading: bool
    tools: tuple[PydanticTypesecToolSpec, ...]

    def as_catalog_entry(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "instructions": self.instructions,
            "defer_loading": self.defer_loading,
            "tools": [tool.__dict__ for tool in self.tools],
        }


def pydantic_typesec_capability_spec() -> PydanticTypesecCapabilitySpec:
    """Return the Typesec capability bundle a Pydantic AI v2 agent should load."""

    return PydanticTypesecCapabilitySpec(
        id="typesec_typedid_reports",
        description="Use for TypeDID-verified report access governed by Typesec.",
        instructions=(
            "Before using protected TypeDID payloads, require the Typesec gate "
            "for the verified subject, action, and resource in run dependencies."
        ),
        defer_loading=True,
        tools=(
            PydanticTypesecToolSpec(
                name="summarize_report",
                description="Summarize a TypeDID-verified sensitive report payload.",
                required_permission="read_sensitive",
                resource_id="reports/q1",
            ),
        ),
    )


def build_pydantic_ai_capability() -> Any:
    """Build a real Pydantic AI v2 Capability when `pydantic-ai` is installed.

    The optional import keeps repository smoke tests deterministic. Production
    code can pass the returned capability to `Agent(..., capabilities=[...])`
    and register tools that accept `RunContext[PydanticTypeDidDeps]`.
    """

    try:
        from pydantic_ai.capabilities import Capability
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("install pydantic-ai to build the runtime capability") from exc

    spec = pydantic_typesec_capability_spec()
    capability = Capability(
        id=spec.id,
        description=spec.description,
        instructions=spec.instructions,
        defer_loading=spec.defer_loading,
    )

    @capability.tool
    async def summarize_report_tool(ctx: Any) -> str:
        """Summarize a TypeDID-verified sensitive report payload."""

        tool = PydanticTypeDidTool(summarize_report)
        return tool(ctx.deps)

    return capability


def summarize_report(payload: bytes) -> str:
    text = payload.decode("utf-8")
    return f"summary({len(text)} bytes): {text[:32]}"


def demo_message(*, subject: str = "agent:data-pipeline") -> VerifiedTypeDidMessageView:
    return VerifiedTypeDidMessageView(
        subject=subject,
        action="read_sensitive",
        resource="reports/q1",
        privacy="secret",
        payload=b"quarterly revenue and customer retention notes",
        conversation=TypeDidConversationView(
            conversation_id="task/langchain-report-review",
            mode="request_reply",
            profile="typedid/v1/x25519-chacha20poly1305-ed25519",
            protocol="mcp",
        ),
        envelope_id="typedid-msg-1",
        envelope_digest="sha256:demo",
    )


def run_langchain_style_demo() -> str:
    middleware = LangChainTypeDidMiddleware(TypesecJsonGate())
    return middleware.invoke_tool(demo_message(), summarize_report)


def run_pydantic_style_demo() -> str:
    tool = PydanticTypeDidTool(summarize_report)
    deps = PydanticTypeDidDeps(gate=TypesecJsonGate(), message=demo_message())
    return tool(deps)


def run_pydantic_capability_spec_demo() -> str:
    spec = pydantic_typesec_capability_spec()
    tool = spec.tools[0]
    return f"{spec.id}:{tool.name}:{tool.required_permission}:{tool.resource_id}"


def run_denied_demo() -> str:
    middleware = LangChainTypeDidMiddleware(TypesecJsonGate())
    try:
        middleware.invoke_tool(demo_message(subject="agent:deploy-bot"), summarize_report)
    except PermissionError as exc:
        return f"blocked as expected: {exc}"
    raise AssertionError("denied TypeDID message unexpectedly ran")


def main() -> None:
    print(f"LangChain-style: {run_langchain_style_demo()}")
    print(f"Pydantic-style:  {run_pydantic_style_demo()}")
    print(f"Pydantic capability: {run_pydantic_capability_spec_demo()}")
    print(run_denied_demo())


if __name__ == "__main__":
    main()
