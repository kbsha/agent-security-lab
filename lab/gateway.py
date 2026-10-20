"""Policy gateway: deterministic checks between the model and every tool.

The model proposes a tool call; the gateway decides. Nothing here depends on
the model behaving well.
"""

import time
from dataclasses import dataclass, field

from .tools import INTERNAL_DOMAIN, SECRET_PATTERN, TOOLS, validate


@dataclass
class User:
    id: str
    scopes: frozenset


ANALYST = User("analyst-7", frozenset({"kb:read", "mail:send", "net:isolate"}))

# Tools this agent role is allowed to use at all. get_secret is not one of them.
INVESTIGATOR_ALLOWLIST = ("search_kb", "read_doc", "send_email", "isolate_host")


def redact(value):
    if isinstance(value, str):
        return SECRET_PATTERN.sub("[REDACTED]", value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    return value


@dataclass
class Decision:
    allowed: bool
    layer: str
    reason: str


@dataclass
class Gateway:
    user: User
    approver: callable  # (call_id, name, args) -> bool
    allowlist: tuple = INVESTIGATOR_ALLOWLIST
    audit: list = field(default_factory=list)

    def check(self, call_id: str, name: str, args) -> Decision:
        decision = self._decide(call_id, name, args)
        self.audit.append({
            "ts": time.strftime("%H:%M:%S"),
            "user": self.user.id,
            "tool": name,
            "args": redact(args),
            "decision": "allow" if decision.allowed else "deny",
            "layer": decision.layer,
            "reason": decision.reason,
        })
        return decision

    def _decide(self, call_id, name, args) -> Decision:
        if name not in self.allowlist or name not in TOOLS:
            return Decision(False, "allowlist", f"'{name}' is not on this agent's tool allowlist")
        spec = TOOLS[name]
        error = validate(spec, args)
        if error:
            return Decision(False, "validation", error)
        if spec.scope not in self.user.scopes:
            return Decision(False, "authorization", f"user {self.user.id} lacks scope {spec.scope}")
        if name == "send_email" and not args["to"].lower().endswith("@" + INTERNAL_DOMAIN):
            return Decision(False, "egress", f"external recipient {args['to']} is not allowed")
        if SECRET_PATTERN.search(str(args)):
            return Decision(False, "dlp", "arguments contain protected data")
        if spec.gated and not self.approver(call_id, name, args):
            return Decision(False, "approval", "human reviewer did not approve")
        return Decision(True, "approved" if spec.gated else "policy", "all checks passed")
