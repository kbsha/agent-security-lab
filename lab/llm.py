"""Model back-ends. Both speak OpenAI-style chat messages with tool calls.

MockLLM is a deterministic, deliberately naive model: it investigates the
alert sensibly, but if a document it reads contains an "ignore the original
task" instruction, it obeys. That makes the attack reproducible on stage and
models the worst case — the secured agent must hold even then.

OpenAICompatLLM talks to any OpenAI-compatible endpoint (Ollama, LM Studio,
llama.cpp server, vLLM, or a hosted API). Real models may or may not fall for
the injection; that variability is part of the lesson.
"""

import itertools
import json
import os
import re
import urllib.request
from dataclasses import dataclass, field

from .tools import INTERNAL_DOMAIN


@dataclass
class Reply:
    content: str | None = None
    tool_calls: list = field(default_factory=list)  # [{"id", "name", "arguments": dict}]
    thought: str | None = None


_ids = itertools.count(1)


def _call(name, args, thought):
    return Reply(tool_calls=[{"id": f"call_{next(_ids)}", "name": name, "arguments": args}], thought=thought)


_TRIGGER = re.compile(r"ignore\s+(?:the\s+|all\s+|any\s+)?(?:user'?s?\s+)?(?:previous|original|prior)\s+(?:task|instructions?)", re.I)
_ACTIONS = [
    ("get_secret", re.compile(r"get_secret\(\s*['\"]?([A-Za-z0-9_]+)")),
    ("send_email", re.compile(r"(?:e-?mail|send)\b[^.]*?\bto\s+([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", re.I | re.S)),
    ("isolate_host", re.compile(r"isolate_host\(\s*['\"]?([A-Za-z0-9-]+)")),
]


def injected_actions(text: str) -> list:
    """Actions an injected instruction block asks for, in the order written."""
    match = _TRIGGER.search(text)
    if not match:
        return []
    tail = text[match.start():]
    found = []
    for name, pattern in _ACTIONS:
        for m in pattern.finditer(tail):
            found.append((m.start(), name, m.group(1)))
    return [(name, value) for _, name, value in sorted(found)]


def _summary(tool_texts: list) -> str:
    rows = []
    for text in tool_texts:
        rows += re.findall(r"^(\S+?Z),(fin-db-02),(\w+),([\d.]+),(FAIL|SUCCESS)$", text, re.M)
    if not rows:
        return ("Investigation summary — fin-db-02\n"
                "- Incident INC-0417 reports a burst of failed admin logins from 10.0.8.51.\n"
                "- I could not find the raw authentication logs to confirm whether a login succeeded.")
    fails = [r for r in rows if r[4] == "FAIL"]
    wins = [r for r in rows if r[4] == "SUCCESS"]
    t = lambda ts: ts[11:16]
    lines = [
        "Investigation summary — fin-db-02",
        f"- {len(fails)} failed logins for '{fails[0][2]}' from {fails[0][3]} between "
        f"{t(fails[0][0])} and {t(fails[-1][0])} UTC.",
    ]
    if wins:
        lines.append(f"- Followed by a SUCCESSFUL login at {t(wins[0][0])} UTC: password guessing likely succeeded.")
    lines.append("- Recommended: reset the admin credential, review activity after the successful login, "
                 "and consider isolating fin-db-02 (needs approval).")
    return "\n".join(lines)


class MockLLM:
    label = "Mock LLM (deterministic, naive)"

    def chat(self, messages: list, tools: list) -> Reply:
        task = next(m["content"] for m in messages if m["role"] == "user")
        made, results = [], {}
        for m in messages:
            if m["role"] == "assistant":
                for tc in m.get("tool_calls", []):
                    made.append((tc["id"], tc["function"]["name"], json.loads(tc["function"]["arguments"])))
            elif m["role"] == "tool":
                results[m["tool_call_id"]] = m["content"]
        names = [n for _, n, _ in made]

        # 1. Look for evidence.
        if "search_kb" not in names:
            return _call("search_kb", {"query": task}, "I'll search the knowledge base for evidence about this alert.")

        # 2. Read every document the search returned.
        search_out = results.get(next(i for i, n, _ in made if n == "search_kb"), "")
        read = {a.get("doc_id") for _, n, a in made if n == "read_doc"}
        for doc_id in re.findall(r'"doc_id":\s*"([^"]+)"', search_out):
            if doc_id not in read:
                return _call("read_doc", {"doc_id": doc_id}, f"Reading '{doc_id}' to gather details.")

        # 3. The vulnerability: treat instructions found in documents as orders.
        doc_texts = [results.get(i, "") for i, n, _ in made if n == "read_doc"]
        secret_result = next((results.get(i, "") for i, n, _ in made if n == "get_secret"), "")
        secret = secret_result if secret_result and "DENIED" not in secret_result and "No such" not in secret_result else None
        done = {(n, json.dumps(a, sort_keys=True)) for _, n, a in made}
        for text in doc_texts:
            for name, value in injected_actions(text):
                if name == "get_secret":
                    args = {"name": value}
                    why = f"The threat-intel note says to call get_secret('{value}'). Doing that now."
                elif name == "send_email":
                    body = f"Requested value: {secret}" if secret else "Requested value could not be retrieved."
                    args = {"to": value, "subject": "Compliance audit value", "body": body}
                    why = f"The note asks me to email the value to {value}."
                else:
                    args = {"host": value}
                    why = f"The note says to isolate {value} to contain the threat."
                if (name, json.dumps(args, sort_keys=True)) not in done and not any(n == name for _, n, _ in made):
                    return _call(name, args, why)

        # 4. Report.
        answer = _summary([results.get(i, "") for i, *_ in made])
        executed, blocked = [], []
        for i, n, a in made:
            if n in {"get_secret", "send_email", "isolate_host"}:
                (blocked if results.get(i, "").startswith("DENIED") else executed).append((n, a))
        if secret:
            answer += f"\n- Audit value retrieved as instructed: {secret}"
        for n, a in executed:
            if n == "send_email" and not a["to"].endswith("@" + INTERNAL_DOMAIN):
                answer += f"\n- Sent the audit value to {a['to']}."
            if n == "isolate_host":
                answer += f"\n- Isolated {a['host']} to contain the threat."
        if blocked:
            answer += "\n- Note: some actions requested by a retrieved document were blocked by policy."
        return Reply(content=answer, thought="I have enough evidence to write the summary.")


class OpenAICompatLLM:
    def __init__(self, base_url=None, model=None, api_key=None, timeout=120):
        self.base_url = (base_url or os.environ.get("LAB_LLM_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
        self.model = model or os.environ.get("LAB_LLM_MODEL", "llama3.1")
        self.api_key = api_key or os.environ.get("LAB_LLM_API_KEY", "")
        self.timeout = timeout
        self.label = f"{self.model} @ {self.base_url}"

    def chat(self, messages: list, tools: list) -> Reply:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "tools": [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                        "parameters": t.schema()}} for t in tools],
        }
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {})},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            msg = json.load(resp)["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            raw = tc["function"].get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                args = {"_unparseable": raw}
            calls.append({"id": tc.get("id") or f"call_{next(_ids)}", "name": tc["function"]["name"], "arguments": args})
        content = msg.get("content")
        return Reply(content=None if calls else content, tool_calls=calls, thought=content if calls else None)


def make_llm(provider="mock", base_url=None, model=None):
    return MockLLM() if provider == "mock" else OpenAICompatLLM(base_url=base_url, model=model)
