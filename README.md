# Trust, But Verify — Agent Security Live Lab demo for the scenario

A live demonstration of **indirect prompt injection** against an AI agent, and of the
**application-level controls** that contain it. Built for the KTT Fellowship masterclass
*"Trust, But Verify: Securing the Age of Agentic AI"*.

NovaTech's SOC assistant is asked to investigate a suspicious login. One document in its
knowledge base contains hidden attacker instructions. The same model runs in two
architectures, side by side:

| | Insecure agent | Secured agent |
|---|---|---|
| Secret in the prompt | Yes | No |
| Tools offered | All, including the vault | Allowlist for the investigator role |
| Tool calls | Executed as requested | Checked by a policy gateway |
| Retrieved text | Mixed in with instructions | Wrapped as `<untrusted>` data |
| Consequential actions | Run immediately | Paused for human approval |
| Audit trail | None | Every decision logged, secrets redacted |

> ⭐ **If you use this lab in a class, talk, or workshop, please [star the repo](https://github.com/kbsha/agent-security-lab)
> and [follow @kbsha](https://github.com/kbsha) for more AI-security labs.** It helps other people find it.

> **Safety:** everything is simulated and synthetic. The "secret" is the dummy value
> `TRAINING-ONLY-4821`, email goes to an in-memory outbox, and "isolating a host" only
> appends to a list. Nothing connects to real systems.

## Online version (no install needed )

[docs/index.html](docs/index.html) is a browser-only build of the demo: the same agent, gateway,
mock model and scorecard, ported to JavaScript, so it runs from any static host with no server.
With GitHub Pages enabled on this repo (Settings → Pages → *Deploy from a branch* → `main` /
`/docs`), it is served at `https://kbsha.github.io/agent-security-lab/`.

To change it, edit [docs/app.html](docs/app.html), then run `python3 docs/build.py` to regenerate
`index.html`. The online version always uses the mock model; use the Python server below to try
a real LLM.

## Quick start as follow ...

Requires Python 3.10+. No packages to install.

```bash
git clone <this repo> && cd agent-security-lab
python3 server.py
# open http://localhost:8000
```

Terminal fallback (if the browser or projector fails):

```bash
python3 cli.py               # both agents, mock model
python3 cli.py --mode secure # approve/deny at the prompt
python3 cli.py --scorecard
```

Tests (the security properties, as regression tests):

```bash
python3 -m unittest -v
```

## Presenter run-sheet (....)

1. **Set the scene** (*The Incident at NovaTech*). Show the task box. Click
   **View the attacker's document**: the injection sits in an HTML comment, invisible when
   rendered for a human, fully visible to the model.
2. **Ask the room to predict** what the agent will do. Set **Pace → Slow** to narrate.
3. **Break it.** Click **Run insecure agent**. Narrate each step: it searches, reads the
   documents, then obeys the note: reads the vault, emails the value to
   `attacker-demo.example`, and disconnects `dc-01`. The leaked value is highlighted in red.
4. **Fix it** (*Defense Needs Layers*). Walk through the secured agent's differences, using
   the table above.
5. **Test it.** Click **Run secured agent**. The *same model is still fooled* (its thoughts
   show it trying), but three different layers stop it:
   - `get_secret` → **ALLOWLIST** (the tool is not available to this role)
   - external email → **EGRESS** (recipient outside `novatech.example`)
   - `isolate_host` → **APPROVAL**: a dialog appears. **Ask the room** whether to approve,
     then click **Deny**. (Approve once afterwards to show that a human gate is only as good
     as the human.)
   The legitimate summary is still produced, so security did not break the job.
6. **Scorecard** (*The Live Scorecard*). Click **Run scorecard**: both agents rerun and the
   table is filled from what actually happened. Scroll to the **Gateway Audit Log**.
7. **Audience round.** Untick *Attacker's document* to show a clean run, or edit the
   document with an attack someone in the room suggests, then run both again.

Tip: **Run both** shows the two agents racing side by side, which works well on a wide screen.

## Using a real LLM

The mock model is deterministic and *deliberately naive*: it always obeys injected
instructions, which models the worst case and makes the demo reproducible. To use a real
model, choose **Real LLM** in the UI (or `--provider openai` in the CLI) and point it at any
OpenAI-compatible endpoint with tool calling:

| Server | Endpoint |
|---|---|
| Ollama | `http://localhost:11434/v1` (e.g. model `llama3.1`, `qwen2.5`) |
| LM Studio | `http://localhost:1234/v1` |
| llama.cpp server | `http://localhost:8080/v1` |
| Hosted API | set `LAB_LLM_API_KEY`, plus base URL and model |

Real models may resist the injection, partially follow it, or follow it, and results can vary
between runs. That variability is the lesson: **the secured agent's guarantees come from the
gateway, not from the model.** Rehearse with your chosen model beforehand, and keep the mock
as the reliable default on stage.

## How it maps to GUARD

| Principle | Where in the code |
|---|---|
| **G**rant least privilege | `INVESTIGATOR_ALLOWLIST`, user scopes in [lab/gateway.py](lab/gateway.py) |
| **U**ntrusted stays untrusted | `<untrusted>` wrapping and no secret in `SECURE_SYSTEM` in [lab/agent.py](lab/agent.py) |
| **A**uthorize outside the model | `Gateway._decide`: allowlist → schema → scope → egress → DLP → approval |
| **R**ecord and review | `Gateway.audit`, with `redact()` |
| **D**efend by testing | [tests/test_lab.py](tests/test_lab.py) and [lab/scorecard.py](lab/scorecard.py) |

## Project layout summery 

```
agent-security-lab/
├── server.py            # live web demo (stdlib HTTP + server-sent events)
├── cli.py               # terminal fallback
├── web/index.html       # the demo UI
├── lab/
│   ├── agent.py         # the agent loop; insecure vs. secured configuration
│   ├── gateway.py       # policy gateway: allowlist, validation, authz, egress, DLP, approval, audit
│   ├── llm.py           # MockLLM (naive, deterministic) + OpenAI-compatible client
│   ├── tools.py         # simulated world and tools
│   ├── kb.py            # tiny keyword-search knowledge base
│   ├── scorecard.py     # measured, not pre-filled
│   └── data/            # synthetic incident, logs, policy, and the poisoned note
└── tests/test_lab.py
```

## Further reading

- OWASP Top 10 for LLM Applications (2025): <https://genai.owasp.org/llm-top-10/>
- Willison, *The lethal trifecta for AI agents*: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>
- Beurer-Kellner et al., *Design Patterns for Securing LLM Agents against Prompt Injections*: <https://arxiv.org/abs/2506.08837>
- AgentDojo benchmark: <https://arxiv.org/abs/2406.13352>
