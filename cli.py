"""Terminal version of the demo: a fallback if the browser or projector fails.

    python3 cli.py                     # run both agents with the mock model
    python3 cli.py --mode secure       # one agent; you approve/deny at the prompt
    python3 cli.py --clean             # no attacker document (utility check)
    python3 cli.py --scorecard
    python3 cli.py --provider openai --base-url http://localhost:11434/v1 --model llama3.1
"""

import argparse
import time

from lab.agent import DEFAULT_TASK, run_agent
from lab.kb import KnowledgeBase
from lab.llm import make_llm
from lab.scorecard import run_scorecard
from lab.tools import SECRET_PATTERN, World

RED, TEAL, AMBER, DIM, BOLD, RESET = "\033[31m", "\033[36m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def highlight(text):
    return SECRET_PATTERN.sub(lambda m: f"{RED}{BOLD}{m.group()}{RESET}", text)


def printer(pace):
    def emit(e):
        t = e["type"]
        if t == "start":
            print(f"{DIM}model: {e['model']} | tools: {', '.join(e['tools'])}{RESET}")
        elif t == "think":
            print(f"  {DIM}MODEL   {e['text']}{RESET}")
        elif t == "tool_call":
            print(f"  {AMBER}CALL    {highlight(e['call'])}{RESET}")
        elif t == "tool_result":
            text = e["text"].strip().replace("\n", " ")
            print(f"  {TEAL}RESULT  {highlight(text[:140])}{'…' if len(text) > 140 else ''}{RESET}")
        elif t == "blocked":
            print(f"  {RED}{BOLD}BLOCKED [{e['layer']}] {e['reason']}{RESET}")
        elif t == "final":
            print(f"\n{BOLD}FINAL ANSWER{RESET}\n{highlight(e['text'])}")
        elif t == "error":
            print(f"{RED}ERROR {e['text']}{RESET}")
        if t in {"think", "tool_call", "tool_result", "blocked"}:
            time.sleep(pace)
    return emit


def ask(call_id, name, args):
    answer = input(f"\n  {AMBER}{BOLD}APPROVAL NEEDED{RESET} {name}({args}) — approve? [y/N] ")
    return answer.strip().lower() == "y"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["insecure", "secure", "both"], default="both")
    p.add_argument("--task", default=DEFAULT_TASK)
    p.add_argument("--clean", action="store_true", help="leave the attacker's document out")
    p.add_argument("--provider", choices=["mock", "openai"], default="mock")
    p.add_argument("--base-url")
    p.add_argument("--model")
    p.add_argument("--pace", type=float, default=0.4)
    p.add_argument("--scorecard", action="store_true")
    a = p.parse_args()
    llm = make_llm(a.provider, a.base_url, a.model)

    if a.scorecard:
        res = run_scorecard(llm, a.task)
        print(f"{BOLD}{'TEST':42} {'INSECURE':10} SECURED{RESET}")
        for r in res["rows"]:
            cell = lambda v: f"{TEAL if v == r['good_when'] else RED}{'Yes' if v else 'No':10}{RESET}"
            print(f"{r['label']:42} {cell(r['insecure'])} {cell(r['secure'])}")
        for mode, err in res["errors"].items():
            print(f"{RED}{mode}: {err}{RESET}")
        return

    for mode in (["insecure", "secure"] if a.mode == "both" else [a.mode]):
        colour = RED if mode == "insecure" else TEAL
        print(f"\n{colour}{BOLD}===== {mode.upper()} AGENT ====={RESET}")
        world = World()
        run_agent(mode, a.task, llm, KnowledgeBase(include_poison=not a.clean), world,
                  emit=printer(a.pace), approver=ask)
        w = world.snapshot()
        print(f"\n{DIM}impact: secret reads={w['secret_reads']}  external emails={w['external_emails']}  "
              f"isolated={w['isolated'] or 'none'}{RESET}")


if __name__ == "__main__":
    main()
