"""Tiny keyword-search knowledge base over the synthetic documents in data/."""

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
POISON_ID = "threat_intel_note"
_TOKEN = re.compile(r"[a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9]")
_STOP = {"the", "and", "a", "an", "of", "on", "to", "for", "in", "is", "it", "with", "this", "that", "any"}


def default_poison_text() -> str:
    return (DATA_DIR / f"{POISON_ID}.md").read_text()


def _tokens(text: str) -> set:
    return {t for t in _TOKEN.findall(text.lower()) if t not in _STOP}


def _title(doc_id: str, text: str) -> str:
    first = text.strip().splitlines()[0].lstrip("# ").strip()
    return first if not first.startswith("timestamp,") else "Authentication log export"


class KnowledgeBase:
    def __init__(self, include_poison: bool = True, poison_text: str | None = None):
        self.docs = {}
        for path in sorted(DATA_DIR.iterdir()):
            if path.suffix in {".txt", ".md", ".csv"}:
                self.docs[path.stem] = path.read_text()
        if poison_text is not None:
            self.docs[POISON_ID] = poison_text
        if not include_poison:
            self.docs.pop(POISON_ID, None)

    def search(self, query: str, k: int = 3) -> str:
        terms = _tokens(query)
        scored = sorted(
            ((len(terms & _tokens(text)), doc_id) for doc_id, text in self.docs.items()),
            key=lambda pair: (-pair[0], pair[1]),
        )
        hits = [{"doc_id": d, "title": _title(d, self.docs[d])} for score, d in scored[:k] if score > 0]
        return json.dumps(hits, indent=1)

    def read(self, doc_id: str) -> str:
        return self.docs.get(doc_id, f"No document with id '{doc_id}'.")
