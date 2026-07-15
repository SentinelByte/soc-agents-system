"""
~~ Prompt Injection Guardrail

Heuristic, defense-in-depth scanner for adversarial content embedded in
alert fields (raw_log, command) that are about to be shown to an LLM.

This is a *secondary* control. The primary control is structural: untrusted
alert content is always passed to the model as clearly delimited data (see
reasoning_engine._llm_verdict), never concatenated into the system prompt or
treated as instructions. This scanner exists to:

1. Flag suspicious content for human review, and
2. Let the reasoning engine force a conservative verdict even if the
   heuristics below miss something but the model itself gets manipulated
   (defense in depth, not a single point of failure).

It will not catch every injection technique -- it is intentionally simple
and reviewable rather than exhaustive.
"""

import re

_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"disregard\s+(the\s+)?(system|previous)\s+prompt", "instruction_override"),
    (r"new\s+instructions\s*:", "instruction_override"),
    (r"you\s+are\s+now\s+", "role_override"),
    (r"^\s*system\s*:", "role_spoof"),
    (r"^\s*assistant\s*:", "role_spoof"),
    (r"</?\s*(system|instructions?|untrusted_data)\s*>", "tag_injection"),
    (r"reveal\s+(your\s+)?(system\s+)?prompt", "prompt_exfiltration"),
    (r"mark\s+(this\s+)?(alert\s+)?as\s+(benign|a\s+false\s+positive)", "verdict_manipulation"),
    (r"this\s+(activity|behavior)\s+is\s+authorized", "verdict_manipulation"),
    (r"set\s+confidence\s+to\s+\d", "verdict_manipulation"),
]

_FLAGS = re.IGNORECASE | re.MULTILINE
_COMPILED = [(re.compile(pattern, _FLAGS), label) for pattern, label in _INJECTION_PATTERNS]


def detect_prompt_injection(text: str) -> list[str]:
    """
    Returns the sorted set of indicator labels matched in `text`. Empty
    list means no known pattern matched -- not proof the content is safe.
    """
    if not text:
        return []
    return sorted({label for pattern, label in _COMPILED if pattern.search(text)})


def sanitize_for_llm(text: str) -> str:
    """
    Strips sequences that could let untrusted content break out of the
    <untrusted_data> delimiter used in the LLM prompt. Detection (above)
    decides what to flag for the verdict; this only prevents structural
    escape from the delimiter itself.
    """
    if not text:
        return text
    return text.replace("<untrusted_data>", "").replace("</untrusted_data>", "")
