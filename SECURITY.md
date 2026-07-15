# Security Policy

TriAgen is a portfolio project, not a production tool. If you're going to point
the optional LLM backend at anything real, read through
`triagen_core/guardrails/` and the trust-boundary logic in
`triagen_core/reasoning_engine.py` first. Don't assume it's hardened just
because "security" is in the description.

## Scope

The threat model here is narrow on purpose: the pipeline ingests untrusted,
possibly attacker-written text (raw logs, command lines), and it has to reason
about that text without letting the text steer its own conclusions. That's the
whole game. See the README's "Security design" section for how it's done.

## Reporting a vulnerability

Found a way around the guardrail, an enrichment heuristic that's trivial to
evade, or a bad dependency? Open an issue on this repo. It's a personal
project, so there's no bounty, just my thanks for the catch.
