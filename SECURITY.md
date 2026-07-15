# Security Policy

TriAgen is a portfolio / research project demonstrating AI-security
engineering patterns for SOC alert triage. It is **not hardened for
production use as-is** — in particular, review `triagen_core/guardrails/`
and the trust-boundary design in `triagen_core/reasoning_engine.py` yourself
before pointing the optional LLM backend at any real environment.

## Scope

This project's threat model is: an alert pipeline that ingests untrusted,
potentially attacker-controlled text (raw logs, command lines) and must
reason over it without that content being able to influence its own
control flow or verdict. See the README's "Security Design" section for
details.

## Reporting a vulnerability

If you find a security issue in this repository — a prompt-injection
bypass, an enrichment heuristic that's trivially evadable, a dependency
CVE, or anything else — please open a GitHub issue on this repository.
This is a personal project; there is no bug bounty.
