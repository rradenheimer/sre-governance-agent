"""SRE Governance Agent — deterministic policy engine package.

The engine is intentionally AI-free: it loads a control catalog and an industry
profile, scans a repository into a signals dict, and deterministically evaluates
each control. AI agents (Copilot / Claude) orchestrate this engine and interpret
its output, but never decide pass/fail themselves. This keeps governance
reproducible, auditable, and safe.
"""

__version__ = "1.0.0"
