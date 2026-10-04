# 🛡 AgentAudit: AI Workflow Security Analyzer

Upload an n8n workflow JSON → Python inventories agents, tools, inputs, credentials and data flows → Gemma 4 reasons about how they combine into security risks → you get an explainable, severity-ranked report with fixes.

## How it works
1. `analyzer/parser.py`: size-limited, safe `json.loads` (nothing is ever executed).
2. `analyzer/detector.py`: finds agents, tools, external inputs, outbound actions, approval gates, input→agent flows.
3. `analyzer/secrets.py`: flags credential-like values; only masked output is kept.
4. `analyzer/risk_rules.py`: deterministic findings for six categories (prompt injection, excessive permissions, secret exposure, unsafe tool calling, data exfiltration, untrusted input).
5. `analyzer/normalizer.py`: builds a compact fact sheet with **no secret values and no credential IDs**.
6. `ai/gemma.py`: sends facts to Gemma 4, validates JSON with Pydantic, and drops findings that reference nodes that don't exist.
7. `app.py`: Streamlit report with tables, charts, graph, before/after comparison, Markdown/JSON export.

**Role of Gemma 4:** Python finds facts; Gemma interprets combinations (input → agent → tool), adds findings the rules missed, prioritizes, and explains impact. Without a key the app still runs in rules-only mode.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add GEMINI_API_KEY, confirm GEMMA_MODEL id
streamlit run app.py
```
Demo: analyze the **vulnerable sample**, then the **safer sample**, and open the *Compare runs* tab.
Sample secrets are fake. Regenerate samples with `python samples/make_samples.py`.

## Safety & limitations
- Risk scores are estimates, not a security certification; "no findings" does not mean "safe".
- Heuristics are tuned for common n8n node types; unknown node types may be missed.
- Never executes uploaded workflows; never modifies or deploys them.
- Secret values are masked before model analysis.

MIT licensed.

## Unique features
- **Privacy-first AI step:** the app shows the exact fact sheet before anything is sent; prompt text is off by default; choose **Local Ollama** so nothing leaves your machine (`OLLAMA_MODEL` in `.env`, e.g. your Gemma 4 tag). "Clear my data" wipes the session.
- **Attack simulation:** written, fictional walkthroughs of how a hijacked agent could misuse its tools (rule-based, or Gemma-written). Nothing is executed.
- **Auto-fix with diff:** generates a hardened copy (approval gates, validation node, secret removal, narrower DB access, untrusted-input prompt wrapper) with a diff and before/after score. Download-only; never deploys.
- **OWASP LLM Top 10 tags** on every finding (LLM01, LLM02, LLM06).
