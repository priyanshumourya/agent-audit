# AgentAudit: AI Workflow Security Analyzer

Upload an n8n workflow JSON to inventory agents, tools, inputs, credentials, and data flows. Deterministic Python rules identify potential risks; optional Gemini analysis explains how the components combine. Reports include recommended fixes.

## How it works

1. `analyzer/parser.py` applies a size limit and parses JSON only; workflows are never executed.
2. `analyzer/detector.py` identifies agents, tools, external inputs, outbound actions, approval gates, and input-to-agent flows.
3. `analyzer/secrets.py` detects credential-like values; secret values are masked in the AI fact sheet.
4. `analyzer/risk_rules.py` generates deterministic findings across six risk categories.
5. `analyzer/normalizer.py` builds a compact fact sheet without secret values or credential IDs.
6. `ai/gemma.py` optionally sends the reviewed facts to Google Gemini, validates the response with Pydantic, and discards findings that reference unknown nodes.
7. `app.py` exposes the FastAPI ASGI application for Vercel and its JSON API. `index.html` provides the browser interface.

Without a Gemini API key, the application works in deterministic rules-only mode.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app:app --reload
```

Open `http://localhost:8000`. You can also set `GEMINI_API_KEY` in the environment to enable optional Gemini analysis. Keys entered in the interface are sent only with the AI request and are not saved by the app.

Analyze the vulnerable sample, then the safer sample, and compare their risk scores. Sample secrets are fake; regenerate them with `python samples/make_samples.py`.

## Deploy to Vercel

Import this GitHub repository into Vercel with the project root set to the repository root. Vercel detects the top-level FastAPI ASGI application named `app` in `app.py`; `index.html` is served at `/`. `requirements.txt` lists the Python dependencies. No Dockerfile is required.

To enable Gemini in production, configure `GEMINI_API_KEY` as a Vercel environment variable. Rules-only analysis requires no environment variables.

## Safety and limitations

- Risk scores are estimates, not a security certification; "no findings" does not mean a workflow is safe.
- Heuristics are tuned for common n8n node types; unknown node types may be missed.
- Uploaded workflows are processed in memory and are never executed, modified, or deployed.
- Secret values are masked before model analysis. Redaction is best-effort; inspect the fact sheet before enabling AI analysis.
- AI analysis is optional and sends the displayed fact sheet to Google's API.
- The browser keeps comparison history for the current page only; the server does not persist uploaded workflows or reports.

## Features

- Privacy-first, rules-only workflow analysis and a reviewable fact sheet for optional Gemini analysis.
- Fictional prompt-injection attack walkthroughs, generated from deterministic templates or Gemini.
- Downloadable hardened workflow copies with changes, manual follow-ups, and a diff. Nothing is automatically deployed.
- Markdown and JSON report downloads, workflow inventory, agent-tool relationships, external-input flows, and OWASP LLM Top 10 tags on findings.

MIT licensed.





chech it here for updated version

-> agent-audit-tw66.vercel.app
