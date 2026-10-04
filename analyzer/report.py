import json

KIND_COLOR = {"agent": "#7F77DD", "input": "#E24B4A", "outbound": "#EF9F27", "database": "#378ADD", "code": "#D4537E", "file": "#BA7517"}


def to_dot(inv):
    lines = ['digraph G { rankdir=LR; node [shape=box, style="rounded,filled", fillcolor="#F1EFE8", fontsize=10];']
    for n, k in inv["kinds"].items():
        col = next((KIND_COLOR[x] for x in ("input", "agent", "outbound", "code", "database", "file") if x in k), None)
        fill = f', fillcolor="{col}", fontcolor="white"' if col else ""
        lines.append(f'"{n}" [label="{n}"{fill}];')
    for e in inv["edges"]:
        style = " [style=dashed]" if e["type"].startswith("ai_") else ""
        lines.append(f'"{e["source"]}" -> "{e["target"]}"{style};')
    return "\n".join(lines) + "}"


def to_markdown(res):
    L = [f"# AgentAudit report: {res['inventory']['name']}", "",
         f"**Estimated risk score:** {res['risk_score']}/100 (rules: {res['rule_score']}, Gemma: {res['gemma_score']})", "",
         "_Estimated risk, not a security certification. No findings does not mean the workflow is safe._", ""]
    if res["gemma_summary"]:
        L += [res["gemma_summary"], ""]
    for f in res["findings"]:
        L += [f"## [{f.severity}] {f.title}", f"- Category: {f.category} ({f.owasp or 'n/a'})", f"- Component: {f.component}",
              f"- Confidence: {f.confidence} (source: {f.source})", "- Evidence:"] + [f"  - {e}" for e in f.evidence]
        L += [f"- Why it matters: {f.explanation}", f"- Potential impact: {f.impact}", f"- Fix: {f.recommendation}", ""]
    return "\n".join(L)


def to_json(res):
    return json.dumps({"risk_score": res["risk_score"], "summary": res["gemma_summary"],
                       "findings": [f.model_dump() for f in res["findings"]]}, indent=2)
