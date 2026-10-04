import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from ai import gemma
from ai.simulate import ai_scenarios, template_scenarios
from analyzer.fixer import apply_fixes
from analyzer.parser import WorkflowError, load_workflow
from analyzer.pipeline import analyze_rules, enrich, preview_facts
from analyzer.report import to_dot, to_json, to_markdown

load_dotenv()
SAMPLES = Path(__file__).parent / "samples"
ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
ss = st.session_state
ss.setdefault("history", [])

st.set_page_config(page_title="AgentAudit", page_icon="🛡", layout="wide")
st.title("🛡 AgentAudit")
st.caption("AI Workflow Security Analyzer · Python inspection + Gemma 4 reasoning · estimated risk, not a certification")

with st.sidebar:
    st.header("Settings")
    framework = st.selectbox("Framework", ["n8n", "LangChain", "custom", "other"])
    purpose = st.text_area("What should this workflow do? (optional)")
    engine = st.radio("AI engine", ["Local Ollama (private)", "Google API (Gemma)"])
    provider = "ollama" if engine.startswith("Local") else "google"
    model = st.text_input("Model id", gemma.default_model(provider))
    api_key = st.text_input("API key (session only)", type="password") or None if provider == "google" else None
    include_prompts = st.checkbox("Also send prompt text (redacted)", value=False)
    st.info("Files are processed in memory and never stored. Secrets are masked; redaction is best-effort.")
    if st.button("🧹 Clear my data"):
        ss.clear()
        st.rerun()

src = st.radio("Workflow source", ["Upload file", "Vulnerable sample", "Safer sample"], horizontal=True)
raw, label = None, None
if src == "Upload file":
    up = st.file_uploader("Upload n8n workflow JSON", type=["json"])
    if up:
        raw, label = up.getvalue(), up.name
else:
    f = SAMPLES / ("vulnerable_workflow.json" if src.startswith("Vuln") else "safer_workflow.json")
    raw, label = f.read_bytes(), f.name


def log(name, res):
    ss["history"].append({"Workflow": name, "Risk": res["risk_score"], "Rules": res["rule_score"], "Gemma": res["gemma_score"],
                          "Findings": len(res["findings"])})


if st.button("Analyze Workflow", type="primary", disabled=raw is None):
    try:
        ss["res"], ss["raw"], ss["label"], ss["sim"] = analyze_rules(raw, purpose, framework), raw, label, None
        log(label, ss["res"])
    except WorkflowError as e:
        st.error(str(e))

res = ss.get("res")
if res:
    inv, c = res["inventory"], res["inventory"]["counts"]
    st.subheader("Workflow Overview")
    for col, (k, v) in zip(st.columns(5), [("Agents", c["agents"]), ("Tools", c["tools"]), ("APIs", c["apis"]),
                                           ("Credential refs", c["credential_refs"]), ("External inputs", c["external_inputs"])]):
        col.metric(k, v)

    with st.expander("🔒 AI analysis: review exactly what will be sent, then run", expanded=res["gemma_score"] is None):
        facts = preview_facts(res, include_prompts)
        st.json(facts, expanded=False)
        st.caption("Local Ollama keeps this on your machine." if provider == "ollama" else "This fact sheet is sent to Google's API.")
        if st.button("Run AI analysis on this data"):
            with st.spinner("Asking Gemma…"):
                enrich(res, provider, api_key, model, include_prompts)
            if not res["gemma_error"]:
                log(ss["label"] + " (+AI)", res)
        if res["gemma_error"]:
            st.warning(f"AI unavailable, showing deterministic findings only: {res['gemma_error']}")

    st.subheader(f"Overall Risk: {res['risk_score']} / 100")
    st.progress(res["risk_score"] / 100)
    if res["gemma_summary"]:
        st.write(res["gemma_summary"])
    if not res["findings"]:
        st.success("No findings detected. This does not prove the workflow is safe.")

    t1, t2, t3, t4, t5, t6 = st.tabs(["Findings", "Attack simulation", "Auto-fix", "Data", "Graph", "Compare runs"])
    with t1:
        for f in res["findings"]:
            with st.expander(f"{ICON[f.severity]} {f.severity} · {f.title}  [{f.source}]"):
                st.markdown(f"**Category:** {f.category} · **OWASP:** {f.owasp or 'n/a'}  \n**Component:** {f.component} · **Confidence:** {f.confidence}")
                st.markdown("**Evidence**\n" + "\n".join(f"- {e}" for e in f.evidence))
                st.markdown(f"**Why it matters:** {f.explanation}\n\n**Potential impact:** {f.impact}")
                st.success(f"**Recommended fix:** {f.recommendation}")
        d1, d2 = st.columns(2)
        d1.download_button("Download Markdown", to_markdown(res), "agentaudit_report.md")
        d2.download_button("Download JSON", to_json(res), "agentaudit_report.json")

    with t2:
        st.caption("Written walkthroughs only. Nothing is executed and payloads are fictional.")
        if st.button("Write attack stories with AI"):
            try:
                ss["sim"] = ai_scenarios(preview_facts(res, include_prompts), provider, api_key, model)
            except gemma.GemmaError as e:
                st.warning(f"AI unavailable, using template scenarios: {e}")
        for s in ss.get("sim") or template_scenarios(inv):
            with st.expander(f"⚔️ {s.title}", expanded=True):
                st.markdown("**Injected content (fictional):**")
                st.code(s.malicious_input, language=None)
                st.markdown("\n".join(f"{i}. {x}" for i, x in enumerate(s.steps, 1)))
                st.error(f"**Outcome:** {s.outcome}")
                st.success(f"**Stopped by:** {s.mitigated_by}")
        if not (ss.get("sim") or template_scenarios(inv)):
            st.info("No untrusted input reaches an agent, so no attack path was found.")

    with t3:
        st.caption("Builds a hardened COPY for you to review and import yourself. Nothing is modified or deployed.")
        if st.button("Generate hardened workflow"):
            fix = apply_fixes(load_workflow(ss["raw"]))
            new = analyze_rules(json.dumps(fix["patched"]).encode(), purpose, framework)
            ss["fix"], ss["fix_res"] = fix, new
            log(ss["label"] + " (hardened)", new)
        fix, new = ss.get("fix"), ss.get("fix_res")
        if fix:
            a, b = st.columns(2)
            a.metric("Risk before", res["rule_score"])
            b.metric("Risk after", new["risk_score"], delta=new["risk_score"] - res["rule_score"], delta_color="inverse")
            st.dataframe(pd.DataFrame(fix["changes"]), use_container_width=True)
            for m in fix["manual"]:
                st.warning("Manual step: " + m)
            with st.expander("Diff (original → hardened)"):
                st.code(fix["diff"], language="diff")
            st.download_button("Download hardened workflow", json.dumps(fix["patched"], indent=2), "hardened_workflow.json")
            st.caption("Review before importing: set real table/columns, rotate removed secrets, extend the validation node.")

    with t4:
        st.markdown("**Node count by type**")
        st.bar_chart(pd.Series(inv["type_counts"], name="nodes"))
        st.markdown("**Agent → tool relationships**")
        st.dataframe(pd.DataFrame([{"Agent": a["name"], "Tool": t["name"], "Type": t["type"].split(".")[-1], "Kinds": ", ".join(t["kinds"]),
                                    "Approval gate": t["approval_gate"]} for a in inv["agents"].values() for t in a["tools"]]), use_container_width=True)
        st.markdown("**External input → agent flows**")
        st.dataframe(pd.DataFrame([{"Input": f["input"], "Agent": f["agent"], "Path": " → ".join(f["path"]),
                                    "Validation": ", ".join(f["validation_nodes"]) or "none"} for f in inv["flows"]]), use_container_width=True)
        st.markdown("**Credential references (names only, no values)**")
        st.dataframe(pd.DataFrame(inv["credentials"]), use_container_width=True)
        cat = pd.Series([f.category for f in res["findings"]]).value_counts()
        if len(cat):
            st.markdown("**Risk by category**")
            st.bar_chart(cat)
    with t5:
        st.graphviz_chart(to_dot(inv))
        st.caption("Red: inputs · Purple: agents · Orange: outbound · Blue: database · Dashed: AI tool/model links")
    with t6:
        st.dataframe(pd.DataFrame(ss["history"]), use_container_width=True)
        st.caption("Analyze the vulnerable sample, generate the hardened copy, and compare the scores.")
