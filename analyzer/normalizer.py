"""Build the compact, masked fact sheet sent to the model. Privacy-first: no secret values,
no credential ids, and (by default) no free-text prompts."""
from .secrets import redact_text


def build_facts(inv, purpose="", framework="n8n", rule_findings=None, include_prompts=False):
    return {
        "workflow_name": inv["name"],
        "framework": framework,
        "declared_purpose": redact_text(purpose)[:500] or "not provided",
        "counts": inv["counts"],
        "external_inputs": inv["inputs"],
        "agents": [{
            "name": a["name"], "type": a["type"], "language_models": a["models"],
            "prompt_excerpt": redact_text(a["prompt"])[:600] if include_prompts else "omitted (privacy mode)",
            "prompt_references_untrusted_input": a["prompt_uses_untrusted_expr"],
            "tools": [{k: t[k] for k in ("name", "type", "kinds", "approval_gate", "operation")} for t in a["tools"]],
        } for a in inv["agents"].values()],
        "data_flows": [{"input": f["input"], "agent": f["agent"], "path": f["path"],
                        "validation_nodes": f["validation_nodes"]} for f in inv["flows"]],
        "credential_references": [{"node": c["node"], "credential_type": c["credential_type"]} for c in inv["credentials"]],
        "secret_scan_hits": [{"node": s["node"], "path": s["path"], "reason": s["reason"]} for s in inv["secrets"]],
        "deterministic_findings": [{"severity": f.severity, "category": f.category, "component": f.component, "title": f.title}
                                   for f in (rule_findings or [])],
    }
