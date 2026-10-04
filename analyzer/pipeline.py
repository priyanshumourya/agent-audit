from ai import gemma
from models.schemas import SEVERITIES
from .detector import inspect
from .normalizer import build_facts
from .parser import load_workflow, parse_workflow
from .risk_rules import run_rules, score, tag_owasp


def _merge(res, extra=()):
    res["findings"] = sorted(tag_owasp(list(res["rule_findings"]) + list(extra)), key=lambda f: SEVERITIES.index(f.severity))


def preview_facts(res, include_prompts=False):
    """Exactly what would be sent to the model."""
    return build_facts(res["inventory"], res["purpose"], res["framework"], res["rule_findings"], include_prompts)


def analyze_rules(raw, purpose="", framework="n8n"):
    inv = inspect(parse_workflow(load_workflow(raw)))
    rules = run_rules(inv)
    res = {"inventory": inv, "purpose": purpose, "framework": framework, "rule_findings": rules,
           "rule_score": score(rules), "gemma_score": None, "gemma_summary": None, "gemma_error": None}
    res["facts"] = preview_facts(res)
    _merge(res)
    res["risk_score"] = res["rule_score"]
    return res


def enrich(res, provider="google", api_key=None, model=None, include_prompts=False):
    res["facts"] = preview_facts(res, include_prompts)
    try:
        g = gemma.analyze(res["facts"], provider, api_key, model)
    except gemma.GemmaError as e:
        res["gemma_error"] = str(e)
        return res
    res["gemma_error"], res["gemma_score"], res["gemma_summary"] = None, g.risk_score, g.summary
    _merge(res, g.findings)
    res["risk_score"] = max(res["rule_score"], g.risk_score)
    return res


def run_analysis(raw, purpose="", framework="n8n", use_gemma=True, api_key=None, model=None,
                 provider="google", include_prompts=False):
    res = analyze_rules(raw, purpose, framework)
    return enrich(res, provider, api_key, model, include_prompts) if use_gemma else res
