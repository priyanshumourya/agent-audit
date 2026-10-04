import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer.pipeline import run_analysis

S = Path(__file__).resolve().parents[1] / "samples"


def run(name):
    return run_analysis((S / name).read_bytes(), use_gemma=False)


def test_vulnerable_is_worse_than_safe():
    v, s = run("vulnerable_workflow.json"), run("safer_workflow.json")
    assert v["risk_score"] > s["risk_score"]
    assert any(f.severity == "CRITICAL" for f in v["findings"])
    assert not any(f.severity == "CRITICAL" for f in s["findings"])


def test_secret_masked():
    v = run("vulnerable_workflow.json")
    assert v["inventory"]["secrets"]
    assert "sk-FAKE" not in str(v["facts"])


def test_autofix_reduces_risk():
    import json
    from analyzer.fixer import apply_fixes
    from analyzer.parser import load_workflow
    from analyzer.pipeline import analyze_rules
    raw = (S / "vulnerable_workflow.json").read_bytes()
    fix = apply_fixes(load_workflow(raw))
    before = analyze_rules(raw)
    after = analyze_rules(json.dumps(fix["patched"]).encode())
    assert after["risk_score"] < before["risk_score"]
    assert not any(f.severity == "CRITICAL" for f in after["findings"])
    assert "sk-FAKE" not in json.dumps(fix["patched"])


def test_simulation_and_owasp():
    from ai.simulate import template_scenarios
    v = run("vulnerable_workflow.json")
    assert template_scenarios(v["inventory"])
    assert all(f.owasp for f in v["findings"])
