import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from ai import gemma
from ai.simulate import ai_scenarios, template_scenarios
from analyzer.fixer import apply_fixes
from analyzer.parser import WorkflowError, load_workflow
from analyzer.pipeline import analyze_rules, enrich, preview_facts
from analyzer.report import to_json, to_markdown

ROOT = Path(__file__).parent
SAMPLES = {
    "vulnerable": ROOT / "samples" / "vulnerable_workflow.json",
    "safer": ROOT / "samples" / "safer_workflow.json",
}

app = FastAPI(title="AgentAudit", version="1.0.0")


class WorkflowRequest(BaseModel):
    workflow: Any
    purpose: str = Field(default="", max_length=5000)
    framework: str = Field(default="n8n", max_length=100)


class AIRequest(WorkflowRequest):
    api_key: str | None = Field(default=None, max_length=500)
    model: str | None = Field(default=None, max_length=200)
    include_prompts: bool = False


class PreviewRequest(WorkflowRequest):
    include_prompts: bool = False


class SimulationRequest(AIRequest):
    use_ai: bool = False


def _load_request_workflow(workflow: Any) -> tuple[bytes, dict]:
    try:
        raw = json.dumps(workflow, ensure_ascii=False).encode("utf-8")
        data = load_workflow(raw)
    except (TypeError, ValueError, WorkflowError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return raw, data


def _result_payload(result: dict) -> dict:
    return {
        "inventory": result["inventory"],
        "purpose": result["purpose"],
        "framework": result["framework"],
        "rule_score": result["rule_score"],
        "gemma_score": result["gemma_score"],
        "gemma_summary": result["gemma_summary"],
        "gemma_error": result["gemma_error"],
        "risk_score": result["risk_score"],
        "facts": result["facts"],
        "findings": [finding.model_dump() for finding in result["findings"]],
    }


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(ROOT / "index.html")


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/samples/{sample_name}")
async def sample(sample_name: str):
    path = SAMPLES.get(sample_name)
    if path is None:
        raise HTTPException(status_code=404, detail="Sample not found.")
    return json.loads(path.read_text(encoding="utf-8"))


@app.post("/api/analyze")
async def analyze(request: WorkflowRequest):
    raw, _ = _load_request_workflow(request.workflow)
    try:
        result = analyze_rules(raw, request.purpose, request.framework)
    except WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _result_payload(result)


@app.post("/api/preview")
async def preview(request: PreviewRequest):
    raw, _ = _load_request_workflow(request.workflow)
    try:
        result = analyze_rules(raw, request.purpose, request.framework)
    except WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"facts": preview_facts(result, request.include_prompts)}


@app.post("/api/enrich")
async def analyze_with_ai(request: AIRequest):
    raw, _ = _load_request_workflow(request.workflow)
    try:
        result = analyze_rules(raw, request.purpose, request.framework)
        enrich(
            result,
            provider="google",
            api_key=request.api_key,
            model=request.model,
            include_prompts=request.include_prompts,
        )
    except WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _result_payload(result)


@app.post("/api/simulate")
async def simulate(request: SimulationRequest):
    raw, _ = _load_request_workflow(request.workflow)
    try:
        result = analyze_rules(raw, request.purpose, request.framework)
    except WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    facts = preview_facts(result, request.include_prompts)
    if request.use_ai:
        try:
            scenarios = ai_scenarios(
                facts, provider="google", api_key=request.api_key, model=request.model
            )
        except gemma.GemmaError as exc:
            raise HTTPException(status_code=502, detail=f"AI unavailable: {exc}") from exc
    else:
        scenarios = template_scenarios(result["inventory"])
    return {"scenarios": [scenario.model_dump() for scenario in scenarios]}


@app.post("/api/fix")
async def harden_workflow(request: WorkflowRequest):
    raw, data = _load_request_workflow(request.workflow)
    try:
        fix = apply_fixes(data)
        hardened_raw = json.dumps(fix["patched"]).encode("utf-8")
        result = analyze_rules(hardened_raw, request.purpose, request.framework)
    except WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "patched": fix["patched"],
        "changes": fix["changes"],
        "manual": fix["manual"],
        "diff": fix["diff"],
        "result": _result_payload(result),
    }


@app.post("/api/report/{report_format}")
async def download_report(report_format: str, request: WorkflowRequest):
    raw, _ = _load_request_workflow(request.workflow)
    try:
        result = analyze_rules(raw, request.purpose, request.framework)
    except WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if report_format == "json":
        content, media_type, filename = to_json(result), "application/json", "agentaudit_report.json"
    elif report_format == "markdown":
        content, media_type, filename = to_markdown(result), "text/markdown; charset=utf-8", "agentaudit_report.md"
    else:
        raise HTTPException(status_code=404, detail="Report format not found.")
    return Response(
        content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
