import json
import os
import re
import urllib.error
import urllib.request

from pydantic import ValidationError

from models.schemas import GemmaReport
from .prompts import SYSTEM_PROMPT

DEFAULT_MODEL = os.getenv("GEMMA_MODEL", "gemma-4-31b-it")  # verify the exact Gemma 4 id for your key
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3")          # set to your local Gemma 4 tag
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")


class GemmaError(RuntimeError):
    pass


def default_model(provider):
    return OLLAMA_MODEL if provider == "ollama" else DEFAULT_MODEL


def _extract_json(text):
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("no JSON object in response")
    return json.loads(text[start:end + 1])


def generate_text(prompt, provider="google", api_key=None, model=None):
    model = model or default_model(provider)
    if provider == "ollama":  # local: nothing leaves this machine
        req = urllib.request.Request(
            f"{OLLAMA_HOST}/api/generate",
            data=json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.loads(r.read())["response"]
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as e:
            raise GemmaError(f"Cannot use local Ollama at {OLLAMA_HOST} (is it running and is model '{model}' pulled?): {e}")
    api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise GemmaError("No GEMINI_API_KEY / GOOGLE_API_KEY configured.")
    try:
        from google import genai
    except ImportError as e:
        raise GemmaError("google-genai is not installed.") from e
    try:
        return genai.Client(api_key=api_key).models.generate_content(model=model, contents=prompt).text or ""
    except Exception as e:  # network / auth / model errors
        raise GemmaError(str(e)) from e


def generate_json(prompt, schema, provider="google", api_key=None, model=None):
    last = None
    for _ in range(2):
        text = generate_text(prompt, provider, api_key, model)
        try:
            return schema.model_validate(_extract_json(text))
        except (ValidationError, ValueError) as e:
            last = e
            prompt += "\n\nYour previous reply was not valid JSON for the schema. Return ONLY the JSON object."
    raise GemmaError(f"Model returned invalid structured output: {last}")


def facts_node_names(facts):
    names = [i["name"] for i in facts["external_inputs"]]
    for a in facts["agents"]:
        names.append(a["name"])
        names += [t["name"] for t in a["tools"]]
    names += [c["node"] for c in facts["credential_references"]]
    names += [s["node"] for s in facts["secret_scan_hits"]]
    return names


def analyze(facts, provider="google", api_key=None, model=None):
    prompt = f"{SYSTEM_PROMPT}\nWORKFLOW FACTS:\n{json.dumps(facts, indent=2)}\n"
    report = generate_json(prompt, GemmaReport, provider, api_key, model)
    known = {n.lower() for n in facts_node_names(facts)} | {"workflow"}  # guardrail: no invented nodes
    report.findings = [f for f in report.findings if f.component.lower() in known]
    for f in report.findings:
        f.source = "gemma"
    return report
