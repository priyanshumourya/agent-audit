"""Secret scanning + redaction. Values are never returned in clear text."""
import re

KEY_RE = re.compile(r"(api[_-]?key|secret|token|passw(or)?d|authorization|bearer|private[_-]?key|client[_-]?secret)", re.I)
VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
]


def mask(value):
    s = str(value)
    return f"{s[:2]}***[{len(s)} chars]"


def redact_text(text):
    if not isinstance(text, str):
        return text
    for p in VALUE_PATTERNS:
        text = p.sub("[REDACTED]", text)
    return text


def _is_candidate(v):
    return isinstance(v, str) and len(v) >= 8 and not v.startswith("=") and "{{" not in v and not v.startswith("<")


def scan_node(node):
    hits = []

    def add(path, reason, value):
        hits.append({"node": node["name"], "path": path, "reason": reason, "masked": mask(value)})

    def walk(obj, path):
        if isinstance(obj, dict):
            if isinstance(obj.get("name"), str) and "value" in obj and KEY_RE.search(obj["name"]) and _is_candidate(obj["value"]):
                add(f"{path}.value", f"secret-like header/parameter '{obj['name']}'", obj["value"])
            for k, v in obj.items():
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")
        elif isinstance(obj, str):
            if any(p.search(obj) for p in VALUE_PATTERNS):
                add(path, "value matches a known secret/token format", obj)
            else:
                leaf = re.split(r"[.\[]", path)[-1].rstrip("]")
                if KEY_RE.search(leaf) and _is_candidate(obj):
                    add(path, f"secret-like key '{leaf}' holds a literal value", obj)

    walk(node["parameters"], "parameters")
    seen, out = set(), []
    for h in hits:
        key = (h["node"], h["path"].replace(".value", ""))
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def scan_workflow(wf):
    hits = []
    for n in wf["nodes"].values():
        hits.extend(scan_node(n))
    return hits
