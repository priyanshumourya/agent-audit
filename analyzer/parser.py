"""Safe n8n workflow parsing. Uploaded files are untrusted: we only json.loads them."""
import json

MAX_BYTES = 2 * 1024 * 1024


class WorkflowError(ValueError):
    pass


def load_workflow(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise WorkflowError(f"File too large (limit {MAX_BYTES // 1024} KB).")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise WorkflowError(f"Invalid JSON: {e}")
    if isinstance(data, list) and data and isinstance(data[0], dict):
        data = data[0]
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list):
        raise WorkflowError("This does not look like an n8n workflow (no 'nodes' list).")
    return data


def parse_workflow(data):
    nodes = {}
    for n in data["nodes"]:
        if not isinstance(n, dict) or "name" not in n:
            continue
        nodes[n["name"]] = {
            "name": n["name"],
            "type": str(n.get("type", "unknown")),
            "parameters": n.get("parameters") or {},
            "credentials": n.get("credentials") or {},
            "disabled": bool(n.get("disabled")),
        }
    edges = []
    for src, outs in (data.get("connections") or {}).items():
        if not isinstance(outs, dict):
            continue
        for ctype, branches in outs.items():
            for branch in branches or []:
                for t in branch or []:
                    if isinstance(t, dict) and t.get("node") in nodes and src in nodes:
                        edges.append({"source": src, "target": t["node"], "type": ctype})
    return {"name": data.get("name", "workflow"), "nodes": nodes, "edges": edges}
