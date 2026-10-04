"""Deterministic discovery of agents, tools, inputs, outbound actions and data flows."""
import re
from collections import deque

from .secrets import scan_workflow

AGENT_TYPES = {"agent", "openaiassistant", "chainllm", "chainretrievalqa", "conversationalagent"}
INPUT_HINTS = ("webhook", "formtrigger", "chattrigger", "emailreadimap", "telegramtrigger",
               "slacktrigger", "gmailtrigger", "whatsapptrigger", "emailtrigger")
OUTBOUND_HINTS = ("httprequest", "emailsend", "gmail", "slack", "telegram", "discord", "twilio",
                  "sendgrid", "mailgun", "outlook", "whatsapp", "teams", "sms")
DB_HINTS = ("postgres", "mysql", "mongodb", "supabase", "sqlite", "mssql", "redis", "airtable",
            "googlesheets", "snowflake", "bigquery", "mariadb", "qdrant", "pinecone")
CODE_HINTS = ("code", "executecommand", "ssh", "python", "function")
FILE_HINTS = ("readwritefile", "readbinaryfile", "writebinaryfile", "ftp", "s3", "googledrive")
VALIDATOR_TYPES = ("if", "filter", "switch")
UNTRUSTED_EXPR = re.compile(r"\$json\.(body|query|headers|chatInput|message|text|subject)|\$\(['\"]", re.I)


def short_type(t):
    return t.split(".")[-1].lower()


def kinds_of(node):
    t = short_type(node["type"])
    k = set()
    if t == "respondtowebhook":
        return k
    trig = "trigger" in t
    if t in AGENT_TYPES:
        k.add("agent")
    if any(h in t for h in INPUT_HINTS):
        k.add("input")
    if not trig:
        if any(h in t for h in OUTBOUND_HINTS):
            k.add("outbound")
        if any(h in t for h in DB_HINTS):
            k.add("database")
        if any(h in t for h in CODE_HINTS):
            k.add("code")
        if any(h in t for h in FILE_HINTS):
            k.add("file")
    return k


def approval_gated(node):
    op = str(node["parameters"].get("operation", "")).lower()
    return "sendandwait" in op or short_type(node["type"]) == "wait"


def _adj(wf, types):
    adj = {}
    for e in wf["edges"]:
        if e["type"] in types:
            adj.setdefault(e["source"], []).append(e["target"])
    return adj


def _bfs(adj, start):
    parent, q = {start: None}, deque([start])
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, []):
            if nxt not in parent:
                parent[nxt] = cur
                q.append(nxt)
    return parent


def _path(parent, end):
    p = []
    while end is not None:
        p.append(end)
        end = parent[end]
    return p[::-1]


def prompt_text(node):
    p = node["parameters"]
    parts = [p.get("text"), (p.get("options") or {}).get("systemMessage")]
    return "\n".join(x for x in parts if isinstance(x, str))


def inspect(wf):
    nodes = wf["nodes"]
    kinds = {n: kinds_of(v) for n, v in nodes.items() if not v["disabled"]}
    agents = [n for n, k in kinds.items() if "agent" in k]
    inputs = [n for n, k in kinds.items() if "input" in k]
    main = _adj(wf, {"main"})

    tools_of = {a: [e["source"] for e in wf["edges"] if e["type"] == "ai_tool" and e["target"] == a] for a in agents}
    model_of = {a: [e["source"] for e in wf["edges"] if e["type"] == "ai_languageModel" and e["target"] == a] for a in agents}

    flows = []
    for i in inputs:
        parent = _bfs(main, i)
        for a in agents:
            if a in parent:
                path = _path(parent, a)
                flows.append({
                    "input": i, "agent": a, "path": path,
                    "validation_nodes": [n for n in path[1:-1] if short_type(nodes[n]["type"]) in VALIDATOR_TYPES],
                })

    agent_info = {}
    for a in agents:
        parent = _bfs(main, a)
        downstream = [n for n in parent if n != a]
        tool_nodes = list(dict.fromkeys(tools_of[a] + [d for d in downstream if kinds.get(d, set()) & {"outbound", "database", "code", "file"}]))
        tools = []
        for t in tool_nodes:
            nd = nodes[t]
            tools.append({
                "name": t, "type": nd["type"], "kinds": sorted(kinds.get(t, set())),
                "attached_as_tool": t in tools_of[a],
                "approval_gate": approval_gated(nd),
                "operation": nd["parameters"].get("operation"),
            })
        text = prompt_text(nodes[a])
        agent_info[a] = {
            "name": a, "type": nodes[a]["type"], "models": model_of[a], "tools": tools,
            "prompt": text, "prompt_uses_untrusted_expr": bool(UNTRUSTED_EXPR.search(text)),
        }

    creds = [{"node": n["name"], "credential_type": c} for n in nodes.values() for c in n["credentials"]]
    type_counts = {}
    for n in nodes.values():
        t = n["type"].split(".")[-1]
        type_counts[t] = type_counts.get(t, 0) + 1

    all_tools = {t["name"] for a in agent_info.values() for t in a["tools"]}
    return {
        "name": wf["name"], "nodes": nodes, "edges": wf["edges"], "kinds": {k: sorted(v) for k, v in kinds.items()},
        "agents": agent_info, "inputs": [{"name": i, "type": nodes[i]["type"]} for i in inputs],
        "flows": flows, "credentials": creds, "secrets": scan_workflow(wf), "type_counts": type_counts,
        "counts": {"nodes": len(nodes), "agents": len(agents), "tools": len(all_tools),
                   "apis": sum(1 for n, k in kinds.items() if "outbound" in k),
                   "credential_refs": len(creds), "external_inputs": len(inputs)},
    }
