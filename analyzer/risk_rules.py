"""Deterministic security checks. Gemma complements these; it does not replace them."""
from models.schemas import Finding

WEIGHTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3, "INFO": 0}


def score(findings):
    return min(100, sum(WEIGHTS[f.severity] for f in findings))


def run_rules(inv):
    out = []
    for name, a in inv["agents"].items():
        tools = a["tools"]
        flows = [f for f in inv["flows"] if f["agent"] == name]
        ungated_out = [t for t in tools if "outbound" in t["kinds"] and not t["approval_gate"]]
        gated_out = [t for t in tools if "outbound" in t["kinds"] and t["approval_gate"]]
        code = [t for t in tools if "code" in t["kinds"]]
        db = [t for t in tools if "database" in t["kinds"]]
        files = [t for t in tools if "file" in t["kinds"]]
        names = lambda ts: ", ".join(t["name"] for t in ts)
        dangerous = bool(ungated_out or code)

        if flows:
            validated = all(f["validation_nodes"] for f in flows)
            ev = [" → ".join(f["path"]) for f in flows]
            if a["prompt_uses_untrusted_expr"]:
                ev.append("Agent prompt interpolates input fields via an expression")
            if dangerous:
                sev = "CRITICAL"
            elif db or gated_out or files:
                sev = "MEDIUM" if validated else "HIGH"
            else:
                sev = "LOW" if validated else "MEDIUM"
            out.append(Finding(
                severity=sev, category="Prompt Injection Exposure",
                title=f"Untrusted input can steer '{name}'", component=name, evidence=ev,
                explanation="External content reaches the agent's prompt, so instructions hidden in that content may be followed as if they were yours.",
                impact="Manipulated tool calls: data lookups, outbound messages or code execution the workflow author never intended."
                       if dangerous else "Manipulated answers or misuse of the agent's limited tools.",
                recommendation="Wrap input in a clearly delimited 'untrusted data' block, validate/length-limit it before the agent, and reduce the tools the agent can reach.",
                confidence="high"))
            if not validated:
                out.append(Finding(
                    severity="MEDIUM", category="Untrusted Input to Agent",
                    title=f"No validation step before '{name}'", component=name,
                    evidence=[" → ".join(f["path"]) for f in flows if not f["validation_nodes"]],
                    explanation="No IF/Filter/Switch node sits between the external input and the agent, so there is no obvious trust boundary.",
                    impact="Unexpected or hostile payloads reach the model unchecked.",
                    recommendation="Add an IF/Filter node that checks schema, length and allowed values before the agent.",
                    confidence="medium"))

        if (ungated_out and (db or code or files)) or len(tools) >= 5:
            out.append(Finding(
                severity="HIGH" if ungated_out else "MEDIUM", category="Excessive Tool Permissions",
                title=f"'{name}' holds a broad tool set", component=name,
                evidence=[f"Tools: {names(tools)}"],
                explanation="Combining data access, code/file access and outbound channels in one agent widens what a single bad instruction can do.",
                impact="Larger blast radius if the agent is manipulated.",
                recommendation="Give the agent only what its task needs; split read-only and outbound capabilities into separate, approval-gated steps.",
                confidence="medium"))
        for t in db:
            if str(t.get("operation", "")).lower() == "executequery":
                out.append(Finding(
                    severity="HIGH" if flows else "MEDIUM", category="Excessive Tool Permissions",
                    title=f"Free-form SQL available via '{t['name']}'", component=t["name"],
                    evidence=[f"operation = executeQuery on {t['type']}"],
                    explanation="The agent can compose arbitrary queries rather than a fixed, parameterised one.",
                    impact="Reads (or writes) beyond the intended tables and columns.",
                    recommendation="Use a fixed 'select' operation with named columns and a read-only database role.",
                    confidence="high"))

        if db and (ungated_out or gated_out):
            ch = ungated_out or gated_out
            out.append(Finding(
                severity=("CRITICAL" if flows else "HIGH") if ungated_out else "MEDIUM",
                category="Potential Data Exfiltration",
                title=f"'{name}' can read data and send it outside", component=name,
                evidence=[f"Data tools: {names(db)}", f"Outbound tools: {names(ch)}",
                          "Outbound tools are approval-gated" if not ungated_out else "No approval gate on outbound tools"],
                explanation="Data access and an external channel are available to the same agent.",
                impact="Sensitive records could be mailed or posted to an attacker-chosen destination.",
                recommendation="Require human approval on outbound actions, restrict recipients/hosts to an allow-list, and limit queried fields.",
                confidence="high" if ungated_out else "medium"))

        risky = ungated_out + code
        if risky:
            out.append(Finding(
                severity="HIGH" if flows else "MEDIUM", category="Unsafe Tool Calling",
                title=f"Powerful actions run without approval ({names(risky)})", component=name,
                evidence=[f"{t['name']} ({t['type'].split('.')[-1]}) has no sendAndWait/Wait gate" for t in risky],
                explanation="These tools act immediately when the model calls them; nothing validates arguments or asks a human.",
                impact="Unintended emails, HTTP calls or code execution triggered by model error or manipulation.",
                recommendation="Switch to a 'send and wait for approval' operation, or insert a Wait/approval step and validate arguments.",
                confidence="high"))

    for h in inv["secrets"]:
        out.append(Finding(
            severity="HIGH", category="Potential Secret Exposure",
            title=f"Credential-like value in '{h['node']}'", component=h["node"],
            evidence=[f"{h['path']}: {h['reason']} (value masked: {h['masked']})"],
            explanation="A literal secret in workflow JSON is exposed to anyone who can read or export the workflow.",
            impact="Account takeover or abuse of the connected service.",
            recommendation="Rotate the value and move it into an n8n credential.",
            confidence="medium"))
    return out


def owasp_for(category):
    c = category.lower()
    if "injection" in c or "untrusted" in c:
        return "LLM01 Prompt Injection"
    if "exfil" in c or "secret" in c or "disclos" in c:
        return "LLM02 Sensitive Information Disclosure"
    if "permission" in c or "tool" in c or "agency" in c:
        return "LLM06 Excessive Agency"
    return ""


def tag_owasp(findings):
    for f in findings:
        f.owasp = owasp_for(f.category)
    return findings
