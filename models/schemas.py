from typing import List, Literal
from pydantic import BaseModel, Field, field_validator

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Finding(BaseModel):
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: str
    title: str
    component: str
    evidence: List[str] = Field(default_factory=list)
    explanation: str = ""
    impact: str = ""
    recommendation: str = ""
    confidence: Literal["high", "medium", "low"] = "medium"
    source: str = "rules"  # "rules" or "gemma"
    owasp: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v):
        return str(v).strip().upper()

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        return str(v).strip().lower()

    @field_validator("evidence", mode="before")
    @classmethod
    def _ev(cls, v):
        if isinstance(v, str):
            return [v]
        return v or []


class GemmaReport(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    summary: str = ""
    findings: List[Finding] = Field(default_factory=list)


class Scenario(BaseModel):
    title: str
    malicious_input: str
    steps: List[str] = Field(default_factory=list)
    outcome: str = ""
    mitigated_by: str = ""


class SimReport(BaseModel):
    scenarios: List[Scenario] = Field(default_factory=list)
