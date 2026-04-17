from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str = ""
    process: str = ""
    command_line: str = ""
    ip: str = ""
    parent_process: str = ""
    destination_port: int = 0
    user_agent: str = ""
    host: str = ""
    user: str = ""
    source: str = "csv"
    raw_event: dict = Field(default_factory=dict)


class AlertRecord(BaseModel):
    id: str
    timestamp: str = ""
    process: str = ""
    host: str = ""
    user: str = ""
    ip: str = ""
    severity: str
    confidence: float
    mitre: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    score: int
    status: str = "OPEN"
    priority: str = ""
    analyst_notes: str = ""
    anomaly_score: float | None = None
    source: str = "csv"
    assignee: str = ""
    false_positive_reason: str = ""
    fingerprint: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    entity_risk_score: int = 0
