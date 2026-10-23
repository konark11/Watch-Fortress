from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str
    email: str | None = None
    password: str
    role: str = "security_analyst"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class AdminResetPasswordRequest(BaseModel):
    new_password: str


class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    threat_actor: str | None = None
    campaign: str | None = None
    source: str | None = None
    related_cves: list[str] = []
    confidence: str = "medium"
    notes: str | None = None


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AssetUpdate(BaseModel):
    criticality: str | None = None
    internet_exposed: bool | None = None
    notes: str | None = None
    tags: list[str] | None = None


class ScanLaunchRequest(BaseModel):
    name: str
    scanner_type: str
    target: str
    options: dict = Field(default_factory=dict)


class ScanImportRequest(BaseModel):
    scanner_type: str
    name: str = "Imported scan"


class ScheduleCreate(BaseModel):
    name: str
    scanner_type: str
    target: str
    frequency: str
    cron_expression: str | None = None
    rescan_on_remediation: bool = False


class VulnStatusUpdate(BaseModel):
    status: str
    assigned_to: str | None = None


class ConversationTurn(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=4000)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    history: list[ConversationTurn] = Field(default_factory=list, max_length=12)


class KnowledgeDocCreate(BaseModel):
    title: str
    category: str
    content: str
    tags: list[str] = Field(default_factory=list)


class ReportRequest(BaseModel):
    report_type: str
    report_format: str
    scope_asset_ids: list[int] | None = None
    compliance_framework: str | None = None
