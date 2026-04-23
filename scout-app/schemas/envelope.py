from pydantic import BaseModel, field_validator
from typing import Optional, List
import re


class Observables(BaseModel):
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    user: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    protocol: Optional[str] = None


class AttackInfo(BaseModel):
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None


class Links(BaseModel):
    parent_event_id: Optional[str] = None
    related_event_ids: Optional[List[str]] = None


VALID_EVENT_TYPES = {"telemetry", "ioc", "alert", "hunt_finding", "action"}
VALID_PRODUCERS   = {"trap", "scout", "analyst", "hunter", "dispatcher"}
VALID_SEVERITIES  = {"info", "low", "medium", "high", "critical"}

# ISO 8601 / RFC 3339 UTC: 2026-04-23T09:15:22Z
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class EventEnvelope(BaseModel):
    schema_version: str
    event_id: str
    event_type: str
    timestamp: str
    producer: str
    severity: str
    observables: Optional[Observables] = None
    attack: Optional[AttackInfo] = None
    data: Optional[dict] = None
    links: Optional[Links] = None

    @field_validator("event_type")
    @classmethod
    def check_event_type(cls, v):
        if v not in VALID_EVENT_TYPES:
            raise ValueError(f"event_type must be one of {VALID_EVENT_TYPES}")
        return v

    @field_validator("producer")
    @classmethod
    def check_producer(cls, v):
        if v not in VALID_PRODUCERS:
            raise ValueError(f"producer must be one of {VALID_PRODUCERS}")
        return v

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {VALID_SEVERITIES}")
        return v

    @field_validator("timestamp")
    @classmethod
    def check_timestamp(cls, v):
        if not _ISO_RE.match(v):
            raise ValueError("timestamp must be ISO 8601 UTC, e.g. 2026-04-23T09:15:22Z")
        return v
