from pydantic import BaseModel, Field
from typing import Literal


class EventEnvelope(BaseModel):
    event_id: str = Field(..., min_length=1)
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    source: str = Field(..., min_length=1)
    ioc_value: str = Field(..., min_length=1)
    ioc_type: Literal["ip", "domain", "url", "hash", "email"]
    tags: list[str] = Field(default_factory=list)
    reputation_score: int = Field(..., ge=0, le=100)
