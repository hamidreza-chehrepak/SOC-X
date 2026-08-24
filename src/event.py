from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class SecurityEvent(BaseModel):
    source_ip: str
    event_type: str
    severity: Severity
    description: str