from pydantic import BaseModel, Field, IPvAnyAddress
from typing import Literal

EventType = Literal["failed_login", "successful_login", "sql_injection", "port_scan", "malware_indicator", "other"]

class AlertIn(BaseModel):
    source_ip: str = Field(min_length=3, max_length=64)
    event_type: EventType
    target: str = Field(min_length=1, max_length=200)
    details: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"

class SimulateIn(BaseModel):
    scenario: Literal["brute_force", "sql_injection", "normal_login"] = "brute_force"
    source_ip: str = "198.51.100.23"
    target: str = "demo-login"
