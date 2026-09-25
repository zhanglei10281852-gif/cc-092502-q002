from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, model_validator

MetricName = Literal["temperature", "humidity", "ph", "conductivity"]
Category = Literal["wood", "textile", "rope"]
OrderType = Literal["wet_storage", "packaging", "transport", "lab_handover"]


class LocationCreate(BaseModel):
    code: str = Field(..., min_length=1, max_length=60)
    name: str = Field(..., min_length=1, max_length=120)
    sensitive: bool = False


class ContainerCreate(BaseModel):
    code: str = Field(..., min_length=1, max_length=60)
    kind: str = Field("box", min_length=1, max_length=40)
    category: Category
    location_id: int | None = None


class ArtifactCreate(BaseModel):
    temp_number: str = Field(..., min_length=1, max_length=80)
    category: Category
    material_note: str = Field("", max_length=500)
    excavation_env: str = Field("", max_length=500)
    container_code: str | None = Field(None, min_length=1, max_length=60)
    location_id: int | None = None
    note: str = Field("", max_length=500)


class MetricBound(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min: FiniteFloat | None = None
    max: FiniteFloat | None = None

    @model_validator(mode="after")
    def _check_bounds(self):
        if self.min is None and self.max is None:
            raise ValueError("指标至少需要一个上限或下限")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("指标下限不能大于上限")
        return self


class EscalationTier(BaseModel):
    after_minutes: int = Field(..., gt=0, le=100000)
    severity: Literal["elevated", "critical"]


class ThresholdConfig(BaseModel):
    metrics: dict[MetricName, MetricBound] = Field(..., min_length=1)
    missing_after_minutes: int = Field(180, gt=0, le=100000)
    escalation: list[EscalationTier] = Field(default_factory=list, max_length=8)


class ThresholdPublish(BaseModel):
    category: Category
    config: ThresholdConfig


class ReadingIn(BaseModel):
    container_id: int | None = None
    container_code: str | None = Field(None, min_length=1, max_length=60)
    metric: MetricName
    value: FiniteFloat
    observed_at: str = Field(..., min_length=1, max_length=40)

    @model_validator(mode="after")
    def _check_container_ref(self):
        if (self.container_id is None) == (self.container_code is None):
            raise ValueError("container_id 与 container_code 必须且只能提供一个")
        return self


class BatchImport(BaseModel):
    batch_key: str = Field(..., min_length=1, max_length=120)
    source: str = Field("offline", min_length=1, max_length=80)
    as_of: str | None = Field(None, min_length=1, max_length=40)
    readings: list[ReadingIn] = Field(default_factory=list, max_length=5000)


class WindowCreate(BaseModel):
    container_id: int | None = None
    starts_at: str = Field(..., min_length=1, max_length=40)
    ends_at: str = Field(..., min_length=1, max_length=40)
    reason: str = Field("", max_length=500)


class EvaluateRequest(BaseModel):
    as_of: str | None = Field(None, min_length=1, max_length=40)


class ReplayRequest(BaseModel):
    as_of: str | None = Field(None, min_length=1, max_length=40)
    readings: list[ReadingIn] = Field(default_factory=list, max_length=5000)


class AckRequest(BaseModel):
    note: str = Field("", max_length=500)


class OrderCreate(BaseModel):
    artifact_id: int
    order_type: OrderType
    title: str = Field(..., min_length=1, max_length=200)
    instructions: str = Field("", max_length=2000)
    assignee_id: int
    lease_minutes: int = Field(30, ge=1, le=1440)


class OrderTransfer(BaseModel):
    assignee_id: int


class OrderComplete(BaseModel):
    note: str = Field("", max_length=500)


class OrderReturn(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class MergeRequest(BaseModel):
    source_container_ids: list[int] = Field(..., min_length=1, max_length=50)
    note: str = Field("", max_length=500)


class NewContainerSpec(BaseModel):
    code: str = Field(..., min_length=1, max_length=60)
    kind: str = Field("box", min_length=1, max_length=40)
    location_id: int | None = None


class SplitRequest(BaseModel):
    artifact_ids: list[int] = Field(..., min_length=1, max_length=500)
    new_container: NewContainerSpec
    note: str = Field("", max_length=500)
