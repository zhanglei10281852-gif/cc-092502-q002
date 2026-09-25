"""有机遗物模块的请求/响应模型。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

MaterialKind = Literal["wood", "textile", "rope", "other"]
BurialEnv = Literal["saturated_silt", "waterlogged", "wet", "damp", "unknown"]
StorageState = Literal["wet_kept", "immersed", "wrapped", "drying", "stable"]
Metric = Literal["temperature", "humidity", "fluid_ph", "fluid_ec", "fluid_level", "oxygen"]
ViolationKind = Literal["low", "high"]

METRICS: tuple[str, ...] = ("temperature", "humidity", "fluid_ph", "fluid_ec", "fluid_level", "oxygen")


class ThresholdRule(BaseModel):
    metric: Metric
    min_value: float | None = None
    max_value: float | None = None
    # 连续越界多少分钟后分别升级到 serious / critical；warning 立即产生
    escalate_after_minutes: int = Field(default=30, ge=1, le=24 * 60)
    critical_after_minutes: int = Field(default=120, ge=1, le=7 * 24 * 60)
    # 配置后，相邻两次读数间隔超过该分钟数即判定为缺测（维护窗口内除外）
    expect_interval_minutes: int | None = Field(default=None, ge=1, le=7 * 24 * 60)

    @field_validator("max_value")
    @classmethod
    def _check_range(cls, value, info):
        low = info.data.get("min_value")
        if value is not None and low is not None and value <= low:
            raise ValueError("max_value 必须大于 min_value")
        return value


class ThresholdSchemeCreate(BaseModel):
    material_kind: MaterialKind
    rules: list[ThresholdRule] = Field(..., min_length=1)

    @field_validator("rules")
    @classmethod
    def _unique_metric(cls, value):
        metrics = [rule.metric for rule in value]
        if len(set(metrics)) != len(metrics):
            raise ValueError("同一指标只能出现一次")
        return value


class ArtifactCreate(BaseModel):
    temp_number: str = Field(..., min_length=1, max_length=60)
    material_kind: MaterialKind
    material_detail: str = Field(default="", max_length=300)
    burial_env: BurialEnv = "unknown"
    storage_state: StorageState = "wet_kept"
    container_code: str = Field(default="", max_length=60)
    immersion_fluid: str = Field(default="", max_length=120)
    location_code: str = Field(default="", max_length=60)
    notes: str = Field(default="", max_length=1000)


class ArtifactUpdate(BaseModel):
    storage_state: StorageState | None = None
    container_code: str | None = Field(default=None, max_length=60)
    immersion_fluid: str | None = Field(default=None, max_length=120)
    location_code: str | None = Field(default=None, max_length=60)
    notes: str | None = Field(default=None, max_length=1000)


class MaintenanceWindowCreate(BaseModel):
    start_at: str = Field(..., min_length=4)
    end_at: str = Field(..., min_length=4)
    location_code: str = Field(default="", max_length=60)
    metric: str = Field(default="", max_length=20)
    reason: str = Field(default="", max_length=300)


class Reading(BaseModel):
    # artifact_temp_number 与 location_code 至少给一个：有遗物编号时绑定遗物，
    # 否则只按库位记录（库位读数同样参与该库位遗物的缺测判断由服务层决定）。
    artifact_temp_number: str | None = Field(default=None, max_length=60)
    location_code: str = Field(default="", max_length=60)
    metric: Metric
    value: float
    measured_at: str = Field(..., min_length=4)


class BatchCreate(BaseModel):
    batch_ref: str = Field(..., min_length=1, max_length=80)
    source: str = Field(default="", max_length=120)
    readings: list[Reading] = Field(..., min_length=1)


class PackageCreate(BaseModel):
    package_code: str = Field(..., min_length=1, max_length=60)
    artifact_temp_numbers: list[str] = Field(default_factory=list)


class PackageMerge(BaseModel):
    source_package_codes: list[str] = Field(..., min_length=2)
    target_package_code: str = Field(..., min_length=1, max_length=60)


class PackageSplit(BaseModel):
    source_package_code: str
    target_package_codes: list[str] = Field(..., min_length=1)
    # 与 target_package_codes 等长的分组，每一组是分到该目标包装的临时编号
    groups: list[list[str]] = Field(..., min_length=1)


class HandlingOrderCreate(BaseModel):
    order_no: str = Field(..., min_length=1, max_length=60)
    kind: Literal["wet_storage", "repack", "transfer", "lab_handover", "inspection"]
    priority: Literal["low", "normal", "high", "urgent"] = "normal"
    reason: str = Field(default="", max_length=500)
    artifact_temp_numbers: list[str] = Field(default_factory=list)
    package_code: str | None = None


class OrderAction(BaseModel):
    note: str = Field(default="", max_length=500)
    # 转交时必须给出新的保护人员用户名；领取/完成/退回可为空
    to_username: str | None = None
