"""有机遗物保护处置模块的 HTTP 路由，统一挂在 /api/projects/{project_id}/... 下。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query

from app.organics.schemas import (
    ArtifactCreate,
    ArtifactUpdate,
    BatchCreate,
    HandlingOrderCreate,
    MaintenanceWindowCreate,
    OrderAction,
    PackageCreate,
    PackageMerge,
    PackageSplit,
    ThresholdSchemeCreate,
)
from app.organics.service import OrganicService
from app.service import ResearchService

router = APIRouter(prefix="/api/projects/{project_id}", tags=["organics"])


def current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        from fastapi import HTTPException

        raise HTTPException(401, "缺少 Bearer 会话")
    return ResearchService().authenticate(authorization[7:])


@router.post("/artifacts", status_code=201)
def register_artifact(project_id: int, payload: ArtifactCreate, user=Depends(current_user)):
    return OrganicService().register_artifact(project_id, payload.model_dump(), user)


@router.get("/artifacts")
def list_artifacts(project_id: int, material_kind: str | None = Query(default=None), user=Depends(current_user)):
    return OrganicService().list_artifacts(project_id, user, material_kind)


@router.get("/artifacts/{temp_number}")
def get_artifact(project_id: int, temp_number: str, user=Depends(current_user)):
    return OrganicService().get_artifact(project_id, temp_number, user)


@router.patch("/artifacts/{temp_number}")
def update_artifact(project_id: int, temp_number: str, payload: ArtifactUpdate, user=Depends(current_user)):
    return OrganicService().update_artifact(project_id, temp_number, payload.model_dump(), user)


@router.get("/artifacts/{temp_number}/chain")
def artifact_chain(project_id: int, temp_number: str, user=Depends(current_user)):
    return OrganicService().artifact_chain(project_id, temp_number, user)


@router.post("/threshold-schemes", status_code=201)
def publish_scheme(project_id: int, payload: ThresholdSchemeCreate, user=Depends(current_user)):
    return OrganicService().publish_scheme(project_id, payload.model_dump(), user)


@router.get("/threshold-schemes")
def list_schemes(project_id: int, material_kind: str | None = Query(default=None), user=Depends(current_user)):
    return OrganicService().list_schemes(project_id, material_kind, user)


@router.post("/maintenance-windows", status_code=201)
def create_maintenance_window(project_id: int, payload: MaintenanceWindowCreate, user=Depends(current_user)):
    return OrganicService().create_maintenance_window(project_id, payload.model_dump(), user)


@router.post("/sensor-batches", status_code=201)
def import_batch(project_id: int, payload: BatchCreate, user=Depends(current_user)):
    return OrganicService().import_batch(project_id, payload.model_dump(), user)


@router.get("/alerts")
def list_alerts(project_id: int, status: str | None = Query(default=None), user=Depends(current_user)):
    return OrganicService().list_alerts(project_id, user, status)


@router.post("/packages", status_code=201)
def create_package(project_id: int, payload: PackageCreate, user=Depends(current_user)):
    return OrganicService().create_package(project_id, payload.model_dump(), user)


@router.post("/packages/merge", status_code=201)
def merge_packages(project_id: int, payload: PackageMerge, user=Depends(current_user)):
    return OrganicService().merge_packages(project_id, payload.model_dump(), user)


@router.post("/packages/split", status_code=201)
def split_packages(project_id: int, payload: PackageSplit, user=Depends(current_user)):
    return OrganicService().split_packages(project_id, payload.model_dump(), user)


@router.get("/packages/{code}")
def get_package(project_id: int, code: str, user=Depends(current_user)):
    return OrganicService().get_package(project_id, code, user)


@router.post("/handling-orders", status_code=201)
def create_order(project_id: int, payload: HandlingOrderCreate, user=Depends(current_user)):
    return OrganicService().create_order(project_id, payload.model_dump(), user)


@router.get("/handling-orders")
def list_orders(project_id: int, status: str | None = Query(default=None), user=Depends(current_user)):
    return OrganicService().list_orders(project_id, user, status)


@router.get("/handling-orders/{order_id}")
def get_order(project_id: int, order_id: int, user=Depends(current_user)):
    return OrganicService().get_order(project_id, order_id, user)


@router.post("/handling-orders/{order_id}/claim")
def claim_order(project_id: int, order_id: int, payload: OrderAction, user=Depends(current_user)):
    return OrganicService().claim_order(project_id, order_id, user, payload.note)


@router.post("/handling-orders/{order_id}/complete")
def complete_order(project_id: int, order_id: int, payload: OrderAction, user=Depends(current_user)):
    return OrganicService().complete_order(project_id, order_id, user, payload.note)


@router.post("/handling-orders/{order_id}/return")
def return_order(project_id: int, order_id: int, payload: OrderAction, user=Depends(current_user)):
    return OrganicService().return_order(project_id, order_id, user, payload.note)


@router.post("/handling-orders/{order_id}/transfer")
def transfer_order(project_id: int, order_id: int, payload: OrderAction, user=Depends(current_user)):
    return OrganicService().transfer_order(project_id, order_id, user, payload.to_username, payload.note)
