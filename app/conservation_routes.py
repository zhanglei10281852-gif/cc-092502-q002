from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.conservation import ConservationService
from app.conservation_schemas import (
    AckRequest,
    ArtifactCreate,
    BatchImport,
    ContainerCreate,
    EvaluateRequest,
    LocationCreate,
    MergeRequest,
    OrderComplete,
    OrderCreate,
    OrderReturn,
    OrderTransfer,
    ReplayRequest,
    SplitRequest,
    ThresholdPublish,
    WindowCreate,
)
from app.deps import current_user

router = APIRouter(prefix="/api/projects/{project_id}/conservation", tags=["conservation"])


def _service() -> ConservationService:
    return ConservationService()


@router.post("/locations", status_code=201)
def create_location(project_id: int, payload: LocationCreate, user=Depends(current_user)):
    return _service().create_location(project_id, user, payload.model_dump())


@router.get("/locations")
def list_locations(project_id: int, user=Depends(current_user)):
    return _service().list_locations(project_id, user)


@router.post("/containers", status_code=201)
def create_container(project_id: int, payload: ContainerCreate, user=Depends(current_user)):
    return _service().create_container(project_id, user, payload.model_dump())


@router.get("/containers")
def list_containers(project_id: int, user=Depends(current_user)):
    return _service().list_containers(project_id, user)


@router.post("/containers/{container_id}/merge")
def merge_containers(project_id: int, container_id: int, payload: MergeRequest, user=Depends(current_user)):
    return _service().merge_containers(project_id, user, container_id, payload.model_dump())


@router.post("/containers/{container_id}/split")
def split_container(project_id: int, container_id: int, payload: SplitRequest, user=Depends(current_user)):
    return _service().split_container(project_id, user, container_id, payload.model_dump())


@router.post("/artifacts", status_code=201)
def register_artifact(project_id: int, payload: ArtifactCreate, user=Depends(current_user)):
    return _service().register_artifact(project_id, user, payload.model_dump())


@router.get("/artifacts")
def list_artifacts(project_id: int, user=Depends(current_user)):
    return _service().list_artifacts(project_id, user)


@router.get("/artifacts/{artifact_id}")
def get_artifact(project_id: int, artifact_id: int, user=Depends(current_user)):
    return _service().get_artifact(project_id, user, artifact_id)


@router.get("/artifacts/{artifact_id}/custody")
def artifact_custody(project_id: int, artifact_id: int, user=Depends(current_user)):
    return _service().artifact_custody(project_id, user, artifact_id)


@router.post("/thresholds", status_code=201)
def publish_threshold(project_id: int, payload: ThresholdPublish, user=Depends(current_user)):
    return _service().publish_threshold(project_id, user, payload.model_dump())


@router.get("/thresholds")
def list_thresholds(project_id: int, user=Depends(current_user)):
    return _service().list_thresholds(project_id, user)


@router.post("/sensor-batches", status_code=201)
def import_batch(project_id: int, payload: BatchImport, user=Depends(current_user)):
    return _service().import_batch(project_id, user, payload.model_dump())


@router.get("/sensor-batches")
def list_batches(project_id: int, user=Depends(current_user)):
    return _service().list_batches(project_id, user)


@router.post("/maintenance-windows", status_code=201)
def create_window(project_id: int, payload: WindowCreate, user=Depends(current_user)):
    return _service().create_window(project_id, user, payload.model_dump())


@router.get("/maintenance-windows")
def list_windows(project_id: int, user=Depends(current_user)):
    return _service().list_windows(project_id, user)


@router.post("/evaluate")
def evaluate(project_id: int, payload: EvaluateRequest, user=Depends(current_user)):
    return _service().evaluate_all(project_id, user, as_of=payload.as_of)


@router.post("/replay")
def replay(project_id: int, payload: ReplayRequest, user=Depends(current_user)):
    return _service().replay(project_id, user, payload.model_dump())


@router.get("/alerts")
def list_alerts(project_id: int, status: str | None = Query(default=None), user=Depends(current_user)):
    return _service().list_alerts(project_id, user, status)


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(project_id: int, alert_id: int, payload: AckRequest, user=Depends(current_user)):
    return _service().acknowledge_alert(project_id, user, alert_id, payload.model_dump())


@router.get("/todos")
def todos(project_id: int, as_of: str | None = Query(default=None), user=Depends(current_user)):
    return _service().todos(project_id, user, as_of)


@router.post("/treatment-orders", status_code=201)
def create_order(project_id: int, payload: OrderCreate, user=Depends(current_user)):
    return _service().create_order(project_id, user, payload.model_dump())


@router.get("/treatment-orders")
def list_orders(project_id: int, status: str | None = Query(default=None), user=Depends(current_user)):
    return _service().list_orders(project_id, user, status)


@router.post("/treatment-orders/{order_id}/claim")
def claim_order(project_id: int, order_id: int, user=Depends(current_user)):
    return _service().claim_order(project_id, user, order_id)


@router.post("/treatment-orders/{order_id}/transfer")
def transfer_order(project_id: int, order_id: int, payload: OrderTransfer, user=Depends(current_user)):
    return _service().transfer_order(project_id, user, order_id, payload.model_dump())


@router.post("/treatment-orders/{order_id}/complete")
def complete_order(project_id: int, order_id: int, payload: OrderComplete, user=Depends(current_user)):
    return _service().complete_order(project_id, user, order_id, payload.model_dump())


@router.post("/treatment-orders/{order_id}/return")
def return_order(project_id: int, order_id: int, payload: OrderReturn, user=Depends(current_user)):
    return _service().return_order(project_id, user, order_id, payload.model_dump())


@router.post("/treatment-orders/{order_id}/cancel")
def cancel_order(project_id: int, order_id: int, user=Depends(current_user)):
    return _service().cancel_order(project_id, user, order_id)
