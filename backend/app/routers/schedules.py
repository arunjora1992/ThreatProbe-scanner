"""Scheduled (recurring) scans — CRUD + run-now."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import ScanSchedule, Target, User
from ..services import scan_scheduler

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


class ScheduleIn(BaseModel):
    target_id: int
    scan_type: str = "full"
    custom_flags: str = ""
    interval_hours: int = 24
    enabled: bool = True


class ScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    scan_type: str
    custom_flags: str
    interval_hours: int
    enabled: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_by: str
    created_at: datetime


@router.get("", response_model=list[ScheduleOut])
def list_schedules(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(ScanSchedule).order_by(ScanSchedule.id.desc()).all()


@router.post("", response_model=ScheduleOut, status_code=201)
def create_schedule(payload: ScheduleIn, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot create schedules")
    if payload.scan_type not in scan_scheduler.SCHEDULABLE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=("Only credential-less scans are schedulable "
                    f"({', '.join(sorted(scan_scheduler.SCHEDULABLE_TYPES))}). "
                    "Credentialed/CIS scans need in-memory credentials and can't be scheduled."))
    if payload.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")
    if not db.get(Target, payload.target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    sch = ScanSchedule(
        target_id=payload.target_id, scan_type=payload.scan_type,
        custom_flags=payload.custom_flags or "", interval_hours=payload.interval_hours,
        enabled=payload.enabled, created_by=user.username,
    )
    db.add(sch)
    db.commit()
    db.refresh(sch)
    return sch


@router.put("/{sid}", response_model=ScheduleOut)
def update_schedule(sid: int, payload: ScheduleIn, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot edit schedules")
    sch = db.get(ScanSchedule, sid)
    if not sch:
        raise HTTPException(status_code=404, detail="Schedule not found")
    sch.scan_type = payload.scan_type
    sch.custom_flags = payload.custom_flags or ""
    sch.interval_hours = max(1, payload.interval_hours)
    sch.enabled = payload.enabled
    db.commit()
    db.refresh(sch)
    return sch


@router.post("/{sid}/run", response_model=dict)
def run_now(sid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot run schedules")
    sch = db.get(ScanSchedule, sid)
    if not sch:
        raise HTTPException(status_code=404, detail="Schedule not found")
    scan = scan_scheduler.enqueue(db, sch)
    return {"scan_id": scan.id, "message": f"Queued scan #{scan.id}"}


@router.delete("/{sid}", status_code=204)
def delete_schedule(sid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot delete schedules")
    sch = db.get(ScanSchedule, sid)
    if sch:
        db.delete(sch)
        db.commit()
