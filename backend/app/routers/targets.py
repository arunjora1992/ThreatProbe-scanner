"""Target (asset) management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import Target, User
from ..schemas import TargetCreate, TargetOut

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Target).order_by(Target.created_at.desc()).all()


@router.post("", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    target = Target(**payload.model_dump())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{target_id}", response_model=TargetOut)
def update_target(target_id: int, payload: TargetCreate, db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    for k, v in payload.model_dump().items():
        setattr(target, k, v)
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
