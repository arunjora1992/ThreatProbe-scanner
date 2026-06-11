"""Finding triage endpoints (update status / notes on CVE and web findings)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import Finding, User, WebFinding
from ..schemas import FindingOut, FindingUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])

VALID_STATUS = {"open", "confirmed", "false_positive", "fixed", "accepted"}


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, payload: FindingUpdate, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot modify findings")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if payload.status is not None:
        if payload.status not in VALID_STATUS:
            raise HTTPException(status_code=400, detail=f"Invalid status. One of {VALID_STATUS}")
        finding.status = payload.status
    if payload.notes is not None:
        finding.notes = payload.notes
    db.commit()
    db.refresh(finding)
    return finding


@router.patch("/web/{finding_id}")
def update_web_finding(finding_id: int, payload: FindingUpdate, db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot modify findings")
    finding = db.get(WebFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Web finding not found")
    if payload.status is not None:
        if payload.status not in VALID_STATUS:
            raise HTTPException(status_code=400, detail=f"Invalid status. One of {VALID_STATUS}")
        finding.status = payload.status
    db.commit()
    return {"id": finding.id, "status": finding.status}
