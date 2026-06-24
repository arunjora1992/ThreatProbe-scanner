"""Offline AI assistant endpoints — RAG-grounded chat over the local CVE DB / findings."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from fastapi import HTTPException

from ..auth import get_current_user, require_admin
from ..database import get_db
from ..models import User
from ..services import app_settings, assistant, llm_models

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


@router.get("/models")
def models(_: User = Depends(get_current_user)):
    """GGUF model files present, which is selected/loaded, the catalog, downloads."""
    return llm_models.list_models()


@router.post("/models/select")
def select_model(payload: dict, _: User = Depends(require_admin)):
    try:
        return llm_models.select_model(payload.get("name", ""))
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/models/download")
def download_model(payload: dict, _: User = Depends(require_admin)):
    try:
        return llm_models.download_model(key=payload.get("key", ""),
                                         url=payload.get("url", ""),
                                         filename=payload.get("filename", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/models/{name}")
def delete_model(name: str, _: User = Depends(require_admin)):
    try:
        return llm_models.delete_model(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/status")
def status(_: User = Depends(get_current_user)):
    """Assistant enabled flag + whether the local model server is reachable."""
    return {"enabled": app_settings.get_bool("assistant_enabled"),
            "model_online": assistant.llm_available()}


@router.post("/toggle")
def toggle(payload: dict, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """One-click enable/disable of the assistant. Body: {enabled: bool}."""
    app_settings.set_many(db, {"assistant_enabled": bool(payload.get("enabled", True))})
    return {"enabled": app_settings.get_bool("assistant_enabled")}


@router.post("/chat")
def chat(payload: dict, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Answer a question, grounded on local data. Body: {message, history?:[{role,content}]}."""
    if not app_settings.get_bool("assistant_enabled"):
        return {"reply": "The AI assistant is disabled. An admin can enable it in "
                         "Settings → AI Assistant.", "citations": [], "grounded": False,
                "model": False}
    message = (payload.get("message") or "").strip()
    if not message:
        return {"reply": "Ask me about a CVE, a scan (e.g. 'scan #12'), a package, or a "
                         "vulnerability class like XSS or SQLi.", "citations": [],
                "grounded": False, "model": assistant.llm_available()}
    history = payload.get("history") or []
    return assistant.answer(db, message[:2000], history)
