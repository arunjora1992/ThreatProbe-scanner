"""Manage the offline LLM's GGUF model files from the GUI.

The llm container auto-loads the model named in `<models_dir>/.active` (else the largest
*.gguf present), so this module just curates files on disk:

  * list_models()    — files present + which is selected/loaded
  * select_model()   — write the .active marker (takes effect on next engine restart)
  * download_model() — fetch a GGUF from the curated catalog or a custom URL (connected host)
  * delete_model()   — remove a GGUF

Switching the *loaded* model requires restarting the `llm` container (it loads one model
at start) — the API reports `restart_required` so the GUI can prompt for it.
"""
import os
import threading
import urllib.request

from ..config import settings

ACTIVE_MARKER = ".active"

# Curated, known-good small instruct GGUFs (Q4_K_M). Sizes approximate. Downloaded on a
# connected host into models_dir; on an air-gapped host, drop the .gguf in manually.
CATALOG = [
    {"key": "qwen2.5-1.5b", "label": "Qwen2.5 1.5B Instruct (Q4_K_M, ~1.0 GB) — fast, low RAM",
     "file": "qwen2.5-1.5b-instruct-q4_k_m.gguf",
     "url": "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf",
     "ram": "~3 GB"},
    {"key": "qwen2.5-3b", "label": "Qwen2.5 3B Instruct (Q4_K_M, ~2.0 GB) — better reasoning",
     "file": "qwen2.5-3b-instruct-q4_k_m.gguf",
     "url": "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf",
     "ram": "~5 GB"},
    {"key": "qwen2.5-7b", "label": "Qwen2.5 7B Instruct (Q4_K_M, ~4.7 GB) — strongest, needs RAM",
     "file": "qwen2.5-7b-instruct-q4_k_m.gguf",
     "url": "https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/qwen2.5-7b-instruct-q4_k_m.gguf",
     "ram": "~8 GB"},
    {"key": "llama3.2-3b", "label": "Llama 3.2 3B Instruct (Q4_K_M, ~2.0 GB)",
     "file": "Llama-3.2-3B-Instruct-Q4_K_M.gguf",
     "url": "https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf",
     "ram": "~5 GB"},
]

# filename -> True while a background download is in flight
_downloading = {}
_lock = threading.Lock()


def _dir() -> str:
    os.makedirs(settings.models_dir, exist_ok=True)
    return settings.models_dir


def _safe(name: str) -> str:
    return os.path.basename(name or "").strip()


def active_selection() -> str:
    path = os.path.join(_dir(), ACTIVE_MARKER)
    if os.path.isfile(path):
        try:
            with open(path) as fh:
                return fh.read().strip()
        except OSError:
            pass
    return ""


def loaded_model() -> str:
    """The model the ACTIVE backend (local or remote) has loaded right now (id), or ''."""
    import json
    from . import assistant
    url, _model, key = assistant.llm_config()
    try:
        req = urllib.request.Request(f"{url}/v1/models", headers=assistant.llm_headers(key))
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        mid = (data.get("data") or [{}])[0].get("id", "")
        return os.path.basename(mid) if mid else ""
    except Exception:
        return ""


def list_models() -> dict:
    from . import app_settings
    mode = app_settings.get_str("llm_mode")
    remote_url = app_settings.get_str("llm_remote_url")
    d = _dir()
    files = sorted(f for f in os.listdir(d) if f.endswith(".gguf"))
    selected = active_selection()
    loaded = loaded_model()
    # Largest is the effective default when nothing is selected.
    largest = ""
    if files:
        largest = max(files, key=lambda f: os.path.getsize(os.path.join(d, f)))
    models = []
    for f in files:
        size = os.path.getsize(os.path.join(d, f))
        eff_selected = (selected == f) or (not selected and f == largest)
        models.append({
            "name": f, "size_mb": round(size / (1024 * 1024), 1),
            "selected": eff_selected, "loaded": bool(loaded) and loaded == f,
        })
    downloading = sorted(k for k, v in _downloading.items() if v)
    # Restart only matters for the local engine; in remote mode the bundled files are unused.
    restart_required = (mode != "remote") and bool(loaded) and any(
        m["selected"] and not m["loaded"] for m in models)
    return {"models": models, "selected": selected, "loaded": loaded, "mode": mode,
            "remote_url": remote_url, "downloading": downloading,
            "restart_required": restart_required,
            "catalog": [{"key": c["key"], "label": c["label"], "file": c["file"],
                         "ram": c["ram"], "present": c["file"] in files} for c in CATALOG]}


def select_model(name: str) -> dict:
    name = _safe(name)
    path = os.path.join(_dir(), name)
    if not name.endswith(".gguf") or not os.path.isfile(path):
        raise FileNotFoundError("Model file not found")
    with open(os.path.join(_dir(), ACTIVE_MARKER), "w") as fh:
        fh.write(name)
    return list_models()


def delete_model(name: str) -> dict:
    name = _safe(name)
    if name == loaded_model():
        raise ValueError("Can't delete the model currently loaded by the engine")
    path = os.path.join(_dir(), name)
    if os.path.isfile(path):
        os.remove(path)
    if active_selection() == name:
        try:
            os.remove(os.path.join(_dir(), ACTIVE_MARKER))
        except OSError:
            pass
    return list_models()


def _download(url: str, filename: str):
    d = _dir()
    dest = os.path.join(d, filename)
    tmp = dest + ".part"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThreatProbe"})
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as out:
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        os.replace(tmp, dest)
    except Exception as exc:  # noqa: BLE001
        try:
            os.remove(tmp)
        except OSError:
            pass
        print(f"[llm-models] download failed for {filename}: {exc}", flush=True)
    finally:
        with _lock:
            _downloading.pop(filename, None)


def download_model(key: str = "", url: str = "", filename: str = "") -> dict:
    """Start a background download from the catalog (by key) or a custom URL."""
    if key:
        entry = next((c for c in CATALOG if c["key"] == key), None)
        if not entry:
            raise ValueError("Unknown model key")
        url, filename = entry["url"], entry["file"]
    else:
        url = (url or "").strip()
        if not url.startswith(("http://", "https://")) or ".gguf" not in url.lower():
            raise ValueError("Provide a direct https URL to a .gguf file")
        filename = _safe(filename) or _safe(url.split("?")[0].split("/")[-1])
        if not filename.endswith(".gguf"):
            filename += ".gguf"
    with _lock:
        if _downloading.get(filename):
            return {"started": False, "filename": filename, "message": "Already downloading"}
        _downloading[filename] = True
    threading.Thread(target=_download, args=(url, filename), daemon=True).start()
    return {"started": True, "filename": filename}
