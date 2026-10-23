from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from auth.security import get_current_user
from models.database import User

from .run import run
from .dataset import candidate_pairs, dataset_status, save_labeled_pairs, sync_database_dataset
from models.database import get_db

router = APIRouter()
ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config.yaml"
RESULTS = ROOT / "results"


def _read(name: str) -> dict:
    path = RESULTS / name
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/status")
def status(db = Depends(get_db), _: User = Depends(get_current_user)):
    return {"validation": _read("validation.json"), "metrics": _read("metrics.json"), "dataset": dataset_status()}


@router.post("/sync-dataset")
def sync_dataset(db = Depends(get_db), _: User = Depends(get_current_user)):
    return {"dataset": sync_database_dataset(db)}


@router.get("/dataset/candidates")
def get_candidates(_: User = Depends(get_current_user)):
    return {"candidates": candidate_pairs()}


@router.post("/dataset/labels")
def save_labels(payload: dict, _: User = Depends(get_current_user)):
    try:
        count = save_labeled_pairs(payload.get("pairs", []))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"saved": count, "path": "experiments/data/real_labeled_pairs.csv"}


@router.post("/run")
def run_controlled(_: User = Depends(get_current_user)):
    exit_code = run(CONFIG)
    return {"exit_code": exit_code, "validation": _read("validation.json"), "metrics": _read("metrics.json")}


@router.get("/export/{name}")
def export(name: str, _: User = Depends(get_current_user)):
    allowed = {"results.csv", "metrics.json", "run_manifest.json"}
    if name not in allowed:
        raise HTTPException(status_code=404, detail="Unknown experiment export")
    path = RESULTS / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Export is not available; run the experiment first")
    return FileResponse(path, filename=name)
