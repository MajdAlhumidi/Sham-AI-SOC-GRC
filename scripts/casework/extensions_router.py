"""Case follow-up, portable evidence and isolated comparison endpoints."""
from typing import Literal
from fastapi import APIRouter, BackgroundTasks, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter()


def _run_comparison(trial_id):
    from . import benchmark
    try:
        benchmark.run_ai_trial(trial_id)
    except ValueError:
        # Another model job owns the DB lease. The saved trial remains pending
        # and can be retried explicitly, rather than reporting a false result.
        pass


class FollowupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=1200)
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,100}$")


@router.get("/cases/{case_id}/followups")
def followups(case_id: str):
    from . import followup
    try:
        return {"items": followup.list_turns(case_id)}
    except KeyError:
        raise HTTPException(404, "Case not found")


@router.get("/cases/{case_id}/followups/{turn_id}")
def followup_turn(case_id: str, turn_id: str):
    from . import followup
    result = followup.get_turn(case_id, turn_id)
    if result is None:
        raise HTTPException(404, "Follow-up not found")
    return result


@router.post("/cases/{case_id}/followups", status_code=202)
def ask_followup(case_id: str, payload: FollowupInput, background: BackgroundTasks):
    from . import followup
    try:
        turn = followup.enqueue(case_id, payload.question, payload.request_id)
    except KeyError:
        raise HTTPException(404, "Case not found")
    except followup.FollowupQueueFull as exc:
        raise HTTPException(429, str(exc))
    except (followup.FollowupBusy, followup.FollowupConflict) as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if turn["status"] == "queued":
        background.add_task(followup.run_turn, turn["id"])
    return turn


@router.get("/cases/{case_id}/export")
def export_case(case_id: str):
    from .export import ExportLimitError, build_bundle
    try:
        content, filename = build_bundle(case_id)
    except KeyError:
        raise HTTPException(404, "Case not found")
    except ExportLimitError as exc:
        raise HTTPException(413, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return Response(content, media_type="application/zip", headers={
        "Content-Disposition": 'attachment; filename="'+filename+'"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    })


class TrialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(min_length=1, max_length=100)
    analyst: str = Field(default="", max_length=160)


class ManualResultInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    classification: Literal["malicious", "suspicious", "benign", "insufficient"]
    rationale: str = Field(min_length=3, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=12)
    active_seconds: float | None = Field(default=None, ge=0, le=86400)


@router.get("/comparison/dataset")
def comparison_dataset():
    from . import benchmark
    return benchmark.dataset()


@router.get("/comparison/trials")
def comparison_trials():
    from . import benchmark
    return benchmark.list_trials()


@router.get("/comparison/summary")
def comparison_summary():
    from . import benchmark
    return benchmark.summary()


@router.post("/comparison/trials", status_code=201)
def comparison_start(payload: TrialInput):
    from . import benchmark
    try:
        return benchmark.create_trial(payload.model_dump())
    except KeyError:
        raise HTTPException(404, "Scenario not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.get("/comparison/trials/{trial_id}")
def comparison_trial(trial_id: str):
    from . import benchmark
    try:
        result = benchmark.get_trial(trial_id)
    except KeyError:
        raise HTTPException(404, "Trial not found")
    if result is None:
        raise HTTPException(404, "Trial not found")
    return result


@router.post("/comparison/trials/{trial_id}/complete", status_code=202)
def comparison_complete(trial_id: str, payload: ManualResultInput, background: BackgroundTasks):
    from . import benchmark
    try:
        trial = benchmark.finish_manual(trial_id, payload.model_dump())
    except KeyError:
        raise HTTPException(404, "Trial not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if trial["ai"]["status"] == "pending":
        background.add_task(_run_comparison, trial_id)
    return trial


@router.post("/comparison/ai-trials", status_code=202)
def comparison_ai_only(payload: TrialInput, background: BackgroundTasks):
    from . import benchmark
    try:
        trial = benchmark.start_ai_only(payload.scenario_id)
    except KeyError:
        raise HTTPException(404, "Scenario not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    background.add_task(_run_comparison, trial["id"])
    return trial


@router.post("/comparison/trials/{trial_id}/run-ai", status_code=202)
def comparison_retry(trial_id: str, background: BackgroundTasks):
    from . import benchmark
    try:
        trial = benchmark.get_trial(trial_id)
    except KeyError:
        raise HTTPException(404, "Trial not found")
    if trial is None:
        raise HTTPException(404, "Trial not found")
    if trial["manual"]["status"] == "running":
        raise HTTPException(409, "Complete the blind manual review before starting AI")
    if trial["ai"]["status"] == "pending":
        background.add_task(_run_comparison, trial_id)
    return trial
