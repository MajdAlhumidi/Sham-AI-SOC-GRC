"""Authenticated investigation API; uses the existing GRC workspace credential."""
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from . import store
try:
    from ..grc.router import require_grc_token
except ImportError:
    from grc.router import require_grc_token


def no_cache(response: Response):
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/investigations", tags=["Investigations"], dependencies=[Depends(require_grc_token), Depends(no_cache)])


class AssetInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=0)
    owner: str = Field(default="", max_length=160)
    service: str = Field(default="", max_length=200)
    criticality: Literal["unassessed", "low", "medium", "high", "critical"]
    sensitivity: Literal["unassessed", "public", "internal", "confidential", "restricted"]


class ChangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    revision: int = Field(default=0, ge=0)
    asset_id: str = Field(min_length=1, max_length=240)
    ticket: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=3, max_length=1000)
    rule_id: str = Field(pattern=r"^[0-9]{1,12}$")
    source_ip: str = Field(min_length=1, max_length=64)
    account: str = Field(default="", max_length=160)
    start: str = Field(max_length=64)
    end: str = Field(max_length=64)
    approved_at: str = Field(max_length=64)
    approved_by: str = Field(min_length=1, max_length=160)
    status: Literal["approved", "revoked"] = "approved"

    @model_validator(mode="after")
    def valid_window(self):
        import ipaddress
        try:
            self.source_ip = str(ipaddress.ip_address(self.source_ip.strip()))
        except ValueError as exc:
            raise ValueError("Use an exact source IP, never a wildcard") from exc
        stamps = [store.epoch(x) for x in (self.start, self.end, self.approved_at)]
        if any(x is None for x in stamps):
            raise ValueError("All dates require an explicit UTC offset")
        if stamps[1] <= stamps[0] or stamps[1]-stamps[0] > 7*86400:
            raise ValueError("Change window must be positive and at most seven days")
        if stamps[2] > stamps[0]:
            raise ValueError("Approval must precede the change window")
        self.account = store.clean(self.account)
        return self


@router.get("/cases")
def cases(q: str = Query("", max_length=200), band: Literal["", "Critical", "High", "Medium", "Low"] = "", offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=100)):
    return store.list_cases(q, band, offset, limit)


@router.get("/cases/{case_id}")
def case(case_id: str):
    result = store.case_detail(case_id)
    if not result:
        raise HTTPException(404, "Case not found")
    return result


@router.get("/incidents/{incident_id}")
def incident(incident_id: str):
    with store.db() as conn:
        row = conn.execute("SELECT case_id FROM events WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(404, "This incident has not been imported into the workspace")
    return {"case_id": row[0]}


@router.get("/evidence/{incident_id}/{ref}")
def evidence(incident_id: str, ref: str):
    result = store.get_evidence(incident_id, ref)
    if not result:
        raise HTTPException(404, "Original evidence is unavailable; a report citation is not a substitute")
    return result


@router.get("/context")
def context():
    return store.profiles()


@router.put("/assets/{asset_id}")
def asset(asset_id: str, payload: AssetInput):
    try:
        return store.save_asset(asset_id, payload.model_dump())
    except KeyError:
        raise HTTPException(404, "Asset not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.put("/changes/{change_id}")
def change(change_id: str, payload: ChangeInput):
    if change_id != payload.id:
        raise HTTPException(422, "Change IDs must match")
    try:
        return store.save_change(payload.model_dump())
    except KeyError:
        raise HTTPException(404, "Asset not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.get("/audit")
def audit(offset: int = Query(0, ge=0), limit: int = Query(40, ge=1, le=100)):
    return store.audit_page(offset, limit)
