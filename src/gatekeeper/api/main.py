"""FastAPI service: batch ingestion, pre-flight validation, quarantine, four-eyes sign-off,
lineage trace and control evidence.

Run locally with ``uvicorn gatekeeper.api.main:app --reload``. The OpenAPI schema is served
at ``/docs`` and ``/openapi.json``.
"""

# Annotations are evaluated eagerly here on purpose: FastAPI resolves dependency and request
# model types at import time, so postponed evaluation adds no value in this module.

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from gatekeeper import __version__
from gatekeeper.evidence.exporter import EvidencePack, findings_csv, render_markdown
from gatekeeper.ledger.four_eyes import (
    FourEyesError,
    SegregationOfDutiesError,
    SelfApprovalError,
)
from gatekeeper.ledger.store import RunNotFoundError
from gatekeeper.models import (
    ChainVerification,
    LineageTrace,
    PackId,
    RemediationAdvice,
    RuleDescriptor,
    RunRecord,
    RunSummary,
)
from gatekeeper.service import GatekeeperService

# ---------------------------------------------------------------------------
# Request and response schemas
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    packs: list[PackId]
    audit_chain_valid: bool
    advisor_mode: str


class PackInfo(BaseModel):
    pack_id: PackId
    display_name: str
    rules: list[RuleDescriptor]


class ValidateRequest(BaseModel):
    maker_id: str = Field(min_length=1, description="Preparer submitting the batch")
    records: list[dict[str, Any]] | None = Field(
        default=None, description="Raw records; each is validated against the pack contract"
    )
    use_synthetic_sample: bool = Field(
        default=False, description="Validate the bundled synthetic batch instead of `records`"
    )
    source_name: str = Field(default="api", min_length=1)


class ApprovalRequest(BaseModel):
    run_id: str = Field(min_length=1)
    checker_id: str = Field(min_length=1)
    decision: Literal["RELEASE", "APPROVE_WITH_EXCEPTION"]
    justification: str | None = None


# ---------------------------------------------------------------------------
# Dependencies and error mapping
# ---------------------------------------------------------------------------


def get_service(request: Request) -> GatekeeperService:
    service = getattr(request.app.state, "service", None)
    if not isinstance(service, GatekeeperService):
        raise RuntimeError("GatekeeperService is not initialised")
    return service


ServiceDep = Annotated[GatekeeperService, Depends(get_service)]


async def _four_eyes_error(request: Request, exc: Exception) -> JSONResponse:
    status = 403 if isinstance(exc, SelfApprovalError | SegregationOfDutiesError) else 409
    return JSONResponse(
        status_code=status, content={"error": type(exc).__name__, "detail": str(exc)}
    )


async def _not_found(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "RunNotFound", "detail": str(exc)})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["operations"])
def health(service: ServiceDep) -> HealthResponse:
    chain = service.verify_audit_chain()
    return HealthResponse(
        status="ok" if chain.valid else "degraded",
        version=__version__,
        packs=list(PackId),
        audit_chain_valid=chain.valid,
        advisor_mode=service.advisor.mode,
    )


@router.get("/packs", response_model=list[PackInfo], tags=["catalogue"])
def packs(service: ServiceDep) -> list[PackInfo]:
    return [
        PackInfo(pack_id=pid, display_name=name, rules=rules)
        for pid, name, rules in service.packs()
    ]


@router.post("/validate/{pack_id}", response_model=RunSummary, tags=["validation"])
def validate(pack_id: PackId, payload: ValidateRequest, service: ServiceDep) -> RunSummary:
    """Ingest a batch, run the deterministic gate and open the maker/checker workflow."""
    if payload.use_synthetic_sample:
        return service.validate_sample(pack_id, payload.maker_id)
    if not payload.records:
        raise HTTPException(
            status_code=422, detail="Provide `records` or set `use_synthetic_sample` to true"
        )
    return service.validate(
        pack_id, payload.records, maker_id=payload.maker_id, source_name=payload.source_name
    )


@router.get("/runs/{run_id}", response_model=RunSummary, tags=["validation"])
def run_summary(run_id: str, service: ServiceDep) -> RunSummary:
    return service.run_summary(run_id)


@router.get("/quarantine", response_model=list[RunRecord], tags=["workflow"])
def quarantine(
    service: ServiceDep, pack_id: Annotated[PackId | None, Query()] = None
) -> list[RunRecord]:
    """Runs held at the gate, awaiting remediation or four-eyes exception approval."""
    return service.quarantined(pack_id)


@router.post("/approve", response_model=RunSummary, tags=["workflow"])
def approve(payload: ApprovalRequest, service: ServiceDep) -> RunSummary:
    """Checker sign-off. Self-approval, SoD conflicts and BLOCKER overrides are rejected."""
    if payload.decision == "RELEASE":
        return service.release(payload.run_id, payload.checker_id)
    return service.approve_with_exception(payload.run_id, payload.checker_id, payload.justification)


@router.get("/lineage/{run_id}/targets", response_model=list[str], tags=["lineage"])
def lineage_targets(run_id: str, service: ServiceDep) -> list[str]:
    return service.lineage_targets(run_id)


@router.get("/lineage/{run_id}", response_model=LineageTrace, tags=["lineage"])
def lineage_trace(
    run_id: str,
    service: ServiceDep,
    target: Annotated[str, Query(description="Target attribute, e.g. SAP_S4HANA/ACDOCA.KSL")],
) -> LineageTrace:
    return service.trace_lineage(run_id, target)


@router.get("/advice/{run_id}", response_model=list[RemediationAdvice], tags=["advisor"])
def advice(run_id: str, service: ServiceDep) -> list[RemediationAdvice]:
    """Advisory remediation drafts. They never alter gate decisions or workflow state."""
    return service.advise(run_id)


@router.get("/evidence/{run_id}", response_model=EvidencePack, tags=["evidence"])
def evidence(run_id: str, service: ServiceDep) -> EvidencePack:
    return service.evidence_pack(run_id)


@router.get("/evidence/{run_id}/summary.md", response_class=PlainTextResponse, tags=["evidence"])
def evidence_markdown(run_id: str, service: ServiceDep) -> str:
    return render_markdown(service.evidence_pack(run_id))


@router.get("/evidence/{run_id}/findings.csv", response_class=PlainTextResponse, tags=["evidence"])
def evidence_csv(run_id: str, service: ServiceDep) -> str:
    return findings_csv(service.evidence_pack(run_id))


@router.get("/audit/verify", response_model=ChainVerification, tags=["operations"])
def audit_verify(service: ServiceDep) -> ChainVerification:
    return service.verify_audit_chain()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(service: GatekeeperService | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = service is None
        app.state.service = service if service is not None else GatekeeperService.from_environment()
        try:
            yield
        finally:
            if owned:
                app.state.service.close()

    app = FastAPI(
        title="Enterprise MDM & ICS Gatekeeper",
        version=__version__,
        description=(
            "Deterministic pre-release control gate for finance pre-close (ICS/SOX, BCBS 239) "
            "and GS1/GDSN product master data, with hash-chained audit evidence and four-eyes "
            "sign-off."
        ),
        lifespan=lifespan,
    )
    app.add_exception_handler(FourEyesError, _four_eyes_error)
    app.add_exception_handler(RunNotFoundError, _not_found)
    app.include_router(router)
    return app


app = create_app()
