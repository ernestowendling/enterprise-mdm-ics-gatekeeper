from __future__ import annotations

from collections.abc import Iterator

import pytest

from gatekeeper.advisor.bedrock_explainer import RemediationAdvisor
from gatekeeper.models import PackId
from gatekeeper.service import GatekeeperService

CLEAN_FINANCE_JOURNALS = frozenset(f"JE-2026-11-{n:04d}" for n in range(1, 6))
CLEAN_TRAVEL_LISTINGS = frozenset(f"L-{n:04d}" for n in range(1, 23))


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> Iterator[GatekeeperService]:
    monkeypatch.delenv("GATEKEEPER_EVIDENCE_HMAC_KEY", raising=False)
    svc = GatekeeperService(advisor=RemediationAdvisor())
    yield svc
    svc.close()


@pytest.fixture
def finance_rows(service: GatekeeperService) -> list[dict[str, str]]:
    return service.sample_rows(PackId.FINANCE_PRECLOSE_ICS)


@pytest.fixture
def travel_rows(service: GatekeeperService) -> list[dict[str, str]]:
    return service.sample_rows(PackId.TRAVEL_RETAIL_GDSN)


@pytest.fixture
def clean_finance_rows(finance_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in finance_rows if r["journal_id"] in CLEAN_FINANCE_JOURNALS]


@pytest.fixture
def clean_travel_rows(travel_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in travel_rows if r["listing_id"] in CLEAN_TRAVEL_LISTINGS]
