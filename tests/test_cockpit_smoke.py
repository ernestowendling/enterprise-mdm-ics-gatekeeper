from __future__ import annotations

from pathlib import Path

import pytest

testing = pytest.importorskip("streamlit.testing.v1")

COCKPIT = Path(__file__).resolve().parents[1] / "app" / "cockpit.py"


def test_cockpit_runs_validation_end_to_end() -> None:
    app = testing.AppTest.from_file(str(COCKPIT), default_timeout=60)
    app.run()
    assert not app.exception

    app.sidebar.button[0].click().run()
    assert not app.exception
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Gate decision"] == "BLOCKED"
    assert metrics["Workflow state"] == "QUARANTINED"
