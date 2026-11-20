"""Four-eyes (maker/checker) state machine with Segregation of Duties enforcement.

State is event-sourced: the current state of a run is the ``to_state`` of its latest workflow
event. Every transition is written together with a hash-chained audit event in one
transaction, so sign-off evidence cannot exist without its audit counterpart.

Lifecycle::

    (none) --OPEN--> DRAFT --SUBMIT--> SUBMITTED --RELEASE--> RELEASED   (gate CLEAR)
                                           |
                                           +--QUARANTINE--> QUARANTINED
                                                                 |
                                       APPROVE_WITH_EXCEPTION ---+--> APPROVED_WITH_EXCEPTION
                                       (warnings only, justified, independent checker)

A quarantined run that carries a BLOCKER is a hard stop: no actor can approve it. The data is
remediated upstream and resubmitted as a new run, which keeps the evidence of the failed run
intact.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from gatekeeper.ledger.store import ControlStore, utc_now_iso
from gatekeeper.models import GateDecision, WorkflowAction, WorkflowEvent, WorkflowState

SYSTEM_ACTOR = "SYSTEM:gatekeeper-engine"

TRANSITIONS: Mapping[tuple[WorkflowState | None, WorkflowAction], WorkflowState] = {
    (None, WorkflowAction.OPEN): WorkflowState.DRAFT,
    (WorkflowState.DRAFT, WorkflowAction.SUBMIT): WorkflowState.SUBMITTED,
    (WorkflowState.SUBMITTED, WorkflowAction.QUARANTINE): WorkflowState.QUARANTINED,
    (WorkflowState.SUBMITTED, WorkflowAction.RELEASE): WorkflowState.RELEASED,
    (
        WorkflowState.QUARANTINED,
        WorkflowAction.APPROVE_WITH_EXCEPTION,
    ): WorkflowState.APPROVED_WITH_EXCEPTION,
}


class FourEyesError(Exception):
    """Base class for rejected workflow transitions."""


class InvalidTransitionError(FourEyesError):
    """The requested action is not permitted from the current state."""


class SelfApprovalError(FourEyesError):
    """The checker is the maker of the run (four-eyes principle breached)."""


class SegregationOfDutiesError(FourEyesError):
    """The actor lacks the required role or holds a role incompatible with the action."""


class HardGateError(FourEyesError):
    """A BLOCKER finding prevents release irrespective of who approves."""


class JustificationRequiredError(FourEyesError):
    """An exception approval was attempted without an adequate written justification."""


@dataclass(frozen=True)
class AccessDirectory:
    """Snapshot of user-to-role assignments taken from the identity and access system."""

    roles_by_user: Mapping[str, frozenset[str]]

    @classmethod
    def from_config(cls, raw: Mapping[str, Sequence[str]]) -> AccessDirectory:
        return cls({str(user): frozenset(str(r) for r in roles) for user, roles in raw.items()})

    def roles_of(self, user_id: str) -> frozenset[str]:
        return self.roles_by_user.get(user_id, frozenset())


@dataclass(frozen=True)
class FourEyesPolicy:
    """Role model for one rule pack."""

    submitter_role: str
    approver_role: str
    roles_incompatible_with_approval: frozenset[str]
    min_justification_length: int = 20

    @classmethod
    def from_config(cls, raw: Mapping[str, Any]) -> FourEyesPolicy:
        return cls(
            submitter_role=str(raw["submitter_role"]),
            approver_role=str(raw["approver_role"]),
            roles_incompatible_with_approval=frozenset(
                str(r) for r in raw.get("roles_incompatible_with_approval", [])
            ),
            min_justification_length=int(raw.get("min_justification_length", 20)),
        )


class FourEyesWorkflow:
    """Maker/checker workflow bound to one pack's policy and access directory."""

    def __init__(
        self, store: ControlStore, policy: FourEyesPolicy, directory: AccessDirectory
    ) -> None:
        self._store = store
        self._policy = policy
        self._directory = directory

    @property
    def policy(self) -> FourEyesPolicy:
        return self._policy

    # -- queries -------------------------------------------------------------------------

    def history(self, run_id: str) -> list[WorkflowEvent]:
        return self._store.fetch_workflow_events(run_id)

    def current_state(self, run_id: str) -> WorkflowState | None:
        events = self.history(run_id)
        return events[-1].to_state if events else None

    def maker_of(self, run_id: str) -> str | None:
        for event in self.history(run_id):
            if event.action is WorkflowAction.SUBMIT:
                return event.actor_id
        return None

    # -- maker actions -------------------------------------------------------------------

    def open_draft(self, run_id: str, maker_id: str) -> WorkflowEvent:
        return self._transition(run_id, WorkflowAction.OPEN, maker_id)

    def assert_can_submit(self, maker_id: str) -> None:
        """Reject an unauthorised maker before any run evidence is created."""
        if self._policy.submitter_role not in self._directory.roles_of(maker_id):
            raise SegregationOfDutiesError(
                f"{maker_id} does not hold submitter role {self._policy.submitter_role}"
            )

    def submit(self, run_id: str, maker_id: str) -> WorkflowEvent:
        self.assert_can_submit(maker_id)
        return self._transition(run_id, WorkflowAction.SUBMIT, maker_id)

    # -- system action -------------------------------------------------------------------

    def quarantine(self, run_id: str) -> WorkflowEvent:
        run = self._store.fetch_run(run_id)
        if run.gate_decision is GateDecision.CLEAR:
            raise InvalidTransitionError(f"run {run_id} is CLEAR and cannot be quarantined")
        return self._transition(run_id, WorkflowAction.QUARANTINE, SYSTEM_ACTOR)

    # -- checker actions -----------------------------------------------------------------

    def release(self, run_id: str, checker_id: str) -> WorkflowEvent:
        self._assert_checker(run_id, checker_id)
        run = self._store.fetch_run(run_id)
        if run.gate_decision is not GateDecision.CLEAR:
            raise HardGateError(
                f"run {run_id} has gate decision {run.gate_decision.value}; "
                "only CLEAR runs can be released without exception"
            )
        return self._transition(run_id, WorkflowAction.RELEASE, checker_id)

    def approve_with_exception(
        self, run_id: str, checker_id: str, justification: str | None
    ) -> WorkflowEvent:
        self._assert_checker(run_id, checker_id)
        run = self._store.fetch_run(run_id)
        if run.blocker_count > 0 or run.gate_decision is GateDecision.BLOCKED:
            raise HardGateError(
                f"run {run_id} carries {run.blocker_count} BLOCKER finding(s); "
                "hard gates cannot be overridden by approval"
            )
        text = (justification or "").strip()
        if len(text) < self._policy.min_justification_length:
            raise JustificationRequiredError(
                "exception approval requires a justification of at least "
                f"{self._policy.min_justification_length} characters"
            )
        return self._transition(run_id, WorkflowAction.APPROVE_WITH_EXCEPTION, checker_id, text)

    # -- internals -----------------------------------------------------------------------

    def _assert_checker(self, run_id: str, checker_id: str) -> None:
        maker_id = self.maker_of(run_id)
        if maker_id is None:
            raise InvalidTransitionError(f"run {run_id} has not been submitted")
        if checker_id == maker_id:
            raise SelfApprovalError(f"{checker_id} submitted run {run_id} and cannot approve it")
        roles = self._directory.roles_of(checker_id)
        if self._policy.approver_role not in roles:
            raise SegregationOfDutiesError(
                f"{checker_id} does not hold approver role {self._policy.approver_role}"
            )
        conflicting = sorted(roles & self._policy.roles_incompatible_with_approval)
        if conflicting:
            raise SegregationOfDutiesError(
                f"{checker_id} holds role(s) incompatible with approval: {', '.join(conflicting)}"
            )

    def _transition(
        self,
        run_id: str,
        action: WorkflowAction,
        actor_id: str,
        justification: str | None = None,
    ) -> WorkflowEvent:
        with self._store.atomic():
            history = self.history(run_id)
            from_state = history[-1].to_state if history else None
            to_state = TRANSITIONS.get((from_state, action))
            if to_state is None:
                current = "none" if from_state is None else from_state.value
                raise InvalidTransitionError(
                    f"action {action.value} is not permitted from state {current}"
                )
            audit = self._store.append_audit_event(
                event_type=f"WORKFLOW_{action.value}",
                actor_id=actor_id,
                run_id=run_id,
                payload={
                    "from_state": None if from_state is None else from_state.value,
                    "to_state": to_state.value,
                    "justification": justification,
                },
            )
            event = WorkflowEvent(
                run_id=run_id,
                seq=len(history) + 1,
                from_state=from_state,
                to_state=to_state,
                action=action,
                actor_id=actor_id,
                justification=justification,
                created_at=utc_now_iso(),
                audit_event_hash=audit.event_hash,
            )
            self._store.insert_workflow_event(event)
        return event
