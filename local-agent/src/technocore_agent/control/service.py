from __future__ import annotations

import uuid

from ..policy.transport import ROOM_PATTERN
from .approval import ApprovalStore
from .drafts import DraftStore
from .operator import OperatorAuth, OperatorSession


class ControlPlane:
    """Trusted coordinator. Agent-facing code has no reference to this object."""

    def __init__(
        self,
        drafts: DraftStore,
        approvals: ApprovalStore,
        auth: OperatorAuth,
        signer,
        *,
        mode: str = "offline",
        identity_backup=None,
    ) -> None:
        self.drafts, self.approvals, self.auth, self.signer = drafts, approvals, auth, signer
        if mode not in {"offline", "live"}:
            raise ValueError("control-plane mode is invalid")
        self.mode = mode
        self._identity_backup = identity_backup

    @property
    def public_did(self) -> str:
        return self.signer.did

    def pending(self):
        return self.drafts.list({"PENDING"})

    def activity(self):
        return self.drafts.list({"APPROVED", "REJECTED", "EXPIRED", "CONSUMED"})

    def activity_result(self, draft_id: str) -> dict | None:
        getter = getattr(self.signer, "operation_record", None)
        return getter(draft_id) if getter is not None else None

    def create_operator_draft(
        self, room: str, text: str, session: OperatorSession, *, source: str
    ):
        self.auth.validate(session.session_id, session.csrf_token)
        if not isinstance(room, str) or not ROOM_PATTERN.fullmatch(room):
            raise ValueError("room must match the official Technocore room-name format")
        if source not in {
            "local-operator-compose",
            "local-onboarding-introduction",
            "local-contribution-record",
            "local-wallet-linkage-declaration",
        }:
            raise ValueError("draft source is not allowed")
        return self.drafts.create(
            f"operator-{uuid.uuid4()}", "sign_room", room, text, source
        )

    def create_identity_backup(
        self, session: OperatorSession, passphrase: str, confirmation: str
    ) -> dict[str, str]:
        self.auth.validate(session.session_id, session.csrf_token)
        if self._identity_backup is None:
            raise ValueError("identity backup is unavailable in this runtime")
        if passphrase != confirmation:
            raise ValueError("backup passphrases do not match")
        if not isinstance(passphrase, str) or len(passphrase) < 20:
            raise ValueError("use a unique backup passphrase of at least 20 characters")
        return self._identity_backup(passphrase)

    def reject(self, draft_id: str, session: OperatorSession):
        self.auth.validate(session.session_id, session.csrf_token)
        return self.drafts.transition(draft_id, "REJECTED")

    def approve_and_execute(self, draft_id: str, session: OperatorSession, fresh_passphrase: str):
        self.auth.validate(session.session_id, session.csrf_token)
        self.auth.reauthenticate(fresh_passphrase)
        draft = self.drafts.get(draft_id)
        if draft is None:
            raise ValueError("unknown draft")
        approval = self.approvals.for_draft(draft_id)
        if draft.status == "PENDING":
            approval = approval or self.approvals.create(
                draft, self.auth.session_hash(session.session_id)
            )
            draft = self.drafts.transition(draft_id, "APPROVED")
        if approval is None:
            raise ValueError("approved draft has no trusted approval")
        if approval.status == "APPROVED":
            approval = self.approvals.consume(approval.approval_id, draft)
        # Consumption is durable before signer access: crashes can deny service but never replay authority.
        if draft.status == "APPROVED":
            self.drafts.transition(draft_id, "CONSUMED")
        return self.signer.execute_room(draft.draft_id, draft.room, draft.cleaned_text, approval)
