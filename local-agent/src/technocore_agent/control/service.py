from __future__ import annotations

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
    ) -> None:
        self.drafts, self.approvals, self.auth, self.signer = drafts, approvals, auth, signer
        if mode not in {"offline", "live"}:
            raise ValueError("control-plane mode is invalid")
        self.mode = mode

    @property
    def public_did(self) -> str:
        return self.signer.did

    def pending(self):
        return self.drafts.list({"PENDING"})

    def activity(self):
        return self.drafts.list({"APPROVED", "REJECTED", "EXPIRED", "CONSUMED"})

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
