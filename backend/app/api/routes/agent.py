"""Agentic investigation API routes (Phase 3 + Phase 6 human-in-the-loop + Observability)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from uuid import UUID
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.core.auth import require_analyst, get_current_user
from app.core.observability import get_metrics_collector
from app.models.investigation import Conversation
from app.modules.agent.investigation_agent import run_three_stage_investigation

router = APIRouter(prefix="/agent", tags=["agent"])

# In-memory pending approvals & paused investigations
_pending_approvals: dict[str, dict] = {}
_paused_investigations: dict[str, dict] = {}


class AgentInvestigateRequest(BaseModel):
    conversation_id: str | None = None
    query: str
    require_approval: bool = False
    approved_steps: list[str] | None = None
    approval_token: str | None = None


class ApprovalRequest(BaseModel):
    approval_token: str
    approved_steps: list[str] | None = None
    reject: bool = False


class PauseResumeRequest(BaseModel):
    investigation_id: str


@router.post("/investigate")
async def agent_investigate(
    req: AgentInvestigateRequest,
    current_user=Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    conversation_id = req.conversation_id
    if conversation_id:
        result = await db.execute(
            select(Conversation).where(Conversation.id == UUID(conversation_id))
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Conversation not found")
    else:
        conv = Conversation(user_id=UUID(current_user.user_id), title=req.query[:100])
        db.add(conv)
        await db.flush()
        conversation_id = str(conv.id)

    if req.approval_token:
        pending = _pending_approvals.pop(req.approval_token, None)
        if not pending:
            raise HTTPException(status_code=404, detail="Approval token expired or invalid")
        req.approved_steps = req.approved_steps or pending.get("planned_steps")
        req.require_approval = False

    state = await run_three_stage_investigation(
        nl_query=req.query,
        conversation_id=conversation_id,
    )

    response = state.model_dump()
    response["conversation_id"] = conversation_id

    return response


@router.post("/approve")
async def approve_agent_plan(
    req: ApprovalRequest,
    current_user=Depends(require_analyst),
):
    pending = _pending_approvals.get(req.approval_token)
    if not pending:
        raise HTTPException(status_code=404, detail="Approval token not found")

    if req.reject:
        _pending_approvals.pop(req.approval_token, None)
        return {"ok": True, "status": "rejected"}

    return {
        "ok": True,
        "status": "approved",
        "approval_token": req.approval_token,
        "planned_steps": req.approved_steps or pending.get("planned_steps"),
        "message": "Re-submit /agent/investigate with approval_token and approved_steps",
    }


@router.post("/pause")
async def pause_investigation(
    req: PauseResumeRequest,
    current_user=Depends(require_analyst),
):
    _paused_investigations[req.investigation_id] = {"status": "paused", "user_id": current_user.user_id}
    return {"ok": True, "investigation_id": req.investigation_id, "status": "paused"}


@router.post("/resume")
async def resume_investigation(
    req: PauseResumeRequest,
    current_user=Depends(require_analyst),
):
    info = _paused_investigations.pop(req.investigation_id, None)
    if not info:
        raise HTTPException(status_code=404, detail="Paused investigation not found")
    return {"ok": True, "investigation_id": req.investigation_id, "status": "resumed"}


@router.get("/metrics")
async def get_metrics(
    current_user=Depends(get_current_user),
):
    collector = get_metrics_collector()
    return collector.get_summary()
