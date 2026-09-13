from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from uuid import UUID

from app.db.session import get_db
from app.core.auth import get_current_user
from app.models.investigation import Investigation, IOC, MITREMapping, Evidence, InvestigationStatus
from app.modules.query_engine.elasticsearch_client import get_siem

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def dashboard_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate statistics for the dashboard."""
    # Total investigations
    inv_count = await db.scalar(
        select(func.count(Investigation.id))
    )
    # Completed investigations
    completed_count = await db.scalar(
        select(func.count(Investigation.id)).where(
            Investigation.status == InvestigationStatus.completed,
        )
    )
    # Total IOCs
    ioc_count = await db.scalar(
        select(func.count(IOC.id))
        .join(Investigation, IOC.investigation_id == Investigation.id)
    )
    # Total MITRE techniques
    mitre_count = await db.scalar(
        select(func.count(MITREMapping.id))
        .join(Investigation, MITREMapping.investigation_id == Investigation.id)
    )
    # Total events analyzed
    evidence_count = await db.scalar(
        select(func.count(Evidence.id))
        .join(Investigation, Evidence.investigation_id == Investigation.id)
    )
    # Failed login count (from evidence)
    failed_logins = await db.scalar(
        select(func.count(Evidence.id))
        .join(Investigation, Evidence.investigation_id == Investigation.id)
        .where(
            Evidence.event_action == "failed_login",
        )
    )
    # Unique source IPs
    unique_ips = await db.scalar(
        select(func.count(func.distinct(Evidence.source_ip)))
        .join(Investigation, Evidence.investigation_id == Investigation.id)
        .where(Evidence.source_ip.isnot(None))
    )

    # Recent investigations (last 10)
    recent_result = await db.execute(
        select(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(10)
    )
    recent = recent_result.scalars().all()

    # Top MITRE techniques
    top_mitre_result = await db.execute(
        select(MITREMapping.technique_id, MITREMapping.technique_name, func.count().label("count"))
        .join(Investigation, MITREMapping.investigation_id == Investigation.id)
        .group_by(MITREMapping.technique_id, MITREMapping.technique_name)
        .order_by(text("count DESC"))
        .limit(5)
    )
    top_mitre = [{"technique_id": r[0], "technique_name": r[1], "count": r[2]} for r in top_mitre_result]

    # Top source IPs
    top_ips_result = await db.execute(
        select(Evidence.source_ip, func.count().label("count"))
        .join(Investigation, Evidence.investigation_id == Investigation.id)
        .where(Evidence.source_ip.isnot(None))
        .group_by(Evidence.source_ip)
        .order_by(text("count DESC"))
        .limit(10)
    )
    top_ips = [{"ip": r[0], "count": r[1]} for r in top_ips_result]

    # SIEM health
    siem = get_siem()
    siem_health = await siem.health()

    return {
        "total_investigations": inv_count or 0,
        "completed_investigations": completed_count or 0,
        "total_iocs": ioc_count or 0,
        "total_mitre_techniques": mitre_count or 0,
        "total_evidence_analyzed": evidence_count or 0,
        "failed_login_count": failed_logins or 0,
        "unique_source_ips": unique_ips or 0,
        "recent_investigations": [
            {
                "id": str(inv.id),
                "query": inv.nl_query[:60],
                "result_count": inv.result_count,
                "status": inv.status.value,
                "created_at": inv.created_at.isoformat(),
            }
            for inv in recent
        ],
        "top_mitre_techniques": top_mitre,
        "top_source_ips": top_ips,
        "siem_health": siem_health,
    }

