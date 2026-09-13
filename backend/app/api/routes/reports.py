from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from uuid import UUID

from app.db.session import get_db
from app.core.auth import get_current_user, require_analyst
from app.models.investigation import Investigation, Report, IOC, MITREMapping, Evidence
from app.modules.reporting.report_builder import build_report
from app.modules.reporting.pdf_exporter import export_to_pdf
from app.modules.threat_analysis.event_correlator import AttackPattern
from app.modules.mitre.attack_mapper import MITRETechniqueResult, map_to_mitre
from app.modules.mitre.timeline_builder import build_timeline

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate/{investigation_id}")
async def generate_report(
    investigation_id: str,
    current_user=Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Generate and store a structured incident report for an investigation."""
    # Load investigation
    result = await db.execute(select(Investigation).where(Investigation.id == UUID(investigation_id)))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Load related data
    iocs_result = await db.execute(select(IOC).where(IOC.investigation_id == UUID(investigation_id)))
    iocs = iocs_result.scalars().all()

    mitre_result = await db.execute(select(MITREMapping).where(MITREMapping.investigation_id == UUID(investigation_id)))
    mitre_rows = mitre_result.scalars().all()

    evidence_result = await db.execute(select(Evidence).where(Evidence.investigation_id == UUID(investigation_id)))
    evidence_rows = evidence_result.scalars().all()

    # Reconstruct hits from evidence
    hits = [
        {
            "_id": ev.log_id or str(ev.id),
            "_source": ev.raw_log or {
                "@timestamp": ev.timestamp,
                "source": {"ip": ev.source_ip},
                "user": {"name": ev.username},
                "event": {"action": ev.event_action, "severity": ev.severity},
            },
        }
        for ev in evidence_rows
    ]

    # Reconstruct patterns (minimal, from MITRE confidence)
    patterns = []
    mitre_objects = []
    for m in mitre_rows:
        mt = MITRETechniqueResult(
            technique_id=m.technique_id,
            technique_name=m.technique_name,
            tactic=m.tactic,
            sub_technique_id=m.sub_technique_id,
            sub_technique_name=m.sub_technique_name,
            confidence=m.confidence,
            evidence_count=m.evidence_count,
            description=m.description or "",
            source_pattern=m.technique_id,
        )
        mitre_objects.append(mt)

    timeline = build_timeline(hits)
    iocs_list = [
        {"type": ioc.type.value, "value": ioc.value, "occurrence_count": ioc.occurrence_count}
        for ioc in iocs
    ]

    # Load analyst name
    from app.models.user import User
    user_result = await db.execute(select(User).where(User.id == UUID(current_user.user_id)))
    user = user_result.scalar_one_or_none()
    analyst_name = user.name if user else "SOC Analyst"

    report_data = await build_report(
        investigation_id=investigation_id,
        nl_query=inv.nl_query,
        generated_query=inv.generated_query or {},
        elasticsearch_query=inv.elasticsearch_query or {},
        hits=hits,
        result_count=inv.result_count,
        iocs=iocs_list,
        patterns=patterns,
        mitre=mitre_objects,
        timeline=timeline,
        explanation=inv.explanation or "",
        analyst_name=analyst_name,
    )

    # Store report in DB
    existing = await db.execute(select(Report).where(Report.investigation_id == UUID(investigation_id)))
    existing_report = existing.scalar_one_or_none()

    if existing_report:
        existing_report.content_json = report_data
        existing_report.title = report_data.get("investigation", {}).get("title", "Incident Report")
        report_id = str(existing_report.id)
    else:
        new_report = Report(
            investigation_id=UUID(investigation_id),
            user_id=UUID(current_user.user_id),
            title=report_data.get("investigation", {}).get("title", "Incident Report"),
            content_json=report_data,
        )
        db.add(new_report)
        await db.flush()
        report_id = str(new_report.id)

    return {"report_id": report_id, "report": report_data}


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Report).where(Report.id == UUID(report_id)))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.content_json


@router.get("/{report_id}/pdf")
async def download_pdf(
    report_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate and stream a PDF version of the report."""
    result = await db.execute(select(Report).where(Report.id == UUID(report_id)))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = export_to_pdf(report.content_json)
    filename = f"siem_report_{report_id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
