from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.app.db.session import get_db
from backend.app.db.models import InvestigationCase
from backend.app.schemas.api_schemas import UpdateInvestigationCaseInput
from backend.app.engines.investigation_engine import investigation_engine

router = APIRouter()

@router.get("/investigation/cases")
async def get_all_cases(
    status: Optional[str] = None,
    limit: int = Query(50, le=100),
    db: AsyncSession = Depends(get_db)
):
    query = select(InvestigationCase).order_by(desc(InvestigationCase.updated_at)).limit(limit)
    if status:
        query = query.where(InvestigationCase.status == status)
    result = await db.execute(query)
    cases = result.scalars().all()
    return cases

@router.get("/investigation/case/{case_id}")
async def get_case_detail(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    details = await investigation_engine.get_case_details(db, case_id)
    if not details:
        raise HTTPException(status_code=404, detail=f"Investigation case {case_id} not found")
    return details

@router.put("/investigation/case/{case_id}")
async def update_case_notes_and_status(
    case_id: str,
    payload: UpdateInvestigationCaseInput,
    db: AsyncSession = Depends(get_db)
):
    try:
        updated = await investigation_engine.update_notes(
            db=db,
            case_id=case_id,
            notes=payload.analyst_notes,
            status=payload.status
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return updated

@router.get("/investigation/case/{case_id}/report.json")
async def download_case_json_report(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    report_dict = await investigation_engine.generate_json_report(db, case_id)
    if "error" in report_dict:
        raise HTTPException(status_code=404, detail=report_dict["error"])
    return report_dict

@router.get("/investigation/case/{case_id}/report.pdf")
async def download_case_pdf_report(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    try:
        pdf_bytes = await investigation_engine.generate_pdf_report(db, case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="THREXIS_Investigation_Report_{case_id}.pdf"'}
    )
