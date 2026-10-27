from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    telemetry,
    readiness,
    detection,
    intelligence,
    prioritization,
    investigation,
    vault
)

api_router = APIRouter()

api_router.include_router(telemetry.router, tags=["telemetry"])
api_router.include_router(readiness.router, tags=["readiness"])
api_router.include_router(detection.router, tags=["detection"])
api_router.include_router(intelligence.router, tags=["intelligence"])
api_router.include_router(prioritization.router, tags=["prioritization"])
api_router.include_router(investigation.router, tags=["investigation"])
api_router.include_router(vault.router, tags=["vault"])
