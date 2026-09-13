from fastapi import APIRouter
from app.api.routes import auth, investigation, reports, dashboard, knowledge, agent

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(investigation.router)
api_router.include_router(reports.router)
api_router.include_router(dashboard.router)
api_router.include_router(knowledge.router)
api_router.include_router(agent.router)
