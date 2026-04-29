from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import logging

from app.config import settings
from app.api.routes import router
from app.database.connection import init_db
from app.utils.logger import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="AIOps System with ML-powered Alert Management"
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Routes
    app.include_router(router)
    
    # Static files (for production, use nginx)
    if settings.SERVE_STATIC:
        static_path = Path(__file__).parent.parent / "static"
        if static_path.exists():
            app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
            
            @app.get("/")
            async def serve_frontend():
                from fastapi.responses import FileResponse
                return FileResponse(static_path / "index.html")
    
    # Initialize database
    @app.on_event("startup")
    async def startup_event():
        init_db()
        logger.info("Application started successfully")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("Application shutting down")
    
    return app