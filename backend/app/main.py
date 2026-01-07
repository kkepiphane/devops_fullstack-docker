"""
Point d'entrée principal de l'application FastAPI
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from prometheus_client import Counter, Histogram, make_asgi_app
import time
import logging

from app.config import settings
from app.core.logging import setup_logging
from app.api.v1 import auth, users
from app.database import engine, Base

# Configuration du logging
setup_logging()
logger = logging.getLogger(__name__)

# Création des tables (en production, utiliser Alembic)
# Base.metadata.create_all(bind=engine)

# Métriques Prometheus
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)
REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

# Initialisation de l'application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="API Backend Full-Stack avec FastAPI",
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT == "development" else None,
)

# Middlewares de sécurité
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware de métriques
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware pour collecter les métriques"""
    start_time = time.time()
    
    response = await call_next(request)
    
    duration = time.time() - start_time
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    REQUEST_DURATION.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)
    
    # Ajouter le temps de traitement dans les headers
    response.headers["X-Process-Time"] = str(duration)
    
    return response

# Middleware de logging
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Middleware pour logger les requêtes"""
    logger.info(
        f"Request: {request.method} {request.url.path}",
        extra={
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else None
        }
    )
    
    response = await call_next(request)
    
    logger.info(
        f"Response: {response.status_code}",
        extra={
            "status_code": response.status_code,
            "method": request.method,
            "path": request.url.path
        }
    )
    
    return response

# Gestionnaires d'erreurs
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Gestionnaire pour les erreurs de validation"""
    logger.warning(
        f"Validation error: {exc.errors()}",
        extra={"path": request.url.path, "errors": exc.errors()}
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": exc.errors(),
            "message": "Validation error"
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Gestionnaire pour les erreurs générales"""
    logger.error(
        f"Unhandled exception: {str(exc)}",
        exc_info=True,
        extra={"path": request.url.path}
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "message": str(exc) if settings.ENVIRONMENT == "development" else "An error occurred"
        }
    )

# Routes
@app.get("/", tags=["root"])
async def root():
    """Endpoint racine"""
    return {
        "message": "Welcome to FastAPI Backend",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT
    }

@app.get("/health", tags=["health"])
async def health_check():
    """Healthcheck pour Docker et monitoring"""
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "timestamp": time.time()
    }

# Inclusion des routers API
app.include_router(
    auth.router,
    prefix="/v1/auth",
    tags=["authentication"]
)

app.include_router(
    users.router,
    prefix="/v1/users",
    tags=["users"]
)

# Monter l'application Prometheus pour les métriques
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Événements de startup/shutdown
@app.on_event("startup")
async def startup_event():
    """Actions au démarrage de l'application"""
    logger.info(
        f"Starting {settings.PROJECT_NAME} in {settings.ENVIRONMENT} mode",
        extra={"environment": settings.ENVIRONMENT}
    )

@app.on_event("shutdown")
async def shutdown_event():
    """Actions à l'arrêt de l'application"""
    logger.info(
        f"Shutting down {settings.PROJECT_NAME}",
        extra={"environment": settings.ENVIRONMENT}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower()
    )