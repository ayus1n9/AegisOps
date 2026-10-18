"""FastAPI Application entrypoint for SecureFlow Python Security Service."""
import logging
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
)
from app.service import evaluate_security_target

# Configure safe structured logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secureflow-python-service")

app = FastAPI(
    title="SecureFlow Python Security Microservice",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,  # Disabled to minimize attack surface
)

# Secure CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors safely without echoing internal stacks."""
    logger.warning("Invalid request payload received: %s", exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "Input validation failed. Check request parameters.",
            "details": [
                {"field": ".".join(str(loc) for loc in err["loc"]), "issue": err["msg"]}
                for err in exc.errors()
            ],
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Fallback safe exception handler to avoid leaking traceback to caller."""
    logger.error("Unhandled server exception: %s", exc, exc_info=False)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred while processing the request.",
        },
    )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check():
    """Liveness probe."""
    return HealthResponse(
        status="healthy",
        service="secureflow-python-service",
        version="1.0.0",
    )


@app.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_check():
    """Readiness probe."""
    return {"status": "ready", "ready": True}


@app.post("/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_200_OK)
async def analyze_target(request: AnalyzeRequest):
    """Perform security compliance evaluation on target artifact."""
    logger.info(
        "Evaluating artifact: target=%s type=%s env=%s",
        request.target_name,
        request.artifact_type,
        request.environment,
    )
    result = evaluate_security_target(request)
    return result
