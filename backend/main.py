from fastapi import FastAPI

from app.core.config import settings
from app.api.v1.api import api_router as api_router_v1

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.APP_V1_STR}/openapi.json"
)

app.include_router(api_router_v1, prefix=settings.APP_V1_STR)

@app.get("/", tags=["Health Check"])
async def read_root():
    """ Root endpoint """
    return {"message": f"Welcome to {settings.PROJECT_NAME}. Go to /docs for API documentation."}