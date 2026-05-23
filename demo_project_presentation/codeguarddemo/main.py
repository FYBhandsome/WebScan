import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from tortoise.contrib.fastapi import register_tortoise
from core.config import settings
from api.audit_api import router

app = FastAPI(title=settings.APP_NAME)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(router)


@app.get("/")
async def index():
    return FileResponse("static/index.html")


db_url = os.getenv("CODE_GUARD_DB_URL", settings.DB_URL)

register_tortoise(
    app,
    db_url=db_url,
    modules={"models": ["models.models"]},
    generate_schemas=True,
    add_exception_handlers=True
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
