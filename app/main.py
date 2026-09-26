from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import audit, auth, roles, system, users
from app.archives.router import router as archives_router
from app.archives.extended_router import router as archive_operations_router
from app.archives.secrecy_router import router as secrecy_router
from app.archives.secrecy import sweep_expired
from app.core.errors import DomainError
from app.database import close_connection, get_connection, init_db, transaction


@asynccontextmanager
async def lifespan(app: FastAPI):
    del app
    init_db()
    # 过期授权只按数据库时间判定；每次启动先清理，保证重启后不会复活。
    with transaction(immediate=True) as connection:
        sweep_expired(connection)
    yield
    close_connection()


app = FastAPI(title="专利与技术秘密档案管理服务", version="1.0.0", lifespan=lifespan)


@app.exception_handler(DomainError)
async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "context": exc.context}},
    )


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(audit.router)
app.include_router(system.router)
app.include_router(archives_router)
app.include_router(archive_operations_router)
app.include_router(secrecy_router)


@app.get("/")
def root() -> dict:
    return {"service": "专利与技术秘密档案管理服务", "version": "1.0.0"}
