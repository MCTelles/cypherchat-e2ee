from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from seguranca_auditoria.config import get_settings
from seguranca_auditoria.routers import auth

get_settings()  # fail at startup on missing/invalid configuration (e.g. weak JWT secret)

app = FastAPI()
app.include_router(auth.router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # The default handler echoes the rejected input (passwords included).
    errors = [
        {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/health")
def health_check():
    return {"status": "ok"}
