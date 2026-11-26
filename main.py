import os
import sys
import json
from typing import Any, Optional

from fastapi import FastAPI, Request, JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import model as gmodel

app = FastAPI(title="Golike Bridge", version="1.0.0")


class GolikeRequestBody(BaseModel):
    token: str
    method: str            # GET / POST / PUT …
    path: str            # raw API path, e.g. "/advertising/publishers/instagram/jobs"
    params: Optional[dict[str, Any]] = None
    json_body: Optional[dict[str, Any]] = Field(default=None, alias="json")   # key "json" in the request


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/golike/request")
async def golike_request(req: GolikeRequestBody) -> JSONResponse:
    try:
        auth = gmodel.GolikeAuth.from_token(
            req.token,
            enable_sig=True,
            fetch_session=True,
            captcha_solver=gmodel.auto_solve_captcha,
            captcha_max_attempts=3,
        )
        method = (req.method or "GET").upper()
        if method == "GET":
            resp = auth.get(req.path, params=req.params)
        else:
            resp = auth.post(req.path, json=req.json_body)
        return JSONResponse(content=resp.json())
    except Exception as exc:
        return JSONResponse(content={"_bridge_error": str(exc)})


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
