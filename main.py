# Q:/Automation/services/platforms/main.py
import os
import sys
import json
from typing import Any, Optional, Mapping, Union

from fastapi import FastAPI, Request, JSONResponse
from pydantic import BaseModel, Field

# Tự động thêm thư mục model.py vào path search
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import model as gmodel          # model.py (Python source) được load trực tiếp

app = FastAPI(title="Golike Bridge", version="1.0.0")

class GolikeRequestBody(BaseModel):
    token: str
    method: str               # GET /POST /PUT …
    path: str                 # raw API path, e.g. "/advertising/publishers/instagram/jobs"
    params: Optional[dict[str, Any]] = None
    json_body: Optional[dict[str, Any]] = Field(default=None, alias="json")  # key "json" trong request

@app.get("/health")
def health() -> dict[str, str]:
    """Health check cho Render / Cloudflare Worker."""
    return {"status": "ok"}

@app.post("/golike/request")
async def golike_request(req: GolikeRequestBody) -> JSONResponse:
    """
    Call GolikeAuth (từ model.GolikeAuth.from_token…) và thực hiện GET/POST.
    """
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
        data = resp.json()
        return JSONResponse(content=data)
    except Exception as exc:
        return JSONResponse(content={"_bridge_error": str(exc)})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
