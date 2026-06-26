import json
import os
from dataclasses import dataclass, field
from typing import Optional

import httpx
from fastapi import Request, Response
from starlette.responses import JSONResponse
from starlette.status import HTTP_502_BAD_GATEWAY, HTTP_504_GATEWAY_TIMEOUT


FORBIDDEN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>403 Forbidden &middot; IAM Gateway</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',system-ui,-apple-system,sans-serif}}
  body{{min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);color:#e2e8f0}}
  .card{{background:rgba(255,255,255,.06);backdrop-filter:blur(24px);border:1px solid rgba(255,255,255,.1);
        border-radius:24px;padding:48px 40px;width:420px;max-width:90vw;text-align:center}}
  .card i{{font-size:48px;color:#ef4444;margin-bottom:16px}}
  .card h1{{font-size:28px;font-weight:700;margin-bottom:8px}}
  .card p{{color:#94a3b8;font-size:14px;line-height:1.6;margin-bottom:24px}}
  .card .reason{{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);border-radius:10px;
                padding:10px 16px;font-size:13px;color:#fca5a5;margin-bottom:24px}}
  .btn{{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border:none;border-radius:12px;
       background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:14px;font-weight:600;
       text-decoration:none;cursor:pointer;transition:all .3s}}
  .btn:hover{{transform:translateY(-2px);box-shadow:0 8px 25px rgba(99,102,241,.35)}}
  .btn-secondary{{background:rgba(148,163,184,.1);color:#94a3b8}}
  .btn-secondary:hover{{background:rgba(148,163,184,.2);box-shadow:none;transform:none}}
</style>
</head>
<body>
<div class="card">
  <i class="fa-solid fa-ban"></i>
  <h1>Access Denied</h1>
  <p>You don't have permission to access this resource.</p>
  <div class="reason">{reason}</div>
  <a href="/login" class="btn" onclick="localStorage.clear()"><i class="fa-solid fa-right-to-bracket"></i> Re-authenticate</a>
</div>
</body>
</html>"""


@dataclass
class ProxyRoute:
    prefix: str
    backend: str
    resource_id: str
    strip_prefix: bool = True
    timeout: int = 30
    preserve_host: bool = False
    inject_identity: bool = True


class ProxyRouter:
    def __init__(self):
        self._routes: list[ProxyRoute] = []
        self._client: Optional[httpx.AsyncClient] = None

    def configure(self, routes: list[ProxyRoute]):
        self._routes = routes

    def load_from_env(self):
        raw = os.environ.get("PROXY_ROUTES", "")
        if not raw:
            return
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            return
        routes = []
        for entry in entries:
            routes.append(ProxyRoute(
                prefix=entry.get("prefix", ""),
                backend=entry.get("backend", ""),
                resource_id=entry.get("resource", ""),
                strip_prefix=entry.get("strip_prefix", True),
                timeout=entry.get("timeout", 30),
                preserve_host=entry.get("preserve_host", False),
                inject_identity=entry.get("inject_identity", True),
            ))
        self._routes = routes

    def match(self, path: str) -> Optional[ProxyRoute]:
        for route in self._routes:
            if path.startswith(route.prefix):
                return route
        return None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            limits = httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30,
            )
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=False,
                limits=limits,
            )
        return self._client

    async def forward(
        self,
        request: Request,
        route: ProxyRoute,
        identity: Optional[dict] = None,
    ) -> Response:
        path = request.url.path
        if route.strip_prefix:
            remaining = path[len(route.prefix):]
            target_path = remaining if remaining.startswith("/") else f"/{remaining}"
        else:
            target_path = path

        query = request.url.query
        target_url = f"{route.backend.rstrip('/')}{target_path}"
        if query:
            target_url += f"?{query}"

        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower in (
                "host", "connection", "transfer-encoding",
                "content-length", "keep-alive",
                "cookie", "x-api-key",
            ):
                continue
            if key_lower.startswith("x-forwarded-"):
                continue
            if key_lower.startswith("x-authenticated-"):
                continue
            headers[key] = value

        if route.inject_identity and identity:
            headers["X-Authenticated-User"] = identity.get("username", "")
            headers["X-Authenticated-Role"] = identity.get("role", "")
            if identity.get("email"):
                headers["X-Authenticated-Email"] = identity["email"]
            if identity.get("groups"):
                headers["X-Authenticated-Groups"] = ",".join(identity["groups"])

        client_host = request.client.host if request.client else "unknown"
        headers["X-Forwarded-For"] = client_host
        headers["X-Forwarded-Proto"] = request.url.scheme
        headers["X-Forwarded-Host"] = request.headers.get("host", "")
        headers["X-Forwarded-Prefix"] = route.prefix

        if not route.preserve_host:
            headers["Host"] = route.backend.split("://")[-1].split("/")[0]

        client = await self._get_client()

        try:
            body = await request.body()
            upstream_request = client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=route.timeout,
            )
            upstream_response = await client.send(
                upstream_request,
                stream=True,
            )

            response_headers = {}
            excluded = {
                "transfer-encoding", "content-encoding",
                "content-length", "connection", "keep-alive",
                "set-cookie",
            }
            for key, value in upstream_response.headers.items():
                if key.lower() not in excluded:
                    response_headers[key] = value

            return Response(
                content=await upstream_response.aread(),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
            )

        except httpx.TimeoutException:
            return JSONResponse(
                status_code=HTTP_504_GATEWAY_TIMEOUT,
                content={"error": "Gateway Timeout", "detail": f"Upstream timed out after {route.timeout}s"},
            )
        except httpx.RequestError as exc:
            return JSONResponse(
                status_code=HTTP_502_BAD_GATEWAY,
                content={"error": "Bad Gateway", "detail": str(exc)},
            )

    async def shutdown(self):
        if self._client:
            await self._client.aclose()
            self._client = None
