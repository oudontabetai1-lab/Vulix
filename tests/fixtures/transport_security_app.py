"""Read-only transport twins and an isolated, disposable method fixture."""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

EXPECTED_FINDINGS = [
    {"check": "transport_security", "path": "/status", "field": None,
     "note": "HTTP document is served without upgrading to HTTPS"},
    {"check": "transport_security", "path": "/mixed", "field": None,
     "note": "HTTPS HTML document declares an http script"},
]
SAFE_ENDPOINTS = [
    {"check": "transport_security", "path": "/status-safe", "field": None,
     "note": "HTTP first hop redirects to the HTTPS document"},
    {"check": "transport_security", "path": "/api/example-safe", "field": None,
     "note": "HTTPS JSON body containing an http script-like string is not an HTML document"},
    {"check": "transport_security", "path": "/mixed-text-safe", "field": None,
     "note": "HTTPS HTML shows http script markup only as textarea/title text"},
]


def create_app():
    app = FastAPI(title="Transport security fixture")
    disposable = {}

    @app.get("/")
    async def index():
        return HTMLResponse('<a href="/status">Legacy status</a><a href="/status-safe">Secure status</a>')

    @app.get("/status")
    async def status():
        return HTMLResponse("<p>Service available</p>")

    @app.get("/status-safe")
    async def status_safe(request: Request):
        if request.url.scheme == "http":
            return Response(status_code=308, headers={"Location": str(request.url.replace(scheme="https"))})
        return HTMLResponse("<p>Service available</p>")

    @app.get("/api/example-safe")
    async def api_example_safe():
        return JSONResponse({"example": '<script src="http://cdn.test/example.js"></script>'})

    @app.get("/mixed-text-safe")
    async def mixed_text_safe():
        return HTMLResponse('<title><script src="http://cdn.test/example.js"></script></title>'
                            '<textarea><script src="http://cdn.test/example.js"></script></textarea>')

    @app.get("/mixed")
    async def mixed():
        return HTMLResponse('<script src="http://cdn.test/example.js"></script>')

    @app.api_route("/methods", methods=["GET", "OPTIONS", "TRACE", "CONNECT", "PROPFIND"])
    async def methods(request: Request):
        method = request.method
        if method == "GET":
            for header in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
                if request.headers.get(header) == "OPTIONS":
                    method = "OPTIONS"
        if method == "OPTIONS":
            return Response(status_code=204, headers={"Allow": "GET, OPTIONS, TRACE, CONNECT, PROPFIND, PUT", "DAV": "1"})
        if method == "TRACE":
            return Response(content="TRACE /methods HTTP/1.1\r\nX-Xst-Probe: " + request.headers.get("X-Xst-Probe", ""),
                            media_type="message/http")
        if method == "PROPFIND":
            return Response(status_code=207, media_type="application/xml", content=
                '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/methods</d:href>'
                '<d:propstat><d:prop><d:supported-method-set><d:supported-method>'
                '<d:method name="PROPFIND"/></d:supported-method></d:supported-method-set>'
                '</d:prop></d:propstat></d:response></d:multistatus>')
        return Response(content="method resource")

    @app.api_route("/disposable/{key}", methods=["GET", "PUT", "PATCH", "DELETE"])
    async def disposable_item(key: str, request: Request):
        if request.method == "PUT":
            disposable[key] = await request.body()
            return Response(status_code=201)
        if key not in disposable:
            return Response(status_code=404)
        if request.method == "PATCH":
            disposable[key] = await request.body()
            return Response(status_code=204)
        if request.method == "DELETE":
            del disposable[key]
            return Response(status_code=204)
        return Response(content=disposable[key])

    return app
