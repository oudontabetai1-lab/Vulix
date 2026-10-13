"""Deterministic artifact exposure fixture with paired safe resources."""
import json
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

EXPECTED_FINDINGS = [
    {"check": "directory_artifacts", "path": "/exposed/", "field": "(directory_listing)", "note": "Autoindex exposes file entries"},
    {"check": "directory_artifacts", "path": "/exposed/app.js.bak", "field": "(derived_backup)", "note": "Observed script has a public source backup"},
    {"check": "directory_artifacts", "path": "/exposed/app.js.map", "field": "(source_map)", "note": "Source map includes private source content"},
]
SAFE_ENDPOINTS = [
    {"path": "/safe/", "field": "(directory_listing)", "note": "Catalog heading alone is not autoindex"},
    {"path": "/safe/app.js.bak", "field": "(derived_backup)", "note": "Backup is absent"},
    {"path": "/safe/app.js.map", "field": "(source_map)", "note": "Public map has no private paths or source content"},
]
LISTING = '<title>Index of /exposed/</title><h1>Index of /exposed/</h1><pre><a href="../">../</a><a href="app.js">app.js</a> 2026-01-01 12:00 <a href="readme.txt">readme.txt</a></pre>'
SAFE = '<title>Index of /safe/</title><p>Product catalog</p><script src="app.js"></script>'
app = FastAPI()

@app.get('/{path:path}')
def resource(path: str):
    if path == 'exposed/':
        return HTMLResponse(LISTING)
    if path == 'safe/':
        return HTMLResponse(SAFE)
    if path in ('exposed/app.js', 'safe/app.js'):
        return PlainTextResponse('const answer = 42;\n//# sourceMappingURL=app.js.map')
    if path == 'exposed/app.js.bak':
        return PlainTextResponse('const privateSetting = "internal";')
    if path == 'exposed/app.js.map':
        return Response(json.dumps({"version": 3, "sources": ["webpack:///src/private.js"], "sourcesContent": ['const privateSetting = "internal";']}), media_type='application/json')
    if path == 'safe/app.js.map':
        return Response(json.dumps({"version": 3, "sources": ["public.js"], "mappings": ""}), media_type='application/json')
    return PlainTextResponse('Not found', status_code=404)
