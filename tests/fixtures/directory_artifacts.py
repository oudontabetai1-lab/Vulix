"""Deterministic artifact exposure fixture with paired safe resources."""
import json
from fastapi import FastAPI, Request
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
ROOT_LISTING = '<title>Index of /</title><h1>Index of /</h1><pre><a href="alpha.txt">alpha.txt</a> 2026-01-01 12:00 <a href="beta.txt">beta.txt</a> 2026-01-02 12:00 <a href="safe/">safe/</a></pre>'
ROOT_SAFE = '<title>Index of /</title><h1>Index of /</h1><p>Product catalog</p>'
SAFE = '<title>Index of /safe/</title><p>Product catalog</p><script src="app.js"></script>'
app = FastAPI()

@app.get('/')
def root_listing():
    return HTMLResponse(ROOT_LISTING)

@app.get('/{path:path}')
def resource(path: str, request: Request):
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
    # Edge 1: 50KB 打ち切りスクリプトと安全ツイン
    if path == 'exposed/truncated-bundle.js':
        return PlainTextResponse('const a = 1;\n' * 4500 + '//# sourceMappingURL=truncated-bundle.js.map')
    if path == 'exposed/truncated-bundle.js.map':
        return Response(json.dumps({"version": 3, "sources": ["webpack:///src/secret-truncated.js"], "sourcesContent": ['const secret = "internal";']}), media_type='application/json')
    if path == 'exposed/truncated-inline.js':
        import base64
        inline_raw = json.dumps({"version": 3, "sources": ["webpack:///src/inline-secret.js"], "sourcesContent": ['const inlineKey = "sec";']})
        inline_ref = 'data:application/json;base64,' + base64.b64encode(inline_raw.encode()).decode()
        return PlainTextResponse('const a = 1;\n' * 4500 + '//# sourceMappingURL=' + inline_ref)
    if path == 'safe/truncated-safe.js':
        return PlainTextResponse('const a = 1;\n' * 4500)
    # Edge 2: 拡張子なしスクリプトリソースと安全ツイン
    if path == 'exposed/bundle':
        return PlainTextResponse('const a = 1;\n//# sourceMappingURL=bundle.map')
    if path == 'exposed/bundle.map':
        return Response(json.dumps({"version": 3, "sources": ["webpack:///src/secret-bundle.js"], "sourcesContent": ['const secret = "bundle-leak";']}), media_type='application/json')
    if path == 'safe/bundle':
        return PlainTextResponse('const a = 1;\n')
    if path == 'safe/catalog':
        return HTMLResponse('<html><body><h1>Catalog Directory</h1><p>Items</p></body></html>')
    # Edge 3: 機微クエリ付き検証ターゲットと安全ツイン
    if path == 'exposed/query-map.js.map':
        if request.query_params.get('token') == 'valid_token':
            return Response(json.dumps({"version": 3, "sources": ["webpack:///src/secret-query.js"], "sourcesContent": ['const token = "secret";']}), media_type='application/json')
        return PlainTextResponse('Forbidden', status_code=403)
    if path == 'safe/query-map.js.map':
        return Response(json.dumps({"version": 3, "sources": ["public.js"], "mappings": ""}), media_type='application/json')
    # Edge 4: 直接観測されたバックアップと安全ツイン
    if path == 'exposed/site-backup.zip':
        return Response(b'PK\x03\x04' + b'\x00' * 200, media_type='application/zip')
    if path == 'exposed/site-backup.tar.gz':
        return Response(b'\x1f\x8b' + b'\x00' * 200, media_type='application/gzip')
    if path == 'exposed/app.js.old':
        return PlainTextResponse('const oldSecret = "db_pass";')
    if path == 'exposed/app.js~':
        return PlainTextResponse('const tildeSecret = "api_key";')
    if path in ('safe/site-backup.zip', 'safe/site-backup.tar.gz', 'safe/app.js.old', 'safe/app.js~'):
        return PlainTextResponse('Not found', status_code=404)
    # Edge 5: 1MB 超アーティファクトの先頭維持と安全ツイン
    if path == 'exposed/oversized-backup.zip':
        return Response(b'PK\x03\x04' + b'\x00' * 1_200_000, media_type='application/zip')
    if path == 'exposed/oversized-backup.tar.gz':
        return Response(b'\x1f\x8b' + b'\x00' * 1_200_000, media_type='application/gzip')
    if path == 'exposed/oversized-backup.tar':
        return Response(b'\x00' * 257 + b'ustar' + b'\x00' * 1_200_000, media_type='application/x-tar')
    if path in ('safe/oversized-file.bin', 'safe/oversized-backup.zip', 'safe/oversized-data.json', 'safe/oversized-image.png'):
        # 1MB を超える無害な非アーカイブレスポンス（先頭 262 バイトにアーカイブシグネチャを含まない大きな JSON / octet-stream / 画像）
        if path.endswith('.png'):
            return Response(b'\x89PNG\r\n\x1a\n' + b'\x00' * 1_200_000, media_type='image/png')
        benign_json = json.dumps({"status": "ok", "message": "benign payload", "items": ["data"] * 1000}).encode()
        benign_body = benign_json + b' ' * (1_200_000 - len(benign_json))
        media_type = 'application/json' if path.endswith('.json') else 'application/octet-stream'
        return Response(benign_body, media_type=media_type)
    return PlainTextResponse('Not found', status_code=404)

def create_app():
    return app
