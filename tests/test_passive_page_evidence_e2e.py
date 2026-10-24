"""Production ScanEngine / real Chromium HTTP twins; each launch is a fresh process."""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from tests.test_shared_probe_evidence import make_engine, rows
from tests.test_passive_page_evidence import SAFE

pytestmark = pytest.mark.skipif(os.environ.get("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 required")


@pytest.fixture(scope="module")
def passive_server():
    app = FastAPI()
    visits = {}
    @app.get('/{kind}')
    async def page(kind: str):
        visits[kind] = visits.get(kind, 0) + 1
        headers = dict(SAFE) if kind == "safe" else {}
        headers["set-cookie"] = "session=passive-private-cookie; HttpOnly"
        return HTMLResponse('<html><head><title>Passive twin</title></head><body>password=passive-private-body</body></html>',
                            headers=headers, status_code=500 if kind == "error" else 200)
    sock = socket.socket(); sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True); thread.start()
    deadline = time.monotonic() + 5
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline
        time.sleep(.01)
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}", visits
    finally:
        server.should_exit = True; thread.join(timeout=5); sock.close()
        assert not thread.is_alive()


async def scan(url, output, resume=False, mode="normal"):
    from wscan.scanners.security_headers import SecurityHeadersScanner
    from wscan.scanners.base import finding_dict_confirmed
    engine = make_engine(url, "clickjacking", output, timeout=2,
                         resume_dir=str(output) if resume else "")
    engine.checks.append("security_headers")
    engine.scanners["security_headers"] = SecurityHeadersScanner(engine)
    if mode == "logger":
        engine.request_logger.probe_ledger._path = Path(output) / 'missing' / 'probe_attempts.jsonl'
    await asyncio.wait_for(engine.run(), timeout=90)
    records = rows(engine.request_logger)
    import hashlib, wscan.engine
    metrics = dict(engine_source=wscan.engine.__file__,
        engine_sha256=hashlib.sha256(Path(wscan.engine.__file__).read_bytes()).hexdigest(), candidate=len(engine.all_findings),
        confirmed=sum(finding_dict_confirmed(f.to_dict()) for f in engine.all_findings),
        by_check={c:sum(f.check_type==c for f in engine.all_findings) for c in engine.checks},
        completion=engine.evidence_completion(),
        api_requests=sum(r['actor']=='api_get_capture' and (r['record_kind']=='request'
            or r['record_kind']=='legacy' and r.get('response') is None) for r in records),
        http_count=engine.request_logger.http_count)
    Path(output, 'passive-metrics.json').write_text(json.dumps(metrics, indent=2))


def launch(url, output, *, resume=False, mode="normal"):
    output.mkdir(parents=True, exist_ok=resume)
    code = 'import asyncio,sys,os;sys.path.insert(0,os.environ.get("WSCAN_PASSIVE_BASELINE_SOURCE",os.getcwd()));import wscan;sys.path.pop(0);from tests.test_passive_page_evidence_e2e import scan;asyncio.run(scan(sys.argv[1],sys.argv[2],sys.argv[3]=="1",sys.argv[4]))'
    argv=[sys.executable, '-c', code, url, str(output), str(int(resume)), mode]
    import datetime
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run(argv,capture_output=True,text=True,timeout=120)
    name='resume' if resume else 'scan'
    (output/f'{name}.stdout').write_text(result.stdout);(output/f'{name}.stderr').write_text(result.stderr)
    (output/f'{name}.json').write_text(json.dumps(dict(argv=argv,start_utc=start,
        end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),exit=result.returncode),indent=2))
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((output/'passive-metrics.json').read_text())


@pytest.mark.parametrize('kind', ['vulnerable','safe','error'])
def test_production_passive_twins(tmp_path, passive_server, kind):
    base, visits = passive_server
    output=Path(os.environ.get('WSCAN_PASSIVE_ACCEPTANCE_DIR',tmp_path))/kind
    before=visits.get(kind,0)
    metrics=launch(base+'/'+kind,output)
    assert metrics['by_check']==({'clickjacking':1,'security_headers':6} if kind=='vulnerable'
                                else {'clickjacking':0,'security_headers':0}), metrics
    assert metrics['confirmed'] == (6 if kind=='vulnerable' else 0), metrics
    if os.environ.get('WSCAN_PASSIVE_BASELINE') == '1':
        assert metrics['api_requests']==(7 if kind=='vulnerable' else 1 if kind=='safe' else 0),metrics
        assert visits[kind]-before==metrics['api_requests']+metrics['http_count'],metrics
        return
    records=[json.loads(x) for x in (output/'probe_attempts.jsonl').read_text().splitlines()]
    decisions=[r for r in records if r['record_kind']=='passive_decision' and r['role']=='attack']
    if kind!='error':
        assert len(decisions)==9 and len({r['parent_id'] for r in decisions})==1
        assert all(any(u['status']=='COMPLETE' for u in c['units'].values())
                   for c in metrics['completion']['checks'].values()),metrics
        assert metrics['api_requests']==(7 if kind=='vulnerable' else 1),metrics
        assert visits[kind]-before==metrics['api_requests']+metrics['http_count'],metrics
    else:
        assert all(u['status']!='COMPLETE' for c in metrics['completion']['checks'].values()
                   for u in c['units'].values()),metrics
    assert metrics['completion']['status']=='EVIDENCE_INCOMPLETE' # unknown paths remain explicit
    text=(output/'probe_attempts.jsonl').read_text()
    assert 'passive-private-cookie' not in text and 'passive-private-body' not in text


def test_fresh_process_resume_and_missing_proof(tmp_path,passive_server):
    base,visits=passive_server
    output=Path(os.environ.get('WSCAN_PASSIVE_ACCEPTANCE_DIR',tmp_path))/'resume'
    first=launch(base+'/safe',output)
    original=(output/'probe_attempts.jsonl').read_bytes()
    after=visits.get('safe',0)
    second=launch(base+'/safe',output,resume=True)
    assert (output/'probe_attempts.jsonl').read_bytes().startswith(original)
    assert second['api_requests']==first['api_requests']==1
    assert visits['safe']==after + 1 # existing crawl GET; passive audit GET is not replayed
    (output/'probe_attempts.jsonl').rename(output/'saved-proof.jsonl')
    third=launch(base+'/safe',output,resume=True)
    assert all(u['status']!='COMPLETE' for c in third['completion']['checks'].values()
               for u in c['units'].values()),third


def test_real_engine_logger_failure(tmp_path,passive_server):
    base,_=passive_server
    output=Path(os.environ.get('WSCAN_PASSIVE_ACCEPTANCE_DIR',tmp_path))/'logger'
    metrics=launch(base+'/vulnerable',output,mode='logger')
    assert metrics['candidate']==7 and metrics['confirmed']==6,metrics
    assert metrics['completion']['logging_failed']
    assert metrics['completion']['status']=='EVIDENCE_INCOMPLETE'
