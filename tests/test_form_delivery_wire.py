import asyncio,json
from types import SimpleNamespace
import pytest
from fastapi import FastAPI,Request
from fastapi.responses import HTMLResponse, RedirectResponse
from tests.test_totp_login_e2e import serving
from wscan.browser import BrowserManager
from wscan.request_logger import RequestLogger
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.scanners.sqli import SQLiScanner

@pytest.mark.parametrize('case',['normal','redirect','redirect-rewrite','multipart','newline','unicode-post','unicode-get','duplicate','submit-rewrite','action-query','beacon'])
def test_actual_selected_field_and_evidence(case,tmp_path):
    candidate='first\nsecond' if case=='newline' else '雪+%--' if case.startswith('unicode') else 'probe--'
    app=FastAPI(); received=[]
    @app.get('/form')
    async def form():
        action='/capture?q=probe--' if case=='action-query' else '/capture'
        field='<textarea name="q"></textarea>' if case=='newline' else '<input name="q">'
        if case=='duplicate':field+='<input name="q" value="other">'
        handler="document.querySelector('[name=q]').value='replacement'" if case in ('submit-rewrite','action-query','redirect-rewrite') else "event.preventDefault();fetch('/beacon?q='+encodeURIComponent(document.querySelector('[name=q]').value))" if case=='beacon' else ''
        enctype=' enctype="multipart/form-data"' if case=='multipart' else ''
        method='get' if case=='unicode-get' else 'post'
        return HTMLResponse(f'<form method="{method}" action="{action}"{enctype} onsubmit="{handler}">{field}<button>Send</button></form>')
    @app.api_route('/capture',methods=['GET','POST'])
    async def capture(request:Request):
        fields=await request.form() if request.method=='POST' else request.query_params
        vals=fields.getlist('q')
        expected=candidate.replace('\n','\r\n') if case=='newline' else candidate
        received.append({'endpoint':'capture','candidate_in_selected_carrier':expected in vals,'method':request.method,'has_query_candidate':request.query_params.get('q')==candidate,'multipart_mixed_boundary':case=='multipart' and 'WebKit' in request.headers.get('content-type','')})
        if case in ('redirect', 'redirect-rewrite') and request.method == 'POST':
            return RedirectResponse('/capture', status_code=303)
        return HTMLResponse('<h1>Response</h1>')
    @app.get('/beacon')
    async def beacon(request:Request):
        received.append({'endpoint':'beacon','candidate_present':request.query_params.get('q')==candidate})
        return HTMLResponse('Telemetry only')
    with serving(app) as url:
        async def exercise():
            logger=RequestLogger(tmp_path)
            b=BrowserManager(headless=True,timeout=5,sleep_factor=1,request_logger=logger,auth_user='fixture-user',auth_pass='fixture-password')
            await b.init()
            try:
                await b.page.context.route('**/*',lambda r:r.continue_() if r.request.url.startswith(url+'/') else r.abort())
                assert await b.navigate(url+'/form')
                scanner=object.__new__(SQLiScanner);scanner.engine=SimpleNamespace(request_logger=logger);scanner.browser=b
                ip=InjectionPoint.for_form(url+'/form','q',form_index=0)
                source,pair=await BaseScanner._send_probe(scanner,ip,lambda:b.fill_and_submit_form(0,'q',candidate))
                decision=BaseScanner._probe_decision(scanner,pair,False,'sqli_payload_oracle')
                records=[json.loads(s) for s in logger.probe_ledger.path.read_text().splitlines()]
                outcomes=[r.get('outcome') for r in records if r.get('record_kind')=='decision']
                print({'case':case,'received':received,'delivered':b.last_probe_delivered,'reason':b.last_probe_delivery_reason,'decisions':outcomes})
                if case in ('submit-rewrite','action-query','beacon','redirect-rewrite'):
                    assert not any(r.get('candidate_in_selected_carrier') for r in received)
                    assert not b.last_probe_delivered, 'No selected-form candidate was submitted'
                    assert decision is None and 'no_match' not in outcomes, 'Undelivered candidate recorded as a tested negative'
                else:
                    assert received and received[0]['candidate_in_selected_carrier']
                    assert b.last_probe_delivered, 'Actual valid selected-field receipt was rejected'
                    if case == 'redirect':
                        assert [r['method'] for r in received] == ['POST', 'GET']
                        assert pair['request']['method'] == 'POST'
                        assert pair['response']['status'] == 303
                        assert pair['request']['_req_id'] == pair['response']['_req_id']
                        assert decision is not None and 'no_match' in outcomes
                        assert 'unexecutable' not in outcomes
            finally:await b.close()
        asyncio.run(exercise())
