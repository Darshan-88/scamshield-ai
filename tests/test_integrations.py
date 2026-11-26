import base64
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend import integrations as i

client=TestClient(app)
@pytest.fixture(autouse=True)
def env(monkeypatch):
    for k in ('GEMINI_API_KEY','VIRUSTOTAL_API_KEY','GEMINI_MODEL'): monkeypatch.delenv(k,raising=False)
    for q in i._calls.values(): q.clear()

def scan(text='https://example.com/',mode='url',**kw):
    r=client.post('/api/scan',json={'text':text,'mode':mode,**kw})
    assert r.status_code==200
    return r.json()

def test_offline_no_keys():
    r=scan(use_gemini=True,use_reputation=True)
    assert r['reputation']['status']=='not_configured' and r['explanation']['status']=='not_configured'
    assert r['explanation']['source']=='local'

def test_no_consent_no_network(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','fake-gemini');monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-vt')
    monkeypatch.setattr(i,'request',lambda *a,**k: pytest.fail('Unexpected network call'))
    r=scan();assert r['reputation']['status']==r['explanation']['status']=='not_requested'
    info=client.get('/api/integrations').json();assert info['gemini_configured'] and info['virustotal_configured'];assert 'fake' not in str(info)

def test_combined_success(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','fake-gemini');monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-vt')
    def mock(method,url,**kw):
        if method=='GET':
            assert url=='https://www.virustotal.com/api/v3/urls/'+base64.urlsafe_b64encode(b'https://example.com/').decode().rstrip('=')
            assert kw['headers']=={'x-apikey':'fake-vt'}
            return httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'malicious':2,'harmless':60},'last_analysis_date':1700000000}}})
        assert url.startswith('https://generativelanguage.googleapis.com/v1beta/models/')
        assert kw['headers']=={'x-goog-api-key':'fake-gemini'}
        assert '123456' not in str(kw['json']) and 'alice@example.com' not in str(kw['json'])
        return httpx.Response(200,json={'candidates':[{'finishReason':'STOP','content':{'parts':[{'text':json.dumps({'summary':'The request may use urgency to pressure you.'})}]}}]})
    monkeypatch.setattr(i,'request',mock)
    r=scan('Please see https://example.com/ and contact alice@example.com OTP: 123456', 'message',use_gemini=True,use_reputation=True)
    assert r['score']>=80 and r['reputation']['stats']['malicious']==2 and r['explanation']['source']=='gemini'
    assert 'fake-' not in str(r)

@pytest.mark.parametrize('code,status',[(401,'auth_error'),(403,'auth_error'),(429,'rate_limited'),(503,'unavailable')])
def test_provider_error(monkeypatch,code,status):
    monkeypatch.setenv('GEMINI_API_KEY','fake');monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake')
    monkeypatch.setattr(i,'request',lambda *a,**kw:httpx.Response(code,text='PRIVATE PROVIDER ERROR'))
    r=scan(use_gemini=True,use_reputation=True);assert r['reputation']['status']==r['explanation']['status']==status
    assert r['explanation']['source']=='local' and 'PRIVATE PROVIDER ERROR' not in str(r)

def test_timeout(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','fake');monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake')
    def timeout(*a,**kw): raise httpx.ReadTimeout('secret')
    monkeypatch.setattr(i,'request',timeout)
    r=scan(use_gemini=True,use_reputation=True);assert r['reputation']['status']==r['explanation']['status']=='unavailable'

@pytest.mark.parametrize('url',['https://127.0.0.1/','https://host.local/','https://example.com/?token=secret','https://name:pw@example.com/'])
def test_privacy_filter(monkeypatch,url):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake');monkeypatch.setattr(i,'request',lambda *a,**kw:pytest.fail('Unexpected network'))
    assert scan(url,use_reputation=True)['reputation']['status']=='privacy_skipped'

def test_unknown_url(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake');monkeypatch.setattr(i,'request',lambda *a,**kw:httpx.Response(404))
    r=scan(use_reputation=True);assert r['reputation']['status']=='not_found' and r['score']==r['rule_score']

def test_bad_response(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','fake');monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake')
    monkeypatch.setattr(i,'request',lambda *a,**kw:httpx.Response(200,json={}))
    r=scan(use_gemini=True,use_reputation=True);assert r['reputation']['status']==r['explanation']['status']=='unavailable'

def test_rate_budget(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake');monkeypatch.setattr(i,'request',lambda *a,**kw:httpx.Response(404))
    for _ in range(4): assert scan(use_reputation=True)['reputation']['status']=='not_found'
    assert scan(use_reputation=True)['reputation']['status']=='rate_limited'

def test_unflagged_never_lowers_risk(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake');monkeypatch.setattr(i,'request',lambda *a,**kw:httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'harmless':70}}}}))
    r=scan('Urgent! Share your OTP immediately. https://example.com','message',use_reputation=True);assert r['score']>=r['rule_score']>=60
