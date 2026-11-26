from datetime import timedelta
from uuid import uuid4
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, inspect, func
from backend.main import app
from backend import accounts
from backend.db import SessionLocal, User, LoginSession, ScanRecord, now, engine
from alembic import command
from alembic.config import Config
from pathlib import Path

client=TestClient(app)
PW='strong-test-password-123'

def create(email=None):
    email=email or f'{uuid4().hex}@example.com'
    r=client.post('/api/auth/register',json={'email':email,'password':PW});assert r.status_code==201,r.text
    d=r.json();return d,{'Authorization':'Bearer '+d['access_token']}

def scan(headers,**kw):
    return client.post('/api/scan',headers=headers,json={'text':'Share your OTP immediately.','mode':'banking',**kw})

@pytest.mark.parametrize('method,path,kwargs', [('post','/api/scan',{'json':{'text':'hello'}}),('post','/api/image/extract',{'content':b'x','headers':{'Content-Type':'image/png'}}),('get','/api/history',{}),('get','/api/dashboard',{}),('get','/api/auth/me',{}),('delete','/api/history',{})])
def test_protection(method,path,kwargs):
    r=getattr(client,method)(path,**kwargs);assert r.status_code==401
    assert r.headers['cache-control']=='no-store'

def test_registration_password_storage_and_login():
    email=f'{uuid4().hex}@example.com';d,h=create(email.upper())
    assert d['user']['email']==email and d['expires_in']==1800
    with SessionLocal() as db:
        u=db.get(User,d['user']['id']);assert u.password_hash.startswith('$argon2id$') and u.password_hash!=PW
    assert client.get('/api/auth/me',headers=h).json()==d['user']
    assert client.post('/api/auth/login',json={'email':email,'password':PW}).status_code==200
    assert client.post('/api/auth/register',json={'email':email,'password':PW}).status_code==409
    assert client.post('/api/auth/login',json={'email':email,'password':'wrong'}).status_code==401

def test_invalid_registration():
    for email,pw in [('bad','long-test-password'),('me@example.com','short')]:
        assert client.post('/api/auth/register',json={'email':email,'password':pw}).status_code==422

def test_expired_tampered_wrong_audience_and_missing_claims():
    d,h=create(); token=d['access_token']; claims=jwt.decode(token,options={'verify_signature':False})
    variants=[{**claims,'exp':now()-timedelta(seconds=1)}, {**claims,'aud':'other'}, {k:v for k,v in claims.items() if k!='exp'}]
    for c in variants:
        t=jwt.encode(c,accounts.secret(),algorithm='HS256')
        assert client.get('/api/auth/me',headers={'Authorization':'Bearer '+t}).status_code==401
    assert client.get('/api/auth/me',headers={'Authorization':'Bearer '+jwt.encode(claims,'x'*48,algorithm='HS256')}).status_code==401

def test_logout_revokes_only_session():
    d,h=create();login=client.post('/api/auth/login',json={'email':d['user']['email'],'password':PW}).json();h2={'Authorization':'Bearer '+login['access_token']}
    assert client.post('/api/auth/logout',headers=h).status_code==204
    assert client.get('/api/auth/me',headers=h).status_code==401
    assert client.get('/api/auth/me',headers=h2).status_code==200

def test_isolation_and_history_dashboard():
    a,ha=create();b,hb=create();r=scan(ha);assert r.status_code==200;rid=r.json()['history_id']
    assert scan(hb,text='Meeting tomorrow.',mode='message').status_code==200
    items=client.get('/api/history',headers=ha).json()['items'];assert len(items)==1 and items[0]['id']==rid
    assert set(items[0])=={'id','mode','score','level','time'}
    assert client.get('/api/history',headers=hb).json()['items'][0]['id']!=rid
    assert client.delete('/api/history/'+rid,headers=hb).status_code==404
    assert client.delete('/api/history',headers=hb).status_code==204
    d=client.get('/api/dashboard',headers=ha).json();assert d['total']==1 and d['by_mode']['banking']==1 and d['by_level']['high']==1
    assert client.get('/api/dashboard',headers=hb).json()['total']==0
    assert client.delete('/api/history/'+rid,headers=ha).status_code==204
    assert client.get('/api/dashboard',headers=ha).json()['total']==0

def test_opt_out_and_no_raw_data():
    d,h=create();r=scan(h,save_history=False);assert r.json()['history_id'] is None
    assert client.get('/api/dashboard',headers=h).json()['total']==0
    assert scan(h,text='private text https://example.com/secret').status_code==200
    with SessionLocal() as db:
        rec=db.scalar(select(ScanRecord).where(ScanRecord.user_id==d['user']['id']))
        assert set(inspect(rec).mapper.columns.keys())=={'id','user_id','mode','score','level','created_at'}

def test_account_deletion_cascades():
    d,h=create();uid=d['user']['id'];email=d['user']['email'];scan(h)
    assert client.request('DELETE','/api/auth/account',headers=h,json={'email':email,'password':'wrong'}).status_code==401
    assert client.request('DELETE','/api/auth/account',headers=h,json={'email':email,'password':PW}).status_code==204
    assert client.get('/api/auth/me',headers=h).status_code==401
    with SessionLocal() as db:
        assert db.get(User,uid) is None
        assert db.scalar(select(func.count()).select_from(LoginSession).where(LoginSession.user_id==uid))==0
        assert db.scalar(select(func.count()).select_from(ScanRecord).where(ScanRecord.user_id==uid))==0

def test_rate_limits_per_account(monkeypatch):
    a,ha=create();b,hb=create()
    for _ in range(20): assert scan(ha,save_history=False).status_code==200
    r=scan(ha);assert r.status_code==429 and int(r.headers['retry-after'])>0
    assert scan(hb).status_code==200
    for _ in range(6): assert client.post('/api/image/extract',headers={**ha,'Content-Type':'image/png'},content=b'bad').status_code==422
    assert client.post('/api/image/extract',headers={**ha,'Content-Type':'image/png'},content=b'bad').status_code==429

def test_login_rate_limit():
    d,h=create();email=d['user']['email']
    for _ in range(5): assert client.post('/api/auth/login',json={'email':email,'password':'wrong'}).status_code==401
    assert client.post('/api/auth/login',json={'email':email,'password':PW}).status_code==429

def test_migration_matches_metadata():
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    command.check(config)
    assert set(inspect(engine).get_table_names())=={'alembic_version','users','login_sessions','scan_records','community_reports','rate_counters'}

def test_startup():
    with TestClient(app) as c: assert c.get('/api/health').status_code==200

def test_validation_does_not_echo_password():
    pw='secret-should-not-echo-'+('x'*140)
    r=client.post('/api/auth/register',json={'email':'user@example.com','password':pw})
    assert r.status_code==422 and pw not in r.text
