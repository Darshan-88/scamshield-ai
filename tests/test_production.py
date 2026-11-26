import hashlib
import io
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from zipfile import ZipFile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from starlette.middleware.cors import CORSMiddleware
from backend.main import app
from backend import accounts, limits, production, integrations, ml
from backend.db import RateCounter, engine
from scripts.import_dataset import install

client=TestClient(app)

def test_health_and_headers():
    assert client.get('/api/health/live').json()=={'status':'ok'}
    r=client.get('/api/health/ready');assert r.status_code==200 and r.json()=={'status':'ready'}
    assert r.headers['cache-control']=='no-store'
    assert len(r.headers['x-request-id'])==32
    assert "object-src 'none'" in r.headers['content-security-policy']
    assert 'camera=()' in r.headers['permissions-policy']

def test_readiness_failure(monkeypatch):
    monkeypatch.setattr(production,'database_ready',lambda:False)
    r=client.get('/api/health/ready');assert r.status_code==503 and r.json()=={'status':'not_ready'}
    assert client.get('/api/health/live').status_code==200

def test_readiness_real_dataset_required(monkeypatch):
    monkeypatch.setenv('REQUIRE_REAL_DATASET','1')
    monkeypatch.setattr('backend.main.get_model',lambda:(None,{'real_dataset':False}))
    assert client.get('/api/health/ready').status_code==503

def test_body_limit_and_no_echo():
    r=client.post('/api/auth/register',content=b'secret'*20000,headers={'Content-Type':'application/json'})
    assert r.status_code==413 and 'secret' not in r.text and r.headers['cache-control']=='no-store'

def test_chunked_body_limit():
    assert client.post('/api/auth/register',content=iter([b'x'*40000,b'y'*40000]),headers={'Content-Type':'application/json'}).status_code==413

def test_exact_cors():
    cors=CORSMiddleware(app,allow_origins=['https://demo.vercel.app'],allow_methods=['POST'],allow_headers=['Authorization','Content-Type'])
    c=TestClient(cors)
    headers={'Origin':'https://demo.vercel.app','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,content-type'}
    assert c.options('/api/scan',headers=headers).headers['access-control-allow-origin']=='https://demo.vercel.app'
    r=c.options('/api/scan',headers={**headers,'Origin':'https://evil.example'});assert r.status_code==400 and 'access-control-allow-origin' not in r.headers

def test_production_requires_postgres(monkeypatch):
    monkeypatch.setenv('APP_ENV','production');monkeypatch.setenv('JWT_SECRET',secrets.token_urlsafe(48));monkeypatch.setenv('RATE_LIMIT_BACKEND','database')
    monkeypatch.setenv('DATABASE_URL','sqlite:///test.db')
    with pytest.raises(RuntimeError,match='PostgreSQL'):production.validate()

def test_production_rejects_weak_key(monkeypatch):
    monkeypatch.setenv('APP_ENV','production');monkeypatch.setenv('JWT_SECRET','a'*64)
    with pytest.raises(RuntimeError,match='JWT_SECRET'):production.validate()

def test_production_config_and_invalid_origins(monkeypatch):
    monkeypatch.setenv('APP_ENV','production');monkeypatch.setenv('JWT_SECRET',secrets.token_urlsafe(48));monkeypatch.setenv('RATE_LIMIT_BACKEND','database');monkeypatch.setenv('DATABASE_URL','postgresql+psycopg://user:pass@db/test');monkeypatch.setenv('FRONTEND_ORIGINS','https://demo.vercel.app');production.validate()
    monkeypatch.setenv('RATE_LIMIT_BACKEND','memory')
    with pytest.raises(RuntimeError,match='shared'):production.validate()
    monkeypatch.setenv('FRONTEND_ORIGINS','*')
    with pytest.raises(RuntimeError,match='origins'):production.validate()

def test_shared_counter_cross_connections_and_expiry(tmp_path):
    url='sqlite:///'+str(tmp_path/'shared.db');a=create_engine(url);b=create_engine(url);RateCounter.__table__.create(a)
    try:
        assert limits.consume('scan','person@example.com',2,bind=a,timestamp=120)==(True,60)
        assert limits.consume('scan','person@example.com',2,bind=b,timestamp=121)==(True,59)
        assert limits.consume('scan','person@example.com',2,bind=a,timestamp=122)==(False,58)
        with b.connect() as c:
            key=c.execute(text('select key from rate_counters')).scalar_one();assert len(key)==64 and 'person' not in key
        assert limits.consume('scan','person@example.com',2,bind=b,timestamp=180)==(True,60)
        with a.connect() as c:assert c.execute(text('select count(*) from rate_counters')).scalar()==1
    finally:a.dispose();b.dispose()

def test_shared_counter_concurrent(tmp_path):
    a=create_engine('sqlite:///'+str(tmp_path/'concurrent.db'));RateCounter.__table__.create(a)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:limits.consume('scan','same',5,bind=a,timestamp=120)[0],range(30)))
        assert sum(results)==5
    finally:a.dispose()

def test_account_limiter_shared_and_fail_closed(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setenv('RATE_LIMIT_BACKEND','database')
    monkeypatch.setattr(limits,'consume',lambda *args:(False,17))
    with pytest.raises(HTTPException) as exc:accounts.limit('scan','u',20)
    assert exc.value.status_code==429 and exc.value.headers['Retry-After']=='17'
    def fail(*args):raise limits.LimitUnavailable()
    monkeypatch.setattr(limits,'consume',fail)
    with pytest.raises(HTTPException) as exc:accounts.limit('scan','u',20)
    assert exc.value.status_code==503
    assert integrations.allow_call('gemini') is False

def test_provider_daily_budget(monkeypatch):
    monkeypatch.setenv('RATE_LIMIT_BACKEND','database');monkeypatch.setenv('GEMINI_DAILY_LIMIT','1')
    calls=[]
    def consume(*args):calls.append(args);return (len(args)==3,1)
    monkeypatch.setattr(limits,'consume',consume)
    assert integrations.allow_call('gemini') is False
    assert calls==[('provider_minute','gemini',5),('provider_day','gemini',1,86400)]

def dataset():
    return ''.join(f'{label}\t{message} number {i}\n' for label,message in [('ham','team meeting'),('spam','urgent prize fee')] for i in range(60)).encode()

def test_dataset_zip_and_digest(tmp_path):
    raw=dataset();buf=io.BytesIO()
    with ZipFile(buf,'w') as z:z.writestr('nested/SMSSpamCollection',raw);z.writestr('../unsafe.txt','bad')
    data=buf.getvalue();target=tmp_path/'SMSSpamCollection'
    info=install(data,target,hashlib.sha256(data).hexdigest());assert target.read_bytes()==raw and info['unique_rows']==120
    assert not (tmp_path/'unsafe.txt').exists()
    with pytest.raises(ValueError,match='SHA-256'):install(data,target,'0'*64)
    assert target.read_bytes()==raw

def test_external_dataset_training(tmp_path,monkeypatch):
    path=tmp_path/'test.tsv';path.write_bytes(dataset());monkeypatch.setenv('SMS_DATASET_PATH',str(path));ml.get_model.cache_clear()
    try:
        _,info=ml.get_model();assert info['real_dataset'] is True and info['samples']==24 and info['split_seed']==42
        assert info['dataset_sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
    finally:ml.get_model.cache_clear()

@pytest.mark.skipif(not os.getenv('CI_POSTGRES_URL'),reason='Requires live PostgreSQL service')
def test_postgres_migration_and_shared_concurrency(monkeypatch):
    from alembic import command
    from alembic.config import Config
    url=os.environ['CI_POSTGRES_URL'];monkeypatch.setenv('DATABASE_URL',url)
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'));command.upgrade(config,'head')
    a=create_engine(url);b=create_engine(url)
    try:
        with a.connect() as c:assert c.execute(text('select version_num from alembic_version')).scalar_one()==production.HEAD
        identity=secrets.token_hex(16)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda n:limits.consume('test',identity,7,bind=a if n%2 else b)[0],range(30)))
        assert sum(results)==7
    finally:a.dispose();b.dispose()

def test_auth_hash_concurrency_guard():
    from fastapi import HTTPException
    with accounts.hash_slot(), accounts.hash_slot():
        with pytest.raises(HTTPException) as exc:
            with accounts.hash_slot(): pass
        assert exc.value.status_code==429
    with accounts.hash_slot(): pass

@pytest.mark.skipif(not os.getenv('CI_POSTGRES_URL'),reason='Requires live PostgreSQL service')
def test_production_api_on_postgres():
    import subprocess,sys
    env={**os.environ,'DATABASE_URL':os.environ['CI_POSTGRES_URL'],'APP_ENV':'production','JWT_SECRET':secrets.token_urlsafe(48),'RATE_LIMIT_BACKEND':'database','ALLOWED_HOSTS':'testserver','FRONTEND_ORIGINS':'https://demo.vercel.app','REQUIRE_REAL_DATASET':'0'}
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],env=env,check=True)
    code='''
from fastapi.testclient import TestClient
from backend.main import app
from uuid import uuid4
with TestClient(app) as c:
    assert c.get('/api/health/ready').status_code==200
    assert c.get('/docs').status_code==404
    h={'Origin':'https://demo.vercel.app'}
    a=c.post('/api/auth/register',headers=h,json={'email':uuid4().hex+'@example.com','password':'test-password-long'})
    assert a.status_code==201,a.text
    assert a.headers['access-control-allow-origin']==h['Origin']
    assert 'max-age=' in a.headers['strict-transport-security']
    h['Authorization']='Bearer '+a.json()['access_token']
    r=c.post('/api/scan',headers=h,json={'text':'Share your OTP immediately.'})
    assert r.status_code==200 and r.json()['level']=='high'
    assert c.get('/api/history',headers=h).json()['items'][0]['score']==r.json()['score']
    assert c.get('/api/health/live',headers={'Host':'bad.example'}).status_code==400
'''
    subprocess.run([sys.executable,'-c',code],env=env,check=True)
